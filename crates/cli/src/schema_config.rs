use std::collections::{BTreeMap, BTreeSet};

use better_auth_schema_registry::{EntityRole, ExtraEntitySchema, FieldDef};
use heck::{ToLowerCamelCase, ToSnakeCase};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(transparent)]
pub(crate) struct SchemaConfig(pub BTreeMap<String, ModelConfig>);

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModelConfig {
    pub model_name: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub additional_fields: BTreeMap<String, AdditionalField>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdditionalField {
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub field_name: Option<String>,
    pub required: Option<bool>,
    #[serde(default)]
    pub unique: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum FieldType {
    Name(String),
    Enum(Vec<String>),
}

impl FieldType {
    fn rust_type(&self) -> Result<&'static str, String> {
        match self {
            Self::Name(name) => match name.as_str() {
                "string" => Ok("String"),
                "number" => Ok("f64"),
                "boolean" => Ok("bool"),
                "date" => Ok("DateTimeUtc"),
                "json" => Ok("Json"),
                "string[]" => Ok("StringArray"),
                "number[]" => Ok("NumberArray"),
                _ => Err(format!("unsupported additional field type `{name}`")),
            },
            Self::Enum(values) => {
                if values.is_empty() {
                    return Err("an enum field must contain at least one string".to_owned());
                }
                Ok("String")
            }
        }
    }
}

pub(crate) struct Entity {
    pub module: syn::Ident,
    pub name: &'static str,
    pub registry_table: &'static str,
    pub table: String,
    pub role: Option<EntityRole>,
    pub fields: Vec<Field>,
}

pub(crate) struct Field {
    pub ident: syn::Ident,
    pub ty: syn::Type,
    pub column: String,
    pub registry_column: Option<&'static str>,
    pub serialized: Option<String>,
    pub primary_key: bool,
    pub unique: Option<bool>,
}

impl SchemaConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, model) in &self.0 {
            if !matches!(
                name.as_str(),
                "session"
                    | "organization"
                    | "member"
                    | "invitation"
                    | "team"
                    | "teamMember"
                    | "organizationRole"
            ) {
                return Err(format!("unknown schema model `{name}`"));
            }
            if matches!(name.as_str(), "session" | "teamMember")
                && !model.additional_fields.is_empty()
            {
                return Err(format!("`{name}` does not support additionalFields"));
            }
            if name == "session" && model.model_name.is_some() {
                return Err("the Organization schema cannot rename the session model".to_owned());
            }
        }
        Ok(())
    }
}

impl Entity {
    pub(crate) fn resolve(
        definition: &ExtraEntitySchema,
        fields: &[FieldDef],
        config: Option<&ModelConfig>,
    ) -> Result<Self, String> {
        let mut entity = Self {
            module: syn::parse_str(definition.mod_name)
                .map_err(|error| format!("invalid model name: {error}"))?,
            name: definition.mod_name,
            registry_table: definition.table_name,
            table: definition.table_name.to_owned(),
            role: definition.role,
            fields: fields
                .iter()
                .map(|field| {
                    Ok(Field {
                        ident: syn::parse_str(field.name)
                            .map_err(|error| format!("invalid field name: {error}"))?,
                        ty: syn::parse_str(field.ty)
                            .map_err(|error| format!("invalid field type: {error}"))?,
                        column: field.column_name.unwrap_or(field.name).to_owned(),
                        registry_column: Some(field.column_name.unwrap_or(field.name)),
                        serialized: None,
                        primary_key: field.is_primary_key,
                        unique: None,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        if let Some(config) = config {
            if let Some(table) = &config.model_name {
                entity.table.clone_from(table);
            }
            for (name, column) in &config.fields {
                let field = entity
                    .fields
                    .iter_mut()
                    .find(|field| {
                        !field.primary_key && field.ident.to_string().to_lower_camel_case() == *name
                    })
                    .ok_or_else(|| {
                        format!("unknown configurable field `{}.{name}`", entity.name)
                    })?;
                if entity.name == "session"
                    && !matches!(name.as_str(), "activeOrganizationId" | "activeTeamId")
                {
                    return Err(format!(
                        "`session.{name}` is not an Organization plugin field"
                    ));
                }
                field.column.clone_from(column);
            }
            for (name, field) in &config.additional_fields {
                if let Some((definition, existing)) = fields
                    .iter()
                    .zip(&mut entity.fields)
                    .find(|(definition, _)| definition.name.to_lower_camel_case() == *name)
                {
                    existing.apply_builtin_override(definition, field, entity.name)?;
                    continue;
                }
                let rust_name = name.to_snake_case();
                let ident = syn::parse_str(&rust_name)
                    .or_else(|_| syn::parse_str(&format!("{rust_name}_")))
                    .map_err(|error| format!("invalid additional field `{name}`: {error}"))?;
                let ty = field.field_type.rust_type()?;
                // Upstream makes organization role fields optional while constructing update-role.
                let ty = if field.required == Some(true)
                    && entity.role != Some(EntityRole::OrganizationRole)
                {
                    ty.to_owned()
                } else {
                    format!("Option<{ty}>")
                };
                let column = field.field_name.as_ref().unwrap_or(name).clone();
                entity.fields.push(Field {
                    ident,
                    ty: syn::parse_str(&ty)
                        .map_err(|error| format!("invalid additional field type: {error}"))?,
                    column: column.clone(),
                    registry_column: None,
                    serialized: Some(column),
                    primary_key: false,
                    unique: Some(field.unique),
                });
            }
        }
        if entity.table.is_empty() {
            return Err(format!("model `{}` has an empty table name", entity.name));
        }
        let mut names = BTreeSet::new();
        let mut columns = BTreeSet::new();
        for field in &entity.fields {
            if !names.insert(field.ident.to_string()) {
                return Err(format!(
                    "model `{}` has conflicting Rust field `{}`",
                    entity.name, field.ident
                ));
            }
            if field.column.is_empty() || !columns.insert(&field.column) {
                return Err(format!(
                    "model `{}` has an empty or duplicate database column `{}`",
                    entity.name, field.column
                ));
            }
        }
        Ok(entity)
    }

    pub(crate) fn column(&self, registry_column: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.registry_column == Some(registry_column))
            .map(|field| field.column.as_str())
    }
}

impl Field {
    fn apply_builtin_override(
        &mut self,
        definition: &FieldDef,
        config: &AdditionalField,
        model: &str,
    ) -> Result<(), String> {
        if definition.name == "member_count"
            || (model == "organization" && definition.name == "updated_at")
        {
            return Err(format!(
                "builtin override `{model}.{}` targets an internal storage field and is unsupported",
                definition.name.to_lower_camel_case()
            ));
        }
        let nullable = definition.ty.starts_with("Option<");
        let base_type = definition
            .ty
            .strip_prefix("Option<")
            .and_then(|ty| ty.strip_suffix('>'))
            .unwrap_or(definition.ty);
        if base_type == "Json" {
            return Err(format!(
                "builtin override `{model}.{}` uses JSON-backed storage and is unsupported",
                definition.name.to_lower_camel_case()
            ));
        }
        if !matches!(&config.field_type, FieldType::Name(_))
            || config.field_type.rust_type()? != base_type
        {
            return Err(format!(
                "builtin override `{model}.{}` must preserve its {base_type} type",
                definition.name.to_lower_camel_case()
            ));
        }
        if definition.is_primary_key {
            return Ok(());
        }
        if config.required.is_some_and(|required| required == nullable) {
            return Err(format!(
                "builtin override `{model}.{}` must preserve its storage nullability",
                definition.name.to_lower_camel_case()
            ));
        }
        self.column = config
            .field_name
            .clone()
            .unwrap_or_else(|| definition.column_name.unwrap_or(definition.name).to_owned());
        self.serialized = Some(self.column.clone());
        self.unique = Some(config.unique);
        Ok(())
    }
}
