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
    pub additional_fields: indexmap::IndexMap<String, AdditionalField>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdditionalField {
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub field_name: Option<String>,
    pub required: Option<bool>,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub index: bool,
    #[serde(default)]
    pub bigint: bool,
    #[serde(default)]
    pub sortable: bool,
    pub references: Option<Reference>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reference {
    pub model: String,
    pub field: String,
    pub on_delete: Option<OnDelete>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OnDelete {
    #[serde(rename = "no action")]
    NoAction,
    Restrict,
    #[default]
    Cascade,
    #[serde(rename = "set null")]
    SetNull,
    #[serde(rename = "set default")]
    SetDefault,
}

impl AdditionalField {
    fn rust_type(&self) -> Result<&'static str, String> {
        let field_type = self.field_type.rust_type()?;
        Ok(
            if self
                .references
                .as_ref()
                .is_some_and(|reference| reference.field == "id")
            {
                // The migration uses the ID storage type even when the public field is a number.
                "better_auth::seaorm::ReferenceId"
            } else {
                field_type
            },
        )
    }
}

#[derive(Clone, Deserialize)]
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
                "number" => Ok("better_auth::seaorm::SqlNumber"),
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
    pub logical_name: String,
    pub ty: syn::Type,
    pub column: String,
    pub registry_column: Option<&'static str>,
    pub serialized: Option<String>,
    pub primary_key: bool,
    pub unique: Option<bool>,
    pub attributes: Option<AdditionalField>,
}

impl SchemaConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, model) in &self.0 {
            if !matches!(
                name.as_str(),
                "user"
                    | "account"
                    | "verification"
                    | "apikey"
                    | "deviceCode"
                    | "passkey"
                    | "twoFactor"
                    | "jwks"
                    | "walletAddress"
                    | "rateLimit"
                    | "session"
                    | "organization"
                    | "member"
                    | "invitation"
                    | "team"
                    | "teamMember"
                    | "organizationRole"
            ) {
                return Err(format!("unknown schema model `{name}`"));
            }
            if !matches!(
                name.as_str(),
                "organization" | "member" | "invitation" | "team" | "organizationRole"
            ) && !model.additional_fields.is_empty()
            {
                return Err(format!("`{name}` does not support additionalFields"));
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
                        logical_name: match (definition.mod_name, field.name) {
                            ("api_key", "key_hash") => "key".to_owned(),
                            ("passkey", "credential_id") => "credentialID".to_owned(),
                            _ => field.name.to_lower_camel_case(),
                        },
                        ty: syn::parse_str(field.ty)
                            .map_err(|error| format!("invalid field type: {error}"))?,
                        column: field.column_name.unwrap_or(field.name).to_owned(),
                        registry_column: Some(field.column_name.unwrap_or(field.name)),
                        serialized: (definition.mod_name == "user"
                            && matches!(
                                field.name,
                                "username" | "display_username" | "last_login_method"
                            ))
                        .then(|| field.name.to_lower_camel_case()),
                        primary_key: field.is_primary_key,
                        unique: None,
                        attributes: None,
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
                        !field.primary_key
                            && (field.ident.to_string().to_lower_camel_case() == *name
                                || (entity.name == "api_key"
                                    && name == "key"
                                    && field.ident == "key_hash")
                                || (entity.name == "passkey"
                                    && name == "credentialID"
                                    && field.ident == "credential_id"))
                    })
                    .ok_or_else(|| {
                        format!("unknown configurable field `{}.{name}`", entity.name)
                    })?;
                field.column.clone_from(column);
                if field.serialized.is_some() {
                    field.serialized = Some(column.clone());
                }
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
                let ty = field.rust_type()?;
                // Upstream makes organization role fields optional while constructing update-role.
                let ty = if field.required != Some(false)
                    && entity.role != Some(EntityRole::OrganizationRole)
                {
                    ty.to_owned()
                } else {
                    format!("Option<{ty}>")
                };
                let column = field.field_name.as_ref().unwrap_or(name).clone();
                entity.fields.push(Field {
                    ident,
                    logical_name: name.clone(),
                    ty: syn::parse_str(&ty)
                        .map_err(|error| format!("invalid additional field type: {error}"))?,
                    column: column.clone(),
                    registry_column: None,
                    serialized: Some(column),
                    primary_key: false,
                    unique: Some(field.unique),
                    attributes: Some(field.clone()),
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
        if definition.is_primary_key {
            return Ok(());
        }
        let kind = config.rust_type()?;
        let kind = if config.required != Some(false) && model != "organization_role" {
            kind.to_owned()
        } else {
            format!("Option<{kind}>")
        };
        self.ty = syn::parse_str(&kind)
            .map_err(|error| format!("invalid built-in field type: {error}"))?;
        self.column = config
            .field_name
            .clone()
            .unwrap_or_else(|| definition.column_name.unwrap_or(definition.name).to_owned());
        self.serialized = Some(self.column.clone());
        self.unique = Some(config.unique);
        self.attributes = Some(config.clone());
        Ok(())
    }
}

/// Match upstream model names where Rust module names differ.
pub(crate) fn model_name(module: &str) -> String {
    match module {
        "api_key" => "apikey".to_owned(),
        "jwk" => "jwks".to_owned(),
        name => name.to_lower_camel_case(),
    }
}
