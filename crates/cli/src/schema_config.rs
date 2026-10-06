use better_auth_schema_registry::resolve_field_name;
use std::collections::{BTreeMap, BTreeSet};

use better_auth_schema_registry::{EntityRole, ExtraEntitySchema, FieldDef};
use heck::{ToLowerCamelCase, ToSnakeCase};
use serde::Deserialize;

#[cfg(test)]
mod empty_field_name_tests;
#[cfg(test)]
mod empty_model_name_tests;
#[cfg(test)]
mod json_storage_tests;
#[cfg(test)]
mod native_empty_field_mapping_tests;

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum IdGeneration {
    #[default]
    Random,
    Serial,
    Uuid,
    Database,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Database {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

pub(crate) fn sqlite_native_catalog(database: Database, role: Option<EntityRole>) -> bool {
    matches!(database, Database::Sqlite)
        && matches!(
            role,
            Some(
                EntityRole::User
                    | EntityRole::Account
                    | EntityRole::Verification
                    | EntityRole::Jwk
                    | EntityRole::RateLimit
                    | EntityRole::Member
                    | EntityRole::OrganizationRole
                    | EntityRole::Team
                    | EntityRole::Invitation
                    | EntityRole::WalletAddress
            )
        )
}

pub(crate) fn core_field(role: Option<EntityRole>, column: &str) -> Option<&'static FieldDef> {
    better_auth_schema_registry::core_fields(role?)
        .iter()
        .find(|field| field.column_name.unwrap_or(field.name) == column)
}

impl IdGeneration {
    pub(crate) fn rust_type(self, database: Database) -> &'static str {
        match (self, database) {
            (Self::Serial, Database::Sqlite) => "i64",
            (Self::Serial, _) => "i32",
            (Self::Uuid, Database::Postgres) => "Uuid",
            _ => "String",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(transparent)]
pub(crate) struct SchemaConfig(pub BTreeMap<String, ModelConfig>);

#[derive(Clone, Copy, Default)]
pub(crate) struct SchemaOptions {
    pub session_active_column: bool,
    pub device_code_legacy_schema: bool,
    pub passkey_legacy_schema: bool,
    pub two_factor_legacy_schema: bool,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModelConfig {
    pub model_name: Option<String>,
    pub fields: Option<BTreeMap<String, String>>,
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
    pub session_row_presence: bool,
    pub device_code_native_schema: bool,
    pub passkey_native_schema: bool,
    pub two_factor_native_schema: bool,
}

pub(crate) struct Field {
    pub ident: syn::Ident,
    pub logical_name: String,
    pub ty: syn::Type,
    pub column: String,
    pub registry_column: Option<&'static str>,
    pub serialized: Option<String>,
    pub primary_key: bool,
    pub reference_override: Option<bool>,
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
                "user"
                    | "session"
                    | "account"
                    | "verification"
                    | "apikey"
                    | "deviceCode"
                    | "passkey"
                    | "jwks"
                    | "walletAddress"
                    | "twoFactor"
                    | "organization"
                    | "member"
                    | "invitation"
                    | "team"
                    | "organizationRole"
            ) && !model.additional_fields.is_empty()
            {
                return Err(format!("`{name}` does not support additionalFields"));
            }
        }
        Ok(())
    }
}

impl Entity {
    pub(crate) fn resolve_ids(
        &mut self,
        generation: IdGeneration,
        database: Database,
    ) -> Result<(), String> {
        for field in &mut self.fields {
            let reference = field.references_id(self.registry_table);
            if !field.primary_key && !reference {
                continue;
            }
            let kind = if reference
                && field.attributes.is_some()
                && generation.rust_type(database) == "String"
            {
                "better_auth::seaorm::ReferenceId"
            } else {
                generation.rust_type(database)
            };
            let optional = matches!(&field.ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"));
            field.ty = syn::parse_str(&if optional {
                format!("Option<{kind}>")
            } else {
                kind.to_owned()
            })
            .map_err(|error| format!("invalid ID type: {error}"))?;
        }
        Ok(())
    }

    pub(crate) fn resolve(
        definition: &ExtraEntitySchema,
        fields: &[FieldDef],
        config: Option<&ModelConfig>,
        database: Database,
        options: SchemaOptions,
    ) -> Result<Self, String> {
        let session_row_presence =
            definition.role == Some(EntityRole::Session) && !options.session_active_column;
        let device_code_native_schema =
            definition.role == Some(EntityRole::DeviceCode) && !options.device_code_legacy_schema;
        let passkey_native_schema =
            definition.role == Some(EntityRole::Passkey) && !options.passkey_legacy_schema;
        let two_factor_native_schema = !options.two_factor_legacy_schema
            && (definition.role == Some(EntityRole::TwoFactor)
                || definition.role == Some(EntityRole::User)
                    && fields
                        .iter()
                        .any(|field| field.name == "two_factor_enabled"));
        let fields = fields
            .iter()
            .filter(|field| {
                !(passkey_native_schema && matches!(field.name, "credential" | "updated_at"))
                    && !(two_factor_native_schema
                        && definition.role == Some(EntityRole::TwoFactor)
                        && matches!(field.name, "created_at" | "updated_at"))
            })
            .collect::<Vec<_>>();
        let native_catalog = sqlite_native_catalog(database, definition.role)
            || session_row_presence
            || device_code_native_schema
            || passkey_native_schema
            || two_factor_native_schema
            || matches!(
                definition.role,
                Some(
                    EntityRole::User
                        | EntityRole::Account
                        | EntityRole::Verification
                        | EntityRole::Jwk
                        | EntityRole::RateLimit
                        | EntityRole::Member
                        | EntityRole::OrganizationRole
                        | EntityRole::Team
                        | EntityRole::Invitation
                        | EntityRole::WalletAddress
                )
            );
        let mut entity = Self {
            module: syn::parse_str(definition.mod_name)
                .map_err(|error| format!("invalid model name: {error}"))?,
            name: definition.mod_name,
            registry_table: definition.table_name,
            table: if native_catalog {
                model_name(definition.mod_name)
            } else {
                definition.table_name.to_owned()
            },
            role: definition.role,
            session_row_presence,
            device_code_native_schema,
            passkey_native_schema,
            two_factor_native_schema,
            fields: fields
                .iter()
                .map(|field| {
                    let logical_name = match (definition.mod_name, field.name) {
                        ("api_key", "key_hash") => "key".to_owned(),
                        ("passkey", "credential_id") => "credentialID".to_owned(),
                        _ => field.name.to_lower_camel_case(),
                    };
                    Ok(Field {
                        ident: syn::parse_str(field.name)
                            .map_err(|error| format!("invalid field name: {error}"))?,
                        ty: syn::parse_str(
                            if passkey_native_schema && field.name == "created_at" {
                                "Option<DateTimeUtc>"
                            } else if two_factor_native_schema
                                && matches!(field.name, "verified" | "two_factor_enabled")
                            {
                                "Option<bool>"
                            } else if two_factor_native_schema
                                && field.name == "failed_verification_count"
                            {
                                if database == Database::Sqlite {
                                    "Option<i64>"
                                } else {
                                    "Option<i32>"
                                }
                            } else if passkey_native_schema
                                && field.name == "counter"
                                && database != Database::Sqlite
                            {
                                "i32"
                            } else if definition.role == Some(EntityRole::Invitation)
                                && field.name == "role"
                            {
                                "Option<String>"
                            } else if database != Database::Sqlite
                                && matches!(
                                    (definition.role, field.name),
                                    (Some(EntityRole::Team), "member_count")
                                        | (Some(EntityRole::WalletAddress), "chain_id")
                                )
                            {
                                "i32"
                            } else if database != Database::Sqlite
                                && definition.role == Some(EntityRole::OrganizationRole)
                                && field.name == "permission"
                            {
                                "String"
                            } else {
                                field.ty
                            },
                        )
                        .map_err(|error| format!("invalid field type: {error}"))?,
                        column: if native_catalog
                            && (core_field(
                                definition.role,
                                field.column_name.unwrap_or(field.name),
                            )
                            .is_some()
                                || two_factor_native_schema && field.name == "two_factor_enabled")
                        {
                            logical_name.clone()
                        } else {
                            field.column_name.unwrap_or(field.name).to_owned()
                        },
                        logical_name,
                        registry_column: Some(field.column_name.unwrap_or(field.name)),
                        serialized: (definition.mod_name == "user"
                            && matches!(
                                field.name,
                                "username" | "display_username" | "last_login_method"
                            ))
                        .then(|| field.name.to_lower_camel_case()),
                        primary_key: field.is_primary_key,
                        reference_override: (device_code_native_schema && field.name == "user_id")
                            .then_some(false),
                        unique: None,
                        attributes: None,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        if let Some(config) = config {
            if let Some(table) = config.model_name.as_ref().filter(|name| !name.is_empty()) {
                entity.table.clone_from(table);
            }
            for (name, column) in config.fields.iter().flatten() {
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
                if column.is_empty() {
                    continue;
                }
                field.column.clone_from(column);
                if field.serialized.is_some() {
                    field.serialized = Some(column.clone());
                }
            }
            for (name, field) in &config.additional_fields {
                if let Some(
                    role @ (EntityRole::ApiKey
                    | EntityRole::DeviceCode
                    | EntityRole::Passkey
                    | EntityRole::Jwk
                    | EntityRole::WalletAddress
                    | EntityRole::TwoFactor),
                ) = entity.role
                {
                    if entity.role == Some(EntityRole::DeviceCode) && name == "scope" {
                        if !matches!(&field.field_type, FieldType::Name(name) if name == "string")
                            || field.references.is_some()
                            || field
                                .field_name
                                .as_deref()
                                .is_some_and(|column| column != "scope")
                        {
                            return Err("DeviceCode scope requires its ordinary string column without reference or field-name replacement".into());
                        }
                    } else {
                        let storage = resolve_field_name(field.field_name.as_deref(), name);
                        if role == EntityRole::ApiKey && [name.as_str(), storage].contains(&"key")
                            || role == EntityRole::Passkey
                                && [name.as_str(), storage].contains(&"credentialID")
                            || matches!(
                                role,
                                EntityRole::ApiKey | EntityRole::TwoFactor | EntityRole::Passkey
                            ) && better_auth_schema_registry::core_field_names(role)
                                .iter()
                                .any(|core| {
                                    [name.as_str(), storage].into_iter().any(|name| {
                                        name == *core || name == core.to_lower_camel_case()
                                    })
                                })
                            || entity
                                .fields
                                .iter()
                                .filter(|core| core.registry_column.is_some())
                                .any(|core| {
                                    let rust = core.ident.to_string();
                                    [name.as_str(), storage].into_iter().any(|name| {
                                        name == rust
                                            || name == rust.to_lower_camel_case()
                                            || name == core.column
                                    })
                                })
                        {
                            return Err(format!(
                                "{role:?} additional field {name} cannot replace native field {storage}"
                            ));
                        }
                    }
                }
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
                let ty = if matches!(database, Database::Sqlite)
                    && matches!(&field.field_type, FieldType::Name(name) if name == "json")
                    && field.references.is_none()
                {
                    "better_auth::seaorm::SqlText"
                } else {
                    field.rust_type()?
                };
                // Upstream makes organization role fields optional while constructing update-role.
                let ty = if field.required != Some(false)
                    && entity.role != Some(EntityRole::OrganizationRole)
                {
                    ty.to_owned()
                } else {
                    format!("Option<{ty}>")
                };
                let column = resolve_field_name(field.field_name.as_deref(), name).to_owned();
                entity.fields.push(Field {
                    ident,
                    logical_name: name.clone(),
                    ty: syn::parse_str(&ty)
                        .map_err(|error| format!("invalid additional field type: {error}"))?,
                    column: column.clone(),
                    registry_column: None,
                    serialized: Some(column),
                    primary_key: false,
                    reference_override: None,
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
        if entity.role == Some(EntityRole::Team)
            && let Some(position) = entity
                .fields
                .iter()
                .position(|field| field.registry_column == Some("member_count"))
        {
            // Builtin overrides pair registry fields with their original positions.
            let member_count = entity.fields.remove(position);
            entity.fields.insert(2, member_count);
        }
        if entity.role == Some(EntityRole::Invitation) {
            // Builtin overrides use the registry order before physical field ordering.
            entity
                .fields
                .sort_by_key(|field| match field.registry_column {
                    Some("id" | "organization_id" | "email" | "role") => 0,
                    Some("team_id") => 1,
                    Some("status") => 2,
                    Some("expires_at") => 3,
                    Some("created_at") => 4,
                    Some("inviter_id") => 5,
                    _ => 6,
                });
        }
        if passkey_native_schema {
            entity
                .fields
                .sort_by_key(|field| match field.registry_column {
                    Some("created_at") => 1,
                    Some("aaguid") => 2,
                    _ => 0,
                });
        }
        Ok(entity)
    }

    pub(crate) fn column(&self, registry_column: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.registry_column == Some(registry_column))
            .map(|field| field.column.as_str())
    }

    pub(crate) fn catalog_field(&self, column: &str) -> Option<&'static FieldDef> {
        core_field(self.role, column).or_else(|| {
            if !self.two_factor_native_schema || self.role != Some(EntityRole::User) {
                return None;
            }
            better_auth_schema_registry::plugin_schemas()
                .iter()
                .flat_map(|plugin| plugin.user_fields)
                .find(|field| field.name == "two_factor_enabled" && field.name == column)
        })
    }
}

impl Field {
    pub(crate) fn references_id(&self, table: &str) -> bool {
        self.attributes.as_ref().map_or_else(
            || {
                self.reference_override.unwrap_or_else(|| {
                    better_auth_schema_registry::entity_foreign_keys(table)
                        .iter()
                        .any(|(column, _)| self.registry_column == Some(*column))
                })
            },
            |attributes| {
                attributes
                    .references
                    .as_ref()
                    .is_some_and(|reference| reference.field == "id")
            },
        )
    }

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
        self.column = resolve_field_name(
            config.field_name.as_deref(),
            definition.column_name.unwrap_or(definition.name),
        )
        .to_owned();
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
