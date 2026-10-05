use crate::schema_config::{
    AdditionalField, Database, Entity, Field, FieldType, IdGeneration, OnDelete, SchemaConfig,
    core_field, model_name, sqlite_native_catalog,
};
use better_auth_schema_registry::{self as registry, EntityRole, ExtraEntitySchema};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

pub(crate) fn generate_schema(
    plugins: &[String],
    config: &SchemaConfig,
    rate_limit_database: bool,
    generation: IdGeneration,
    database: Database,
    session_active_column: bool,
) -> Result<String, String> {
    config.validate()?;
    let mut user = registry::core_fields(EntityRole::User).to_vec();
    let mut session = registry::core_fields(EntityRole::Session).to_vec();
    if !session_active_column {
        session.retain(|field| field.name != "active");
    }
    let mut extra_entities: Vec<&ExtraEntitySchema> = Vec::new();
    if rate_limit_database {
        extra_entities.push(&registry::RATE_LIMIT);
    }
    for plugin_name in plugins {
        if let Some(schema) = registry::plugin_schemas()
            .iter()
            .find(|p| p.name == plugin_name.as_str())
        {
            user.extend_from_slice(schema.user_fields);
            session.extend_from_slice(schema.session_fields);
            extra_entities.extend(schema.extra_entities.iter());
        }
    }
    let core_entities = [
        ExtraEntitySchema {
            mod_name: "user",
            table_name: "users",
            role: Some(EntityRole::User),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "session",
            table_name: "sessions",
            role: Some(EntityRole::Session),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "account",
            table_name: "accounts",
            role: Some(EntityRole::Account),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "verification",
            table_name: "verifications",
            role: Some(EntityRole::Verification),
            fields: &[],
        },
    ];
    let mut definitions = Vec::new();
    for entity in core_entities.iter().chain(extra_entities) {
        let fields = match entity.role {
            Some(EntityRole::User) => user.as_slice(),
            Some(EntityRole::Session) => session.as_slice(),
            Some(role) => registry::core_fields(role),
            None => entity.fields,
        };
        let configured = config.0.get(&model_name(entity.mod_name));
        let mut entity =
            Entity::resolve(entity, fields, configured, database, session_active_column)?;
        entity.resolve_ids(generation, database)?;
        definitions.push(entity);
    }
    for name in config.0.keys() {
        if !definitions
            .iter()
            .any(|entity| model_name(entity.name) == *name)
        {
            return Err(format!(
                "schema model `{name}` requires its plugin or database storage option to be enabled"
            ));
        }
    }
    let mut table_names = std::collections::BTreeSet::new();
    for entity in &definitions {
        if !table_names.insert(&entity.table) {
            return Err(format!("duplicate database table `{}`", entity.table));
        }
    }
    let entities = definitions
        .iter()
        .map(|entity| gen_entity(entity, generation, config));
    let tables = definitions
        .iter()
        .map(|entity| gen_table(entity, &definitions, generation, database))
        .collect::<Result<Vec<_>, _>>()?;
    let indexes = definitions
        .iter()
        .flat_map(|entity| gen_indexes(entity, database));
    let declarations = [
        ("user", "User"),
        ("session", "Session"),
        ("account", "Account"),
        ("verification", "Verification"),
    ]
    .into_iter()
    .filter_map(|(name, role)| {
        let model = config.0.get(name)?;
        let role = format_ident!("{role}");
        let model_name = match &model.model_name {
            Some(name) => quote!(Some(#name)),
            None => quote!(None),
        };
        let fields = match &model.fields {
            Some(fields) => {
                let fields = fields.iter().map(|(name, column)| quote!((#name, #column)));
                quote!(Some(&[#(#fields),*]))
            }
            None => quote!(None),
        };
        Some(quote! {
            better_auth::schema::ModelDeclaration {
                role: better_auth::schema::EntityRole::#role,
                model_name: #model_name,
                fields: #fields,
            }
        })
    });
    let organization_schema = definitions
        .iter()
        .any(|entity| entity.role == Some(EntityRole::Organization))
        .then(|| {
            quote! {
                pub type AppOrganizationSchema = better_auth::seaorm::OrganizationModels<
                    organization::Model, member::Model, invitation::Model,
                    team::Model, team_member::Model, organization_role::Model
                >;
            }
        });
    let plugin_models = [("api_key", "ApiKey"), ("device_code", "DeviceCode"), ("passkey", "Passkey"), ("two_factor", "TwoFactor"), ("jwk", "Jwk"), ("wallet_address", "WalletAddress"), ("rate_limit", "RateLimit")]
        .map(|(name, role)| {
            let module = format_ident!("{name}");
            let role = format_ident!("{role}");
            if definitions.iter().any(|entity| entity.name == name) {
                quote!(#module::Model)
            } else {
                quote!(<better_auth::seaorm::PluginModels as better_auth::seaorm::SeaOrmPluginSchema>::#role)
            }
        });
    let plugin_schema = definitions
        .iter()
        .any(|entity| {
            matches!(
                entity.role,
                Some(
                    EntityRole::ApiKey
                        | EntityRole::DeviceCode
                        | EntityRole::Passkey
                        | EntityRole::TwoFactor
                        | EntityRole::Jwk
                        | EntityRole::WalletAddress
                        | EntityRole::RateLimit
                )
            )
        })
        .then(|| {
            quote! {
                pub type AppPluginSchema = better_auth::seaorm::PluginModels<#(#plugin_models),*>;
            }
        });
    let arrays = [("StringArray", quote!(String)), ("NumberArray", quote!(f64))].into_iter().filter_map(|(name, element)| {
        let used = definitions.iter().flat_map(|entity| &entity.fields).any(|field| {
            let ty = &field.ty;
            quote!(#ty).to_string().contains(name)
        });
        used.then(|| {
            let name = format_ident!("{name}");
            quote! {
                #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, FromJsonQueryResult)]
                #[serde(transparent)]
                pub struct #name(pub Vec<#element>);
            }
        })
    });
    let tokens = quote! {
        use better_auth::AuthSchema;
        use better_auth::seaorm::sea_orm;
        use better_auth::seaorm::sea_orm::entity::prelude::*;
        use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
        use better_auth::seaorm::sea_orm::sea_query::{Alias, ForeignKey, ForeignKeyAction, Index, Table};
        use better_auth::seaorm::AuthEntity;

        #(#arrays)*
        #(#entities)*
        #organization_schema
        #plugin_schema

        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;

            fn model_declarations() -> &'static [better_auth::schema::ModelDeclaration] {
                &[#(#declarations),*]
            }
        }

        /// Create auth tables in an empty database.
        ///
        /// Call this scaffold from the application's initial migration.
        /// Use versioned migrations to change existing tables.
        pub async fn create_auth_tables(database: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
            let schema = Schema::new(database.get_database_backend());
            for statement in [#(#tables,)*] {
                let _ = database.execute(&statement).await?;
            }
            for statement in [#(#indexes,)*] {
                let _ = database.execute(&statement).await?;
            }
            Ok(())
        }
    };
    let file = syn::parse2(tokens).map_err(|error| format!("cannot generate schema: {error}"))?;
    Ok(prettyplease::unparse(&file))
}

fn gen_entity(entity: &Entity, generation: IdGeneration, config: &SchemaConfig) -> TokenStream {
    let mod_ident = &entity.module;
    let table_name = &entity.table;
    let field_tokens = entity.fields.iter().map(|field| {
        let name = &field.ident;
        let ty = &field.ty;
        let column = &field.column;
        let column_attr =
            (name != column.as_str()).then(|| quote! { #[sea_orm(column_name = #column)] });
        let serialized = field
            .serialized
            .as_ref()
            .map(|name| quote! { #[serde(rename = #name)] });
        let auto_increment = generation == IdGeneration::Serial;
        let primary_key = field
            .primary_key
            .then(|| quote! { #[sea_orm(primary_key, auto_increment = #auto_increment)] });
        let number_storage = if entity.role == Some(EntityRole::RateLimit) && name == "count" {
            Some(quote!(#[sea_orm(column_type = "Integer")]))
        } else if entity.role == Some(EntityRole::DeviceCode) && name == "polling_interval" {
            Some(quote!(#[sea_orm(column_type = "Integer", nullable)]))
        } else {
            None
        };
        let reference = (entity.role.is_some()
            && field.attributes.is_some()
            && field.references_id(entity.registry_table))
        .then(|| quote!(#[auth(reference)]));
        quote! {
            #column_attr
            #serialized
            #primary_key
            #number_storage
            #reference
            pub #name: #ty,
        }
    });
    let derives = if entity.role.is_some() {
        let role = entity.name;
        let declaration = (entity.role == Some(EntityRole::RateLimit))
            .then(|| {
                config
                    .0
                    .get("rateLimit")
                    .and_then(|model| model.model_name.as_ref())
            })
            .flatten()
            .map(|name| quote!(, model_name = #name));
        let row_presence = entity.session_row_presence.then(|| quote!(, row_presence));
        quote! {
            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role #declaration #row_presence)]
        }
    } else {
        quote! { #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)] }
    };
    quote! {
        pub mod #mod_ident {
            use super::*;
            #derives
            #[sea_orm(table_name = #table_name)]
            pub struct Model { #(#field_tokens)* }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

fn gen_table(
    entity: &Entity,
    entities: &[Entity],
    generation: IdGeneration,
    database: Database,
) -> Result<TokenStream, String> {
    let module = &entity.module;
    let table = &entity.table;
    let mut foreign_keys = registry::entity_foreign_keys(entity.registry_table)
        .iter()
        .filter(|entry| {
            entity
                .fields
                .iter()
                .find(|field| field.registry_column == Some(entry.0))
                .is_none_or(|field| field.attributes.is_none())
        })
        .map(|(column, target)| {
            let column = entity
                .column(column)
                .ok_or_else(|| format!("foreign key column `{table}.{column}` is missing"))?;
            let target = entities
                .iter()
                .find(|entity| entity.registry_table == *target)
                .map(|entity| entity.table.as_str())
                .ok_or_else(|| format!("foreign key target `{target}` is missing"))?;
            let name = format!("fk_{table}_{column}");
            Ok(quote! {
                .foreign_key(ForeignKey::create()
                    .name(#name)
                    .from(Alias::new(#table), Alias::new(#column))
                    .to(Alias::new(#target), Alias::new("id"))
                    .on_delete(ForeignKeyAction::Cascade))
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    for field in &entity.fields {
        let Some(reference) = field
            .attributes
            .as_ref()
            .and_then(|field| field.references.as_ref())
        else {
            continue;
        };
        let (target, target_column) = entities
            .iter()
            .find(|entity| model_name(entity.name) == reference.model)
            .and_then(|entity| {
                entity
                    .fields
                    .iter()
                    .find(|field| field.logical_name == reference.field)
                    .map(|field| (entity.table.as_str(), field.column.as_str()))
            })
            .unwrap_or((&reference.model, &reference.field));
        let column = &field.column;
        let name = format!("fk_{table}_{column}");
        let action = match reference.on_delete.unwrap_or_default() {
            OnDelete::NoAction => quote!(NoAction),
            OnDelete::Restrict => quote!(Restrict),
            OnDelete::Cascade => quote!(Cascade),
            OnDelete::SetNull => quote!(SetNull),
            OnDelete::SetDefault => quote!(SetDefault),
        };
        foreign_keys.push(quote! {
            .foreign_key(ForeignKey::create()
                .name(#name)
                .from(Alias::new(#table), Alias::new(#column))
                .to(Alias::new(#target), Alias::new(#target_column))
                .on_delete(ForeignKeyAction::#action))
        });
    }
    let types: Vec<_> = entity
        .fields
        .iter()
        .filter_map(|field| {
            let name = &field.column;
            let reference = field.references_id(entity.registry_table);
            if field.primary_key || reference {
                let data_type = match generation {
                    IdGeneration::Serial => quote!(column.integer();),
                    IdGeneration::Uuid => quote! {
                        if database.get_database_backend() == sea_orm::DbBackend::Postgres { column.uuid(); }
                        else if database.get_database_backend() == sea_orm::DbBackend::MySql { column.string_len(36); }
                        else { column.text(); }
                    },
                    _ => quote! {
                        if database.get_database_backend() == sea_orm::DbBackend::MySql { column.string_len(36); }
                        else { column.text(); }
                    },
                };
                let primary = field.primary_key.then(|| match generation {
                    IdGeneration::Serial => quote! {
                        column = sea_orm::sea_query::ColumnDef::new(Alias::new(#name)).integer().not_null().primary_key().to_owned();
                        if database.get_database_backend() == sea_orm::DbBackend::Postgres {
                            column.custom(Alias::new("integer GENERATED BY DEFAULT AS IDENTITY"));
                        } else if database.get_database_backend() == sea_orm::DbBackend::MySql { column.auto_increment(); }
                    },
                    IdGeneration::Uuid => quote! {
                        if database.get_database_backend() == sea_orm::DbBackend::Postgres {
                            column.default(sea_orm::sea_query::Expr::cust("pg_catalog.gen_random_uuid()"));
                        }
                    },
                    _ => quote!(),
                });
                let unique = field.attributes.as_ref().is_some_and(|attributes| attributes.unique)
                    .then(|| quote!(column.unique_key();));
                return Some(quote! {
                    if column.get_column_name().as_str() == #name {
                        #data_type #primary #unique
                    }
                });
            }
            if let Some(column) = gen_server_native_column(entity, field, database) {
                return Some(column);
            }
            if database == Database::Sqlite
                && (sqlite_native_catalog(database, entity.role) || entity.session_row_presence)
                && field.attributes.is_none()
            {
                let definition = core_field(entity.role, field.registry_column?)?;
                let data_type = match definition.ty {
                    "String" | "Option<String>" => quote!(column.text();),
                    "bool" => quote!(column.integer();),
                    "DateTimeUtc" | "Option<DateTimeUtc>" => {
                        quote!(column.custom(Alias::new("date"));)
                    }
                    "i64" if entity.role == Some(EntityRole::Team)
                        && definition.name == "member_count" => quote!(column.integer();),
                    "i64" => quote!(column.custom(Alias::new("bigint"));),
                    "Json" if entity.role == Some(EntityRole::OrganizationRole)
                        && definition.name == "permission" => quote!(column.text();),
                    _ => return None,
                };
                let unique = inline_native_unique(entity, field, database)
                    .then(|| quote!(column.unique_key();));
                let required_email = (entity.role == Some(EntityRole::User)
                    && definition.name == "email")
                    .then(|| quote!(column.not_null();));
                return Some(quote! {
                    if column.get_column_name().as_str() == #name {
                        #data_type #unique #required_email
                    }
                });
            }
            let attributes = field.attributes.as_ref()?;
            let data_type = gen_column_type(attributes);
            let nullability = if attributes.required != Some(false)
                && entity.role != Some(EntityRole::OrganizationRole)
            {
                quote!(column.not_null();)
            } else {
                quote!(column.null();)
            };
            // Referenced unique columns must exist when foreign keys are created.
            let unique = attributes.unique.then(|| quote!(column.unique_key();));
            Some(quote! {
                if column.get_column_name().as_str() == #name {
                    #data_type #nullability #unique
                }
            })
        })
        .collect();
    let configure_columns = if types.is_empty() {
        quote! {
            for column in schema.create_table_from_entity(#module::Entity).get_columns().clone() {
                table.col(column);
            }
        }
    } else {
        quote! {
            for mut column in schema.create_table_from_entity(#module::Entity).get_columns().clone() {
                #(#types)*
                table.col(column);
            }
        }
    };
    Ok(quote! {{
        let mut table = Table::create();
        table.table(Alias::new(#table));
        #configure_columns
        table #(#foreign_keys)* .to_owned()
    }})
}

fn gen_server_native_column(
    entity: &Entity,
    field: &Field,
    database: Database,
) -> Option<TokenStream> {
    if database == Database::Sqlite
        || !(entity.session_row_presence
            || matches!(
                entity.role,
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
                )
            ))
        || field.attributes.is_some()
    {
        return None;
    }
    let definition = core_field(entity.role, field.registry_column?)?;
    let data_type = match (database, definition.ty) {
        (Database::Mysql, "String" | "Option<String>")
            if matches!(
                (entity.role, definition.name),
                (Some(EntityRole::User), "name" | "email")
                    | (Some(EntityRole::Session), "token")
                    | (Some(EntityRole::Verification), "identifier")
                    | (Some(EntityRole::RateLimit), "key")
                    | (Some(EntityRole::Member), "role")
                    | (Some(EntityRole::OrganizationRole), "role")
                    | (
                        Some(EntityRole::Invitation),
                        "email" | "role" | "team_id" | "status"
                    )
            ) =>
        {
            quote!(column.string_len(255);)
        }
        (_, "String" | "Option<String>") => quote!(column.text();),
        (_, "i64")
            if entity.role == Some(EntityRole::Team) && definition.name == "member_count" =>
        {
            quote!(column.integer();)
        }
        (_, "Json")
            if entity.role == Some(EntityRole::OrganizationRole)
                && definition.name == "permission" =>
        {
            quote!(column.text();)
        }
        (_, "bool") => quote!(column.boolean();),
        (Database::Postgres, "DateTimeUtc" | "Option<DateTimeUtc>") => {
            quote!(column.timestamp_with_time_zone();)
        }
        (Database::Mysql, "DateTimeUtc" | "Option<DateTimeUtc>") => {
            quote!(column.custom(Alias::new("timestamp(3)"));)
        }
        _ => return None,
    };
    let required_email = (entity.role == Some(EntityRole::User) && definition.name == "email")
        .then(|| quote!(column.not_null();));
    let unique =
        inline_native_unique(entity, field, database).then(|| quote!(column.unique_key();));
    let timestamp_default = if database == Database::Mysql {
        quote!(sea_orm::sea_query::Expr::custom_keyword(
            "CURRENT_TIMESTAMP(3)"
        ))
    } else {
        quote!(sea_orm::sea_query::Expr::cust("CURRENT_TIMESTAMP"))
    };
    let default = matches!(
        (entity.role, definition.name),
        (
            Some(
                EntityRole::User
                    | EntityRole::Session
                    | EntityRole::Account
                    | EntityRole::Verification
                    | EntityRole::OrganizationRole
                    | EntityRole::Invitation
            ),
            "created_at"
        ) | (
            Some(EntityRole::User | EntityRole::Verification),
            "updated_at"
        )
    )
    .then(|| quote!(column.default(#timestamp_default);));
    let name = &field.column;
    Some(quote! {
        if column.get_column_name().as_str() == #name {
            #data_type #required_email #unique #default
        }
    })
}

fn gen_column_type(field: &AdditionalField) -> TokenStream {
    let FieldType::Name(name) = &field.field_type else {
        return quote!(column.text(););
    };
    match name.as_str() {
        "number" if field.bigint => quote!(column.custom(Alias::new("BIGINT"));),
        "number" => quote!(column.integer();),
        "string"
            if !field.unique && field.references.is_none() && !field.sortable && !field.index =>
        {
            quote!(column.text();)
        }
        "string" => {
            let mysql = if field.unique {
                quote!(column.string_len(255);)
            } else if field.references.is_some() {
                quote!(column.string_len(36);)
            } else if field.sortable || field.index {
                quote!(column.string_len(255);)
            } else {
                quote!(column.text();)
            };
            quote! {
                if database.get_database_backend() == sea_orm::DbBackend::MySql {
                    #mysql
                } else {
                    column.text();
                }
            }
        }
        "boolean" => quote! {
            if database.get_database_backend() == sea_orm::DbBackend::Sqlite {
                column.integer();
            } else {
                column.boolean();
            }
        },
        "date" => quote! {
            match database.get_database_backend() {
                sea_orm::DbBackend::Sqlite => { column.date(); }
                sea_orm::DbBackend::Postgres => { column.timestamp_with_time_zone(); }
                sea_orm::DbBackend::MySql => { column.custom(Alias::new("timestamp(3)")); }
                backend => return Err(sea_orm::DbErr::Custom(format!("Unsupported database backend: {backend:?}"))),
            }
        },
        "json" | "string[]" | "number[]" => quote! {
            match database.get_database_backend() {
                sea_orm::DbBackend::Sqlite => { column.text(); }
                sea_orm::DbBackend::Postgres => { column.json_binary(); }
                sea_orm::DbBackend::MySql => { column.json(); }
                backend => return Err(sea_orm::DbErr::Custom(format!("Unsupported database backend: {backend:?}"))),
            }
        },
        _ => quote!(),
    }
}

fn inline_native_unique(entity: &Entity, field: &Field, database: Database) -> bool {
    (sqlite_native_catalog(database, entity.role) || entity.session_row_presence)
        && field.attributes.is_none()
        && field.registry_column.is_some_and(|column| {
            core_field(entity.role, column).is_some()
                && registry::entity_indexes(entity.registry_table)
                    .iter()
                    .any(|index| index.unique && index.columns == [column])
        })
}

fn gen_indexes(entity: &Entity, database: Database) -> Vec<TokenStream> {
    let table = &entity.table;
    let mut indexes: Vec<_> = registry::entity_indexes(entity.registry_table)
        .iter()
        .filter(|index| !(entity.session_row_presence && index.columns == ["expires_at"]))
        .filter(|index| {
            !(database == Database::Sqlite
                && entity.role == Some(EntityRole::Invitation)
                && index.columns == ["status"])
        })
        .filter(|index| {
            !entity.fields.iter().any(|field| {
                inline_native_unique(entity, field, database)
                    && index.unique
                    && field
                        .registry_column
                        .is_some_and(|column| index.columns == [column])
            })
        })
        .filter_map(|index| {
            let columns = index
                .columns
                .iter()
                .map(|column| entity.column(column))
                .collect::<Option<Vec<_>>>()?;
            Some((columns, index.unique))
        })
        .collect();
    for field in &entity.fields {
        if let Some(unique) = field.unique {
            indexes.retain(|(columns, _)| columns.as_slice() != [field.column.as_str()]);
            if !unique && field.attributes.as_ref().is_some_and(|field| field.index) {
                indexes.push((vec![field.column.as_str()], false));
            }
        }
    }
    indexes.into_iter().map(|(columns, unique)| {
        let native_index = entity.fields.iter().find(|field| {
            matches!(database, Database::Sqlite)
                && (matches!(
                    (entity.role, field.registry_column),
                    (Some(EntityRole::Verification), Some("identifier"))
                        | (Some(EntityRole::Account), Some("user_id"))
                        | (Some(EntityRole::Member), Some("organization_id" | "user_id"))
                        | (Some(EntityRole::OrganizationRole), Some("organization_id" | "role"))
                        | (Some(EntityRole::Team), Some("organization_id"))
                        | (Some(EntityRole::Invitation), Some("organization_id" | "email"))
                ) || (entity.session_row_presence && field.registry_column == Some("user_id")))
                && field.attributes.is_none()
                && !unique && columns.as_slice() == [field.column.as_str()]
        });
        let name = if let Some(field) = native_index {
            sqlite_field_index_name(table, &field.column)
        } else {
            format!("idx_{table}_{}", columns.join("_"))
        };
        let columns = columns.iter().map(|column| quote! { .col(Alias::new(#column)) });
        let unique = unique.then(|| quote! { .unique() });
        quote! { Index::create().name(#name).table(Alias::new(#table)) #(#columns)* #unique .to_owned() }
    }).collect()
}

fn sqlite_field_index_name(table: &str, column: &str) -> String {
    let prefix = format!("{table}_{column}");
    let name = format!("{prefix}_idx");
    if name.len() <= 63 {
        return name;
    }
    // Upstream hashes UTF-16 units but bounds the stored name in UTF-8 bytes.
    let hash = name.encode_utf16().fold(2_166_136_261_u32, |hash, unit| {
        (hash ^ u32::from(unit)).wrapping_mul(16_777_619)
    });
    let suffix = format!("_{hash:08x}_idx");
    let mut bytes = 0;
    let prefix: String = prefix
        .chars()
        .take_while(|character| {
            bytes += character.len_utf8();
            bytes <= 63 - suffix.len()
        })
        .collect();
    format!("{prefix}{suffix}")
}
