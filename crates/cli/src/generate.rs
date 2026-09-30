use crate::schema_config::{Entity, SchemaConfig, model_name};
use better_auth_schema_registry::{self as registry, EntityRole, ExtraEntitySchema};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

pub(crate) fn generate_schema(plugins: &[String], config: &SchemaConfig) -> Result<String, String> {
    config.validate()?;
    let mut user = registry::core_fields(EntityRole::User).to_vec();
    let mut session = registry::core_fields(EntityRole::Session).to_vec();
    let mut extra_entities: Vec<&ExtraEntitySchema> = Vec::new();
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
        definitions.push(Entity::resolve(entity, fields, configured)?);
    }
    for name in config.0.keys() {
        if !definitions
            .iter()
            .any(|entity| model_name(entity.name) == *name)
        {
            return Err(format!(
                "schema model `{name}` requires its plugin to be enabled"
            ));
        }
    }
    let mut table_names = std::collections::BTreeSet::new();
    for entity in &definitions {
        if !table_names.insert(&entity.table) {
            return Err(format!("duplicate database table `{}`", entity.table));
        }
    }
    let entities = definitions.iter().map(gen_entity);
    let tables = definitions
        .iter()
        .map(|entity| gen_table(entity, &definitions))
        .collect::<Result<Vec<_>, _>>()?;
    let indexes = definitions.iter().flat_map(gen_indexes);
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
    let plugin_models = [("api_key", "ApiKey"), ("device_code", "DeviceCode"), ("passkey", "Passkey"), ("two_factor", "TwoFactor"), ("jwk", "Jwk"), ("wallet_address", "WalletAddress")]
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
        use better_auth::seaorm::sea_orm::sea_query::{Alias, ForeignKey, ForeignKeyAction, Index};
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

fn gen_entity(entity: &Entity) -> TokenStream {
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
        let primary_key = field
            .primary_key
            .then(|| quote! { #[sea_orm(primary_key, auto_increment = false)] });
        quote! {
            #column_attr
            #serialized
            #primary_key
            pub #name: #ty,
        }
    });
    let derives = if entity.role.is_some() {
        let role = entity.name;
        quote! {
            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role)]
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

fn gen_table(entity: &Entity, entities: &[Entity]) -> Result<TokenStream, String> {
    let module = &entity.module;
    let table = &entity.table;
    let foreign_keys = registry::entity_foreign_keys(entity.registry_table)
        .iter()
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
    Ok(quote! { schema.create_table_from_entity(#module::Entity) #(#foreign_keys)* .to_owned() })
}

fn gen_indexes(entity: &Entity) -> Vec<TokenStream> {
    let table = &entity.table;
    let mut indexes: Vec<_> = registry::entity_indexes(entity.registry_table)
        .iter()
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
            if unique {
                indexes.push((vec![field.column.as_str()], true));
            }
        }
    }
    indexes.into_iter().map(|(columns, unique)| {
        let name = format!("idx_{table}_{}", columns.join("_"));
        let columns = columns.iter().map(|column| quote! { .col(Alias::new(#column)) });
        let unique = unique.then(|| quote! { .unique() });
        quote! { Index::create().name(#name).table(Alias::new(#table)) #(#columns)* #unique .to_owned() }
    }).collect()
}
