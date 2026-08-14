use better_auth_schema_registry::{self as registry, EntityRole, ExtraEntitySchema, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

pub(crate) fn generate_schema(plugins: &[String]) -> String {
    // Collect plugin fields for user and session
    let mut extra_user: Vec<FieldDef> = Vec::new();
    let mut extra_session: Vec<FieldDef> = Vec::new();
    let mut extra_entities: Vec<&ExtraEntitySchema> = Vec::new();

    for plugin_name in plugins {
        if let Some(schema) = registry::plugin_schemas()
            .iter()
            .find(|p| p.name == plugin_name.as_str())
        {
            extra_user.extend_from_slice(schema.user_fields);
            extra_session.extend_from_slice(schema.session_fields);
            extra_entities.extend(schema.extra_entities.iter());
        }
    }

    let imports = quote! {
        use better_auth::AuthSchema;
        use better_auth::seaorm::sea_orm;
        use better_auth::seaorm::sea_orm::entity::prelude::*;
        use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
        use better_auth::seaorm::{AuthEntity, DatabaseConnection};
    };

    let user_entity = gen_entity("user", "users", EntityRole::User, &extra_user);
    let session_entity = gen_entity("session", "sessions", EntityRole::Session, &extra_session);
    let account_entity = gen_entity("account", "accounts", EntityRole::Account, &[]);
    let verification_entity = gen_entity(
        "verification",
        "verifications",
        EntityRole::Verification,
        &[],
    );
    let extra_entity_tokens: Vec<TokenStream> = extra_entities
        .iter()
        .map(|entity| gen_extra_entity(entity))
        .collect();

    let schema_impl = quote! {
        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }
    };

    let extra_migration_statements: Vec<TokenStream> = extra_entities
        .iter()
        .map(|entity| {
            let mod_ident = format_ident!("{}", entity.mod_name);
            quote! { schema.create_table_from_entity(#mod_ident::Entity).if_not_exists().to_owned() }
        })
        .collect();

    let migration_fn = quote! {
        pub async fn run_app_migrations(
            database: &DatabaseConnection,
        ) -> Result<(), sea_orm::DbErr> {
            let schema = Schema::new(database.get_database_backend());
            for statement in [
                schema.create_table_from_entity(user::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(session::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(account::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(verification::Entity).if_not_exists().to_owned(),
                #(#extra_migration_statements,)*
            ] {
                let _ = database.execute(&statement).await?;
            }
            Ok(())
        }
    };

    let tokens = quote! {
        #imports
        #user_entity
        #session_entity
        #account_entity
        #verification_entity
        #(#extra_entity_tokens)*
        #schema_impl
        #migration_fn
    };

    #[expect(
        clippy::expect_used,
        reason = "generated from hardcoded registry; parse failure is a bug"
    )]
    let file = syn::parse2(tokens).expect("generated code should be valid syntax");
    prettyplease::unparse(&file)
}

fn gen_entity(
    mod_name: &str,
    table_name: &str,
    role: EntityRole,
    plugin_fields: &[FieldDef],
) -> TokenStream {
    let mod_ident = format_ident!("{}", mod_name);
    let role_str = mod_name;

    let core = registry::core_fields(role);
    let all_fields: Vec<&FieldDef> = core.iter().chain(plugin_fields.iter()).collect();

    let field_tokens: Vec<TokenStream> = all_fields
        .iter()
        .map(|f| {
            let name = format_ident!("{}", f.name);
            #[expect(
                clippy::panic,
                reason = "type strings come from hardcoded registry; parse failure is a bug"
            )]
            let ty: syn::Type = syn::parse_str(f.ty)
                .unwrap_or_else(|e| panic!("invalid type `{}` for field `{}`: {e}", f.ty, f.name));
            let column_attr = f.column_name.map(|column_name| {
                quote! { #[sea_orm(column_name = #column_name)] }
            });
            if f.is_primary_key {
                quote! {
                    #column_attr
                    #[sea_orm(primary_key, auto_increment = false)]
                    pub #name: #ty,
                }
            } else {
                quote! {
                    #column_attr
                    pub #name: #ty,
                }
            }
        })
        .collect();

    quote! {
        mod #mod_ident {
            use super::*;

            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role_str)]
            #[sea_orm(table_name = #table_name)]
            pub struct Model {
                #(#field_tokens)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

fn gen_extra_entity(entity: &ExtraEntitySchema) -> TokenStream {
    let mod_ident = format_ident!("{}", entity.mod_name);
    let table_name = entity.table_name;

    let field_tokens: Vec<TokenStream> = entity
        .fields
        .iter()
        .map(|f| {
            let name = format_ident!("{}", f.name);
            #[expect(
                clippy::panic,
                reason = "type strings come from hardcoded registry; parse failure is a bug"
            )]
            let ty: syn::Type = syn::parse_str(f.ty)
                .unwrap_or_else(|e| panic!("invalid type `{}` for field `{}`: {e}", f.ty, f.name));
            let column_attr = f.column_name.map(|column_name| {
                quote! { #[sea_orm(column_name = #column_name)] }
            });
            if f.is_primary_key {
                quote! {
                    #column_attr
                    #[sea_orm(primary_key, auto_increment = false)]
                    pub #name: #ty,
                }
            } else {
                quote! {
                    #column_attr
                    pub #name: #ty,
                }
            }
        })
        .collect();

    let derive_attrs = if let Some(role) = entity.role {
        let role_str = match role {
            EntityRole::User => "user",
            EntityRole::Session => "session",
            EntityRole::Account => "account",
            EntityRole::Verification => "verification",
        };
        quote! {
            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role_str)]
        }
    } else {
        quote! {
            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
        }
    };

    quote! {
        mod #mod_ident {
            use super::*;

            #derive_attrs
            #[sea_orm(table_name = #table_name)]
            pub struct Model {
                #(#field_tokens)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_schema, list_plugins};

    #[test]
    fn list_plugins_includes_passkey() {
        assert!(list_plugins().contains(&"passkey"));
    }

    #[test]
    fn generate_schema_with_passkey_emits_entity_and_migration() {
        let schema = generate_schema(&["passkey".to_string()]);

        assert!(schema.contains("mod passkey"));
        assert!(schema.contains("#[sea_orm(table_name = \"passkeys\")]"));
        assert!(schema.contains("pub credential: String"));
        assert!(schema.contains("pub aaguid: Option<String>"));
        assert!(schema.contains("schema.create_table_from_entity(passkey::Entity)"));
    }

    #[test]
    fn generate_schema_phase_zero_through_eight_plugins_emit_required_entities() {
        let schema = generate_schema(&[
            "device-authorization".to_string(),
            "api-key".to_string(),
            "organization".to_string(),
            "passkey".to_string(),
        ]);

        assert!(schema.contains("mod device_code"));
        assert!(schema.contains("mod api_key"));
        assert!(schema.contains("mod organization"));
        assert!(schema.contains("mod member"));
        assert!(schema.contains("mod invitation"));
        assert!(schema.contains("#[sea_orm(column_name = \"key\")]"));
        assert!(schema.contains("schema.create_table_from_entity(device_code::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(api_key::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(organization::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(member::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(invitation::Entity)"));
    }
}
