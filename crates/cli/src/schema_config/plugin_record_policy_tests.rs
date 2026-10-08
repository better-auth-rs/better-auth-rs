use super::*;
use quote::ToTokens;
use serde_json::json;

#[test]
fn jwk_and_wallet_replacements_merge_columns_and_remove_native_references() -> Result<(), String> {
    let config: SchemaConfig = serde_json::from_value(json!({
        "jwks": {"additionalFields": {
            "publicKey": {"type":"json","required":false,"fieldName":"shared_key"},
            "privateKey": {"type":"string","required":false,"fieldName":"shared_key"},
            "createdAt": {"type":"string","required":false},
            "expiresAt": {"type":"number","required":false},
            "alg": {"type":"string[]","required":false},
            "crv": {"type":"json","required":false}
        }},
        "walletAddress": {"additionalFields": {
            "userId": {"type":"number","required":false},
            "address": {"type":"json","required":false,"fieldName":"shared_value"},
            "createdAt": {"type":"string","required":false,"fieldName":"shared_value"},
            "chainId": {"type":"string","required":false},
            "isPrimary": {"type":"json","required":false}
        }}
    }))
    .map_err(|error| error.to_string())?;
    for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
        for (role, model, first, last, column) in [
            (
                EntityRole::Jwk,
                "jwks",
                "public_key",
                "private_key",
                "shared_key",
            ),
            (
                EntityRole::WalletAddress,
                "walletAddress",
                "address",
                "created_at",
                "shared_value",
            ),
        ] {
            let definition = better_auth_schema_registry::plugin_schemas()
                .iter()
                .flat_map(|plugin| plugin.extra_entities)
                .find(|entity| entity.role == Some(role))
                .ok_or("Missing plugin registry model")?;
            let entity = Entity::resolve(
                definition,
                better_auth_schema_registry::core_fields(role),
                config.0.get(model),
                database,
                Default::default(),
            )?;
            let shared = entity
                .fields
                .iter()
                .filter(|field| field.column == column)
                .collect::<Vec<_>>();
            assert_eq!(shared.len(), 1);
            let shared = shared.first().ok_or("Missing shared column")?;
            assert_eq!(shared.ident, first);
            assert_eq!(
                shared.ty.to_token_stream().to_string(),
                quote::quote!(Option<String>).to_string()
            );
            assert_eq!(entity.column(first), Some(column));
            assert_eq!(entity.column(last), Some(column));
            let json_name = if role == EntityRole::Jwk {
                "crv"
            } else {
                "isPrimary"
            };
            let json_field = entity
                .fields
                .iter()
                .find(|field| field.logical_name == json_name)
                .ok_or("Missing JSON declaration")?;
            let json_type = if database == Database::Sqlite {
                quote::quote!(Option<better_auth::seaorm::SqlText>)
            } else {
                quote::quote!(Option<Json>)
            };
            assert_eq!(
                json_field.ty.to_token_stream().to_string(),
                json_type.to_string()
            );
            if role == EntityRole::WalletAddress {
                let owner = entity
                    .fields
                    .iter()
                    .find(|field| field.logical_name == "userId")
                    .ok_or("Missing Wallet owner declaration")?;
                assert!(!owner.references_id(entity.registry_table));
                assert_eq!(
                    owner.ty.to_token_stream().to_string(),
                    quote::quote!(Option<better_auth::seaorm::SqlNumber>).to_string()
                );
            }
        }
        let source = crate::generate::generate_schema(
            &["jwt".into(), "siwe".into()],
            &config,
            false,
            IdGeneration::Random,
            database,
            Default::default(),
        )?;
        let _ = syn::parse_file(&source).map_err(|error| error.to_string())?;
    }
    Ok(())
}
