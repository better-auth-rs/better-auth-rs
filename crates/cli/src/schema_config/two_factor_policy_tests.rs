use super::*;
use quote::ToTokens;
use serde_json::json;

#[test]
fn two_factor_replacements_share_physical_columns_and_preserve_declarations() -> Result<(), String>
{
    let config: SchemaConfig = serde_json::from_value(json!({
        "twoFactor": {"additionalFields": {
            "secret": {"type":"json","required":false,"fieldName":"shared_value"},
            "backupCodes": {"type":"string","required":false,"fieldName":"shared_value"},
            "verified": {"type":"string","required":false,"fieldName":"verified_value"},
            "failedVerificationCount": {"type":"number","required":false,"fieldName":"attempts"},
            "lockedUntil": {"type":"string","required":false,"fieldName":"lock_value"},
            "userId": {"type":"json","required":false},
            "createdAt": {"type":"date","required":false}
        }}
    }))
    .map_err(|error| error.to_string())?;
    let definition = better_auth_schema_registry::plugin_schemas()
        .iter()
        .flat_map(|plugin| plugin.extra_entities)
        .find(|entity| entity.role == Some(EntityRole::TwoFactor))
        .ok_or("Missing TwoFactor registry model")?;
    for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
        let entity = Entity::resolve(
            definition,
            better_auth_schema_registry::core_fields(EntityRole::TwoFactor),
            config.0.get("twoFactor"),
            database,
            Default::default(),
        )?;
        let shared = entity
            .fields
            .iter()
            .filter(|field| field.column == "shared_value")
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 1);
        let shared = shared.first().ok_or("Missing shared column")?;
        assert_eq!(shared.ident, "secret");
        assert_eq!(
            shared.ty.to_token_stream().to_string(),
            quote::quote!(Option<String>).to_string()
        );
        assert_eq!(entity.column("secret"), Some("shared_value"));
        assert_eq!(entity.column("backup_codes"), Some("shared_value"));
        assert_eq!(entity.logical_column("backupCodes"), Some("shared_value"));
        assert_eq!(entity.logical_column("lockedUntil"), Some("lock_value"));
        let owner = entity
            .fields
            .iter()
            .find(|field| field.logical_name == "userId")
            .ok_or("Missing owner declaration")?;
        assert!(!owner.references_id(entity.registry_table));
        assert!(
            entity
                .fields
                .iter()
                .any(|field| field.logical_name == "createdAt")
        );
        assert!(
            !entity
                .fields
                .iter()
                .any(|field| field.logical_name == "updatedAt")
        );
        let source = crate::generate::generate_schema(
            &["two-factor".into()],
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
