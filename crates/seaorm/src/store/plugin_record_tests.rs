use super::*;
use crate::store::{bundled_schema::BundledSchema, entities};
use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, FieldValue,
    store::{
        ApiKeyStore, JwksStore, PasskeyStore, WalletStore,
        schema::{SchemaCheckError, SchemaConfiguration, SchemaFinding},
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use sea_orm::Database;
use std::sync::Arc;

mod keys {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "jwk")]
    #[sea_orm(table_name = "replacement_jwks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub public_key: Option<f64>,
        pub created_at: Option<String>,
        pub expires_at: Option<String>,
        pub alg: Option<String>,
        pub crv: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod wallets {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "wallet_address")]
    #[sea_orm(table_name = "replacement_wallets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[auth(reference = false)]
        pub user_id: Option<f64>,
        pub address: Option<f64>,
        pub chain_id: Option<String>,
        pub is_primary: Option<String>,
        pub created_at: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod merged_api_keys {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "api_key")]
    #[sea_orm(table_name = "merged_apikey")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "shared")]
        pub config_id: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod merged_passkeys {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "passkey", native_passkey)]
    #[sea_orm(table_name = "merged_passkey")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "shared")]
        pub name: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

fn field(field_type: UserFieldType) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        required: Some(false),
        ..Default::default()
    }
}

#[tokio::test]
async fn api_key_and_passkey_preflight_accepts_merged_columns_and_rejects_missing_storage()
-> AuthResult<()> {
    type Plugins = crate::PluginModels<
        merged_api_keys::Model,
        entities::device_code::Model,
        merged_passkeys::Model,
    >;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    super::super::migrator::run_migrations(&database)
        .await
        .map_err(map_db_err)?;
    for statement in [
        "CREATE TABLE merged_apikey (id TEXT NOT NULL PRIMARY KEY, shared TEXT)",
        "CREATE TABLE merged_passkey (id TEXT NOT NULL PRIMARY KEY, shared TEXT)",
    ] {
        database
            .execute_unprepared(statement)
            .await
            .map_err(map_db_err)?;
    }
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database.clone(),
    )
    .with_plugin_schema::<Plugins>();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    for role in [EntityRole::ApiKey, EntityRole::Passkey] {
        let mut fields = better_auth_core::plugin_runtime::ModelFields::plugin_native_fields(role);
        for declaration in fields.fields_mut().values_mut() {
            *declaration = UserFieldConfig {
                field_name: Some("shared".into()),
                ..field(UserFieldType::String)
            };
        }
        init.register_model_fields(role, fields)?;
    }
    store.model_fields = init.into_parts().plugin_fields;
    let settings = SchemaConfiguration {
        config: store.config.clone(),
        plugins: vec!["api-key", "passkey"],
        metadata: Default::default(),
        secondary_storage: false,
        database_rate_limit: false,
    };
    let check = store
        .create_schema_check(&settings)?
        .ok_or_else(|| AuthError::internal("Expected the SQLite schema check"))?;
    check.check().await?;
    for (created, material) in [
        (
            store
                .create_api_key_record(FieldMap::from([
                    ("id".into(), "key".into()),
                    ("key".into(), "key-material".into()),
                ]))
                .await?,
            "key-material",
        ),
        (
            store
                .create_passkey_record(FieldMap::from([
                    ("id".into(), "passkey".into()),
                    ("credentialID".into(), "credential-material".into()),
                ]))
                .await?,
            "credential-material",
        ),
    ] {
        assert_eq!(created.get("name"), Some(&material.into()));
    }
    database
        .execute_unprepared("ALTER TABLE merged_passkey DROP COLUMN shared")
        .await
        .map_err(map_db_err)?;
    store.invalidate_schema_check();
    let Err(AuthError::SchemaCheck(error)) = check.check().await else {
        return Err(AuthError::internal(
            "Expected a missing merged column error",
        ));
    };
    let SchemaCheckError::Mismatch(error) = error.as_ref() else {
        return Err(AuthError::internal("Expected a schema mismatch"));
    };
    assert_eq!(
        error.findings,
        vec![SchemaFinding::MissingColumn {
            table: "merged_passkey".into(),
            column: "shared".into(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn passkey_and_two_factor_preflight_keep_undeclared_legacy_envelope_columns() -> AuthResult<()>
{
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    super::super::migrator::run_migrations(&database)
        .await
        .map_err(map_db_err)?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database.clone(),
    );
    let check = store
        .create_schema_check(&SchemaConfiguration {
            config: store.config.clone(),
            plugins: vec!["passkey", "two-factor"],
            metadata: Default::default(),
            secondary_storage: false,
            database_rate_limit: false,
        })?
        .ok_or_else(|| AuthError::internal("Expected the SQLite schema check"))?;
    check.check().await?;
    let missing = [
        ("passkeys", "credential"),
        ("passkeys", "updated_at"),
        ("two_factor", "created_at"),
        ("two_factor", "updated_at"),
    ];
    for (table, column) in missing {
        database
            .execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN {column}"))
            .await
            .map_err(map_db_err)?;
    }
    store.invalidate_schema_check();
    let Err(AuthError::SchemaCheck(error)) = check.check().await else {
        return Err(AuthError::internal("Expected missing legacy column errors"));
    };
    let SchemaCheckError::Mismatch(error) = error.as_ref() else {
        return Err(AuthError::internal("Expected a schema mismatch"));
    };
    assert_eq!(
        error.findings,
        missing
            .map(|(table, column)| SchemaFinding::MissingColumn {
                table: table.into(),
                column: column.into(),
            })
            .to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn native_key_and_wallet_records_keep_dynamic_fields_and_transaction_boundaries()
-> AuthResult<()> {
    type Plugins = crate::PluginModels<
        entities::api_key::Model,
        entities::device_code::Model,
        entities::passkey::Model,
        entities::two_factor::Model,
        keys::Model,
        wallets::Model,
    >;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    for statement in [
        "CREATE TABLE replacement_jwks (id TEXT PRIMARY KEY, public_key REAL, created_at TEXT, expires_at TEXT, alg TEXT, crv TEXT)",
        "CREATE TABLE replacement_wallets (id TEXT PRIMARY KEY, user_id REAL, address REAL, chain_id TEXT, is_primary TEXT, created_at TEXT)",
    ] {
        database
            .execute_unprepared(statement)
            .await
            .map_err(map_db_err)?;
    }
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    )
    .with_plugin_schema::<Plugins>();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    let add_ten = UserFieldTransform::new(|value| {
        Ok((better_auth_core::query::field_number(&value)? + 10.0).into())
    });
    init.register_model_fields(
        EntityRole::Jwk,
        UserConfig {
            additional_fields: Some(
                [
                    ("publicKey".into(), field(UserFieldType::Number)),
                    (
                        "privateKey".into(),
                        UserFieldConfig {
                            field_name: Some("public_key".into()),
                            transform: Some(FieldTransforms {
                                input: Some(add_ten.clone()),
                                ..Default::default()
                            }),
                            ..field(UserFieldType::Number)
                        },
                    ),
                    ("createdAt".into(), field(UserFieldType::String)),
                    ("expiresAt".into(), field(UserFieldType::String)),
                ]
                .into(),
            ),
        },
    )?;
    init.register_model_fields(
        EntityRole::WalletAddress,
        UserConfig {
            additional_fields: Some(
                [
                    ("userId".into(), field(UserFieldType::Number)),
                    (
                        "address".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                input: Some(add_ten),
                                output: Some(UserFieldTransform::new(|value| {
                                    Ok((better_auth_core::query::field_number(&value)? * 2.0)
                                        .into())
                                })),
                            }),
                            ..field(UserFieldType::Number)
                        },
                    ),
                    ("chainId".into(), field(UserFieldType::String)),
                    ("isPrimary".into(), field(UserFieldType::String)),
                    ("createdAt".into(), field(UserFieldType::String)),
                ]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    store.validate_jwk_fields()?;
    store.validate_wallet_fields()?;
    let key_id = "key".into();
    let created_key = store
        .create_jwk_record(FieldMap::from([
            ("id".into(), "key".into()),
            ("publicKey".into(), 2.into()),
            ("privateKey".into(), 4.into()),
            ("createdAt".into(), "key timestamp".into()),
        ]))
        .await?;
    assert_eq!(created_key.get("publicKey"), Some(&14.into()));
    assert_eq!(created_key.get("privateKey"), Some(&14.into()));
    assert_eq!(store.list_jwk_records().await?, vec![created_key.clone()]);
    let key = store
        .get_jwk("key")
        .await?
        .ok_or_else(|| AuthError::internal("Missing key"))?;
    assert_eq!(key.private_key.field_value(), FieldValue::Number(14.0));
    assert_eq!(
        key.created_at.field_value(),
        FieldValue::from("key timestamp")
    );

    let wallet_id = "wallet".into();
    let created_wallet = store
        .create_wallet_address_record(FieldMap::from([
            ("id".into(), "wallet".into()),
            ("userId".into(), 7.into()),
            ("address".into(), 5.into()),
            ("chainId".into(), "main".into()),
            ("isPrimary".into(), "primary".into()),
            ("createdAt".into(), "wallet timestamp".into()),
        ]))
        .await?;
    assert_eq!(created_wallet.get("address"), Some(&30.into()));
    let wallet = store
        .get_wallet_address_value(&15.into(), Some(&"main".into()))
        .await?
        .ok_or_else(|| AuthError::internal("Missing wallet"))?;
    assert_eq!(wallet.user_id.field_value(), FieldValue::Number(7.0));
    assert_eq!(wallet.address.field_value(), FieldValue::Number(30.0));
    assert_eq!(wallet.chain_id.field_value(), FieldValue::from("main"));
    assert!(
        store
            .get_wallet_address_value(&15.into(), Some(&"other".into()))
            .await?
            .is_none()
    );

    let aborted = better_auth_core::store::transaction::<BundledSchema, (), _>(&store, |tx| {
        Box::pin(async move {
            let updated = tx
                .update_jwk_record(
                    &"key".into(),
                    FieldMap::from([("privateKey".into(), 9.into())]),
                )
                .await?
                .ok_or_else(|| AuthError::internal("Missing key in transaction"))?;
            assert_eq!(updated.get("privateKey"), Some(&19.into()));
            tx.delete_wallet_address_record(&"wallet".into()).await?;
            assert!(
                tx.get_wallet_address_record(&"wallet".into())
                    .await?
                    .is_none()
            );
            Err(AuthError::internal("Rollback native plugin writes"))
        })
    })
    .await;
    assert!(
        matches!(aborted, Err(AuthError::Internal(message)) if message == "Rollback native plugin writes")
    );
    assert_eq!(store.get_jwk_record(&key_id).await?, Some(created_key));
    assert_eq!(
        store.get_wallet_address_record(&wallet_id).await?,
        Some(created_wallet)
    );

    let updated = store
        .update_wallet_address_record(&wallet_id, FieldMap::from([("address".into(), 8.into())]))
        .await?
        .ok_or_else(|| AuthError::internal("Missing updated wallet"))?;
    assert_eq!(updated.get("address"), Some(&36.into()));
    store.delete_jwk_record(&key_id).await?;
    store.delete_wallet_address_record(&wallet_id).await?;
    assert!(store.get_jwk_record(&key_id).await?.is_none());
    assert!(store.get_wallet_address_record(&wallet_id).await?.is_none());
    Ok(())
}
