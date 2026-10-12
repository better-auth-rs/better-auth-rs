#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use crate::store::{bundled_schema::BundledSchema, map_db_err, migrator};
use better_auth_core::{
    AuthConfig, AuthError,
    store::schema::{EntityRole, SchemaCheckError},
    user_fields::{UserConfig, UserFieldConfig},
};
use sea_orm::{ConnectionTrait, Database};

async fn findings(
    store: &SeaOrmStore<BundledSchema>,
    settings: &SchemaConfiguration,
) -> AuthResult<Vec<SchemaFinding>> {
    let check = store
        .create_schema_check(settings)?
        .ok_or_else(|| AuthError::internal("Expected the SQLite schema check"))?;
    match check.check().await {
        Ok(()) => Ok(Vec::new()),
        Err(AuthError::SchemaCheck(error)) => {
            let SchemaCheckError::Mismatch(mismatch) = error.as_ref() else {
                return Err(AuthError::SchemaCheck(error));
            };
            Ok(mismatch.findings.clone())
        }
        Err(error) => Err(error),
    }
}

#[tokio::test]
async fn a_plugin_name_without_a_declaration_does_not_require_a_passkey_table() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    migrator::run_migrations(&database)
        .await
        .map_err(map_db_err)?;
    let _ = database
        .execute_unprepared("DROP TABLE passkeys")
        .await
        .map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let settings = SchemaConfiguration {
        config: store.config.clone(),
        plugins: vec!["passkey"],
        metadata: Default::default(),
        secondary_storage: false,
        rate_limit: Default::default(),
    };
    store.model_fields.set_schema_configuration(&settings);
    assert!(findings(&store, &settings).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn rate_limit_preflight_uses_declared_memory_fields_and_replaced_database_fields()
-> AuthResult<()> {
    for database_rate_limit in [false, true] {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(map_db_err)?;
        migrator::run_migrations(&database)
            .await
            .map_err(map_db_err)?;
        let mut store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("a-secret-that-is-at-least-32-characters"),
            database.clone(),
        );
        let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
        model_fields.register_model_fields(
            EntityRole::RateLimit,
            UserConfig {
                additional_fields: Some(
                    [(
                        "key".into(),
                        UserFieldConfig {
                            field_name: Some("count".into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )?;
        store.model_fields = model_fields;
        let settings = SchemaConfiguration {
            config: store.config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: false,
            rate_limit: better_auth_core::middleware::RateLimitConfig {
                storage: database_rate_limit
                    .then_some(better_auth_core::middleware::RateLimitStorageKind::Database),
                ..Default::default()
            },
        };
        store.model_fields.set_schema_configuration(&settings);
        let unwritten = if database_rate_limit {
            Vec::new()
        } else {
            ["key", "last_request"]
                .map(|column| SchemaFinding::UnexpectedRequiredColumn {
                    table: "rate_limit".into(),
                    column: column.into(),
                })
                .to_vec()
        };
        assert_eq!(findings(&store, &settings).await?, unwritten);
        let _ = database
            .execute_unprepared("ALTER TABLE rate_limit DROP COLUMN count")
            .await
            .map_err(map_db_err)?;
        let expected = std::iter::once(SchemaFinding::MissingColumn {
            table: "rate_limit".into(),
            column: "count".into(),
        })
        .chain(unwritten)
        .collect::<Vec<_>>();
        assert_eq!(findings(&store, &settings).await?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn secondary_storage_hides_explicit_core_declarations_from_physical_preflight()
-> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    migrator::run_migrations(&database)
        .await
        .map_err(map_db_err)?;
    for table in ["sessions", "verifications"] {
        let _ = database
            .execute_unprepared(&format!("DROP TABLE {table}"))
            .await
            .map_err(map_db_err)?;
    }
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    for role in [EntityRole::Session, EntityRole::Verification] {
        model_fields.register_model_fields(role, UserConfig::default())?;
    }
    store.model_fields = model_fields;
    for secondary_storage in [true, false] {
        let settings = SchemaConfiguration {
            config: store.config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage,
            rate_limit: Default::default(),
        };
        store.model_fields.set_schema_configuration(&settings);
        let expected = if secondary_storage {
            Vec::new()
        } else {
            ["sessions", "verifications"]
                .map(|table| SchemaFinding::MissingTable {
                    table: table.into(),
                })
                .to_vec()
        };
        assert_eq!(findings(&store, &settings).await?, expected);
    }
    Ok(())
}
