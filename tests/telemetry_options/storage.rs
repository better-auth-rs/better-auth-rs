use super::*;
use better_auth::__private_core::store::{EphemeralStore, MemoryCacheAdapter};
use serde_json::json;

#[tokio::test]
async fn storage_context_matches_real_initialization() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/telemetry-storage-init-1.7.6.json"
    ))?;
    for database in [false, true] {
        for secondary in [false, true] {
            let (config, reports) = configuration();
            let mut builder = if database {
                BetterAuth::new(config.clone()).store(EphemeralStore::new(Arc::new(config)))
            } else {
                BetterAuth::stateless(config)
            };
            if secondary {
                builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
            }
            let auth = builder.build().await?;
            assert_eq!(auth.store().adapter_id(), "memory");
            let config = reports.config()?;
            assert!(auth.store().rate_limit_model_declaration().is_none());
            assert!(config["rateLimit"].get("modelName").is_none());
            let case = format!(
                "{}-{}",
                if database { "database" } else { "stateless" },
                if secondary { "secondary" } else { "primary" }
            );
            assert_eq!(
                json!({
                    "database": config.get("database"),
                    "adapter": config.get("adapter"),
                    "secondaryStorage": config.get("secondaryStorage"),
                }),
                fixture[case],
            );
        }
    }
    Ok(())
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
async fn sql_storage_reports_its_adapter_without_querying_a_schema() -> AuthResult<()> {
    use better_auth_seaorm::{
        SeaOrmStore, sea_orm::Database,
        store::__private_test_support::bundled_schema::BundledSchema,
    };

    for secondary in [false, true] {
        let (config, reports) = configuration();
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut builder = BetterAuth::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, database));
        if secondary {
            builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
        }
        let auth = builder.build().await?;
        let config = reports.config()?;
        assert_eq!(config.get("database"), Some(&json!("adapter")));
        assert_eq!(config.get("adapter"), Some(&json!("seaorm")));
        assert_eq!(config.get("secondaryStorage"), Some(&json!(secondary)));
        assert_eq!(auth.store().adapter_id(), "seaorm");
    }
    Ok(())
}
