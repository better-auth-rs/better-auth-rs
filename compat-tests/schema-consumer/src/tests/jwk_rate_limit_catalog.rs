use better_auth::seaorm::{Database, sea_orm::EntityName};
use serde_json::{Value, json};

mod default {
    include!(env!("BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_DEFAULT_SCHEMA"));
}

mod legacy {
    include!(env!("BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_LEGACY_SCHEMA"));
}

mod custom {
    include!(env!("BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_CUSTOM_SCHEMA"));
}

#[tokio::test]
async fn generated_jwk_rate_limit_catalog_matches_pinned_sqlite() {
    let mut cases = Vec::new();
    for name in ["default", "legacy", "custom"] {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let table_names = match name {
            "default" => {
                let _schema = default::AppAuthSchema;
                let _plugins = std::marker::PhantomData::<default::AppPluginSchema>;
                default::create_auth_tables(&database).await.unwrap();
                [
                    default::jwk::Entity.table_name().to_owned(),
                    default::rate_limit::Entity.table_name().to_owned(),
                ]
            }
            "legacy" => {
                let _schema = legacy::AppAuthSchema;
                let _plugins = std::marker::PhantomData::<legacy::AppPluginSchema>;
                legacy::create_auth_tables(&database).await.unwrap();
                [
                    legacy::jwk::Entity.table_name().to_owned(),
                    legacy::rate_limit::Entity.table_name().to_owned(),
                ]
            }
            _ => {
                let _schema = custom::AppAuthSchema;
                let _plugins = std::marker::PhantomData::<custom::AppPluginSchema>;
                custom::create_auth_tables(&database).await.unwrap();
                [
                    custom::jwk::Entity.table_name().to_owned(),
                    custom::rate_limit::Entity.table_name().to_owned(),
                ]
            }
        };
        let mut models = Vec::new();
        for (model, table_name) in ["jwks", "rateLimit"].into_iter().zip(table_names) {
            let (mut catalog, ddl) = super::sqlite_catalog::observe(
                &database,
                &table_name,
                "the generated model table exists in the SQLite catalog",
            )
            .await
            .unwrap();
            eprintln!("{}", json!({"case": name, "model": model, "ddl": ddl}));
            catalog["model"] = json!(model);
            models.push(catalog);
        }
        cases.push(json!({"name": name, "models": models}));
        database.close().await.unwrap();
    }
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/jwk-rate-limit-catalog-1.7.6.json"
    ))
    .unwrap();
    assert_eq!(
        json!({"version": "1.7.6", "database": "sqlite", "cases": cases}),
        expected
    );
}
