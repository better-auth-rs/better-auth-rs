use better_auth::seaorm::{Database, sea_orm::EntityName};
use serde_json::{Value, json};

mod default {
    include!(env!("BETTER_AUTH_VERIFICATION_CATALOG_DEFAULT_SCHEMA"));
}

mod legacy {
    include!(env!("BETTER_AUTH_VERIFICATION_CATALOG_LEGACY_SCHEMA"));
}

mod custom {
    include!(env!("BETTER_AUTH_VERIFICATION_CATALOG_CUSTOM_SCHEMA"));
}

#[tokio::test]
async fn generated_verification_catalog_matches_pinned_sqlite() {
    let mut cases = Vec::new();
    for name in ["default", "legacy", "customLong"] {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let table_name = match name {
            "default" => {
                let _schema = default::AppAuthSchema;
                default::create_auth_tables(&database).await.unwrap();
                default::verification::Entity.table_name().to_owned()
            }
            "legacy" => {
                let _schema = legacy::AppAuthSchema;
                legacy::create_auth_tables(&database).await.unwrap();
                legacy::verification::Entity.table_name().to_owned()
            }
            _ => {
                let _schema = custom::AppAuthSchema;
                custom::create_auth_tables(&database).await.unwrap();
                custom::verification::Entity.table_name().to_owned()
            }
        };
        let (mut catalog, ddl) = super::sqlite_catalog::observe(
            &database,
            &table_name,
            "the generated Verification table exists in the SQLite catalog",
        )
        .await
        .unwrap();
        eprintln!("{}", json!({"case": name, "ddl": ddl}));
        catalog["name"] = json!(name);
        cases.push(catalog);
        database.close().await.unwrap();
    }
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/verification-catalog-1.7.6.json"
    ))
    .unwrap();
    assert_eq!(
        json!({"version": "1.7.6", "database": "sqlite", "cases": cases}),
        expected
    );
}
