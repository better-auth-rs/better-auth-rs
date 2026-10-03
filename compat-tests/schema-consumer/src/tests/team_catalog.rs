use better_auth::seaorm::{Database, sea_orm::EntityName};
use serde_json::{Value, json};

mod default {
    include!(env!("BETTER_AUTH_TEAM_CATALOG_DEFAULT_SCHEMA"));
}

mod legacy {
    include!(env!("BETTER_AUTH_TEAM_CATALOG_LEGACY_SCHEMA"));
}

mod custom {
    include!(env!("BETTER_AUTH_TEAM_CATALOG_CUSTOM_SCHEMA"));
}

#[tokio::test]
async fn generated_team_catalog_matches_pinned_sqlite() {
    let mut cases = Vec::new();
    for name in ["default", "legacy", "custom"] {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let table_name = match name {
            "default" => {
                let _schema = default::AppAuthSchema;
                let _organization = std::marker::PhantomData::<default::AppOrganizationSchema>;
                default::create_auth_tables(&database).await.unwrap();
                default::team::Entity.table_name().to_owned()
            }
            "legacy" => {
                let _schema = legacy::AppAuthSchema;
                let _organization = std::marker::PhantomData::<legacy::AppOrganizationSchema>;
                legacy::create_auth_tables(&database).await.unwrap();
                legacy::team::Entity.table_name().to_owned()
            }
            _ => {
                let _schema = custom::AppAuthSchema;
                let _organization = std::marker::PhantomData::<custom::AppOrganizationSchema>;
                custom::create_auth_tables(&database).await.unwrap();
                custom::team::Entity.table_name().to_owned()
            }
        };
        let (mut catalog, ddl) = super::sqlite_catalog::observe(
            &database,
            &table_name,
            "the generated team table exists in the SQLite catalog",
        )
        .await
        .unwrap();
        eprintln!("{}", json!({"case": name, "model": "team", "ddl": ddl}));
        catalog["model"] = json!("team");
        cases.push(json!({"name": name, "models": [catalog]}));
        database.close().await.unwrap();
    }
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/team-catalog-1.7.6.json"
    ))
    .unwrap();
    assert_eq!(
        json!({"version": "1.7.6", "database": "sqlite", "cases": cases}),
        expected
    );
}
