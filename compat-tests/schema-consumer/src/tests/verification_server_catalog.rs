use super::{
    server_catalog::{mysql, postgres},
    server_catalog_support::{self as server_catalog, TestResult},
};
use better_auth::seaorm::{
    DatabaseConnection,
    sea_orm::{DbBackend, EntityName},
};
use serde_json::{Value, json};

mod postgres_legacy {
    include!(env!(
        "BETTER_AUTH_VERIFICATION_SERVER_POSTGRES_LEGACY_SCHEMA"
    ));
}

mod mysql_legacy {
    include!(env!("BETTER_AUTH_VERIFICATION_SERVER_MYSQL_LEGACY_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/verification-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Verification catalog cases")?;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names, vec![Some("default"), Some("legacy")]);
    let configurations: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/verification-catalog-config.json"
    )))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing Verification catalog case name")?;
        assert_eq!(
            case.get("configuration"),
            configurations.get(name),
            "Generated Verification configuration for {name}"
        );
    }
    Ok(cases.clone())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing Verification catalog case name")?;
    let table = match (backend, name) {
        (DbBackend::Postgres, "default") => {
            postgres::create_auth_tables(database).await?;
            postgres::verification::Entity.table_name().to_owned()
        }
        (DbBackend::Postgres, "legacy") => {
            let _schema = postgres_legacy::AppAuthSchema;
            postgres_legacy::create_auth_tables(database).await?;
            postgres_legacy::verification::Entity
                .table_name()
                .to_owned()
        }
        (DbBackend::MySql, "default") => {
            mysql::create_auth_tables(database).await?;
            mysql::verification::Entity.table_name().to_owned()
        }
        (DbBackend::MySql, "legacy") => {
            let _schema = mysql_legacy::AppAuthSchema;
            mysql_legacy::create_auth_tables(database).await?;
            mysql_legacy::verification::Entity.table_name().to_owned()
        }
        _ => return Err(format!("Unsupported Verification catalog {backend:?}/{name}").into()),
    };
    let actual = server_catalog::observe(database, backend, [table]).await?;
    assert_eq!(
        &actual,
        case.get("columns")
            .ok_or("Missing upstream Verification catalog columns")?,
        "{backend:?} Verification catalog {name}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_verification_catalog_matches_upstream() -> TestResult {
    for case in cases("postgres")? {
        server_catalog::in_postgres_catalog(|database| async move {
            check(&database, DbBackend::Postgres, &case).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream catalog fixture"]
async fn live_mysql_verification_catalog_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
