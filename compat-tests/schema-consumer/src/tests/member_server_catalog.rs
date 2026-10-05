use super::{
    organization_server_schema::{mysql as mysql_default, postgres as postgres_default},
    server_catalog::{self, TestResult},
};
use better_auth::seaorm::{
    DatabaseConnection,
    sea_orm::{DbBackend, EntityName},
};
use serde_json::{Value, json};

mod postgres_custom {
    include!(env!("BETTER_AUTH_MEMBER_SERVER_POSTGRES_CUSTOM_SCHEMA"));
}

mod mysql_custom {
    include!(env!("BETTER_AUTH_MEMBER_SERVER_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/member-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Member catalog cases")?;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names, vec![Some("default"), Some("custom")]);
    let configurations: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/member-organization-role-catalog-config.json"
    )))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing Member catalog case name")?;
        let configuration = configurations
            .get(name)
            .ok_or("Missing Member catalog configuration")?;
        let configuration = Value::Object(
            ["user", "organization", "member"]
                .into_iter()
                .filter_map(|key| {
                    configuration
                        .get(key)
                        .map(|value| (key.to_owned(), value.clone()))
                })
                .collect(),
        );
        assert_eq!(
            case.get("configuration"),
            Some(&configuration),
            "Generated Member configuration for {name}"
        );
    }
    Ok(cases.clone())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing Member catalog case name")?;
    let table = match (backend, name) {
        (DbBackend::Postgres, "default") => {
            let _schema = postgres_default::AppAuthSchema;
            let _organization = std::marker::PhantomData::<postgres_default::AppOrganizationSchema>;
            postgres_default::create_auth_tables(database).await?;
            postgres_default::member::Entity.table_name().to_owned()
        }
        (DbBackend::Postgres, "custom") => {
            let _schema = postgres_custom::AppAuthSchema;
            let _organization = std::marker::PhantomData::<postgres_custom::AppOrganizationSchema>;
            postgres_custom::create_auth_tables(database).await?;
            postgres_custom::member::Entity.table_name().to_owned()
        }
        (DbBackend::MySql, "default") => {
            let _schema = mysql_default::AppAuthSchema;
            let _organization = std::marker::PhantomData::<mysql_default::AppOrganizationSchema>;
            mysql_default::create_auth_tables(database).await?;
            mysql_default::member::Entity.table_name().to_owned()
        }
        (DbBackend::MySql, "custom") => {
            let _schema = mysql_custom::AppAuthSchema;
            let _organization = std::marker::PhantomData::<mysql_custom::AppOrganizationSchema>;
            mysql_custom::create_auth_tables(database).await?;
            mysql_custom::member::Entity.table_name().to_owned()
        }
        _ => return Err(format!("Unsupported Member catalog {backend:?}/{name}").into()),
    };
    let actual = server_catalog::observe(database, backend, [table]).await?;
    assert_eq!(
        &actual,
        case.get("columns")
            .ok_or("Missing upstream Member catalog columns")?,
        "{backend:?} Member catalog {name}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_member_catalog_matches_upstream() -> TestResult {
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
async fn live_mysql_member_catalog_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
