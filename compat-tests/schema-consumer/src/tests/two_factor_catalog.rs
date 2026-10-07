use super::{
    server_catalog_indexes,
    server_catalog_support::{self as server_catalog, TestResult},
    two_factor_catalog_storage,
};
use better_auth::seaorm::{
    Database, DatabaseConnection,
    sea_orm::{DbBackend, EntityName},
};
use serde_json::{Map, Value, json};

mod sqlite_default {
    include!(env!("BETTER_AUTH_TWO_FACTOR_SQLITE_DEFAULT_SCHEMA"));
}
mod sqlite_legacy {
    include!(env!("BETTER_AUTH_TWO_FACTOR_SQLITE_LEGACY_SCHEMA"));
}
mod sqlite_custom {
    include!(env!("BETTER_AUTH_TWO_FACTOR_SQLITE_CUSTOM_SCHEMA"));
}
mod postgres_default {
    include!(env!("BETTER_AUTH_TWO_FACTOR_POSTGRES_DEFAULT_SCHEMA"));
}
mod postgres_custom {
    include!(env!("BETTER_AUTH_TWO_FACTOR_POSTGRES_CUSTOM_SCHEMA"));
}
mod mysql_default {
    include!(env!("BETTER_AUTH_TWO_FACTOR_MYSQL_DEFAULT_SCHEMA"));
}
mod mysql_custom {
    include!(env!("BETTER_AUTH_TWO_FACTOR_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/two-factor-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing TwoFactor catalog cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        if backend == "sqlite" {
            vec![Some("default"), Some("legacy"), Some("custom")]
        } else {
            vec![Some("default"), Some("custom")]
        }
    );
    let configurations: Value =
        serde_json::from_str(include_str!("../../two-factor-catalog-config.json"))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing TwoFactor case name")?;
        assert_eq!(case.get("configuration"), configurations.get(name));
    }
    Ok(cases.clone())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing TwoFactor case name")?;
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            let storage = two_factor_catalog_storage::check::<
                $module::AppAuthSchema,
                $module::AppPluginSchema,
            >(database)
            .await?;
            (
                [
                    $module::user::Entity.table_name().to_owned(),
                    $module::two_factor::Entity.table_name().to_owned(),
                ],
                storage,
            )
        }};
    }
    let (tables, storage) = match (backend, name) {
        (DbBackend::Sqlite, "default") => generated!(sqlite_default),
        (DbBackend::Sqlite, "legacy") => generated!(sqlite_legacy),
        (DbBackend::Sqlite, "custom") => generated!(sqlite_custom),
        (DbBackend::Postgres, "default") => generated!(postgres_default),
        (DbBackend::Postgres, "custom") => generated!(postgres_custom),
        (DbBackend::MySql, "default") => generated!(mysql_default),
        (DbBackend::MySql, "custom") => generated!(mysql_custom),
        _ => return Err(format!("Unsupported TwoFactor catalog {backend:?}/{name}").into()),
    };
    let mut catalogs = Map::new();
    for (model, table) in ["user", "twoFactor"].into_iter().zip(&tables) {
        let observed = if backend == DbBackend::Sqlite {
            let (catalog, ddl) = super::sqlite_catalog::observe(
                database,
                table,
                "The generated TwoFactor or User table exists in the SQLite catalog",
            )
            .await?;
            eprintln!(
                "{}",
                json!({"case": name, "model": model, "ddl": ddl,
                    "upstreamDdl": case.get("ddl").and_then(|ddl| ddl.get(model))})
            );
            catalog
        } else {
            server_catalog_indexes::observe(database, backend, table).await?
        };
        catalogs.insert(model.to_owned(), observed);
    }
    if backend == DbBackend::Sqlite {
        assert_eq!(
            Some(&Value::Object(catalogs)),
            case.get("catalog"),
            "SQLite TwoFactor and User catalogs {name}"
        );
        assert_eq!(
            Some(&json!({"storage": storage})),
            case.get("observation"),
            "SQLite TwoFactor complete storage records {name}"
        );
    } else {
        let columns = server_catalog::observe(database, backend, tables).await?;
        catalogs.insert("storage".to_owned(), storage);
        assert_eq!(
            Some(&columns),
            case.get("columns"),
            "{backend:?} TwoFactor and User columns {name}"
        );
        assert_eq!(
            Some(&Value::Object(catalogs)),
            case.get("observation"),
            "{backend:?} TwoFactor and User indexes and foreign keys {name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn generated_two_factor_catalog_matches_pinned_sqlite_and_stores_native_records() -> TestResult
{
    for case in cases("sqlite")? {
        let database = Database::connect("sqlite::memory:").await?;
        let result = check(&database, DbBackend::Sqlite, &case).await;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_two_factor_catalog_and_native_storage() -> TestResult {
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
async fn live_mysql_two_factor_catalog_and_native_storage() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
