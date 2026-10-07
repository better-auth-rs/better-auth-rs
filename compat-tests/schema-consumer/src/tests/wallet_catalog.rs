use super::{
    server_catalog_indexes,
    server_catalog_support::{self as server_catalog, TestResult},
    wallet_catalog_storage,
};
use better_auth::seaorm::{
    Database, DatabaseConnection,
    sea_orm::{DbBackend, EntityName},
};
use serde_json::{Value, json};
use wallet_catalog_storage::Input;

mod sqlite_default {
    include!(env!("BETTER_AUTH_WALLET_SQLITE_DEFAULT_SCHEMA"));
}
mod sqlite_legacy {
    include!(env!("BETTER_AUTH_WALLET_SQLITE_LEGACY_SCHEMA"));
}
mod sqlite_custom {
    include!(env!("BETTER_AUTH_WALLET_SQLITE_CUSTOM_SCHEMA"));
}
mod postgres_default {
    include!(env!("BETTER_AUTH_WALLET_POSTGRES_DEFAULT_SCHEMA"));
}
mod postgres_custom {
    include!(env!("BETTER_AUTH_WALLET_POSTGRES_CUSTOM_SCHEMA"));
}
mod mysql_default {
    include!(env!("BETTER_AUTH_WALLET_MYSQL_DEFAULT_SCHEMA"));
}
mod mysql_custom {
    include!(env!("BETTER_AUTH_WALLET_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<(Input, Vec<Value>)> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/wallet-address-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let input =
        serde_json::from_value(fixture.get("input").ok_or("Missing Wallet input")?.clone())?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Wallet catalog cases")?;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        if backend == "sqlite" {
            vec![Some("default"), Some("legacy"), Some("custom")]
        } else {
            vec![Some("default"), Some("custom")]
        }
    );
    let configurations: Value =
        serde_json::from_str(include_str!("../../wallet-address-catalog-config.json"))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing Wallet case name")?;
        assert_eq!(case.get("configuration"), configurations.get(name));
    }
    Ok((input, cases.clone()))
}

async fn check(
    database: &DatabaseConnection,
    backend: DbBackend,
    input: &Input,
    case: &Value,
) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing Wallet case name")?;
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            let storage = wallet_catalog_storage::observe::<
                $module::AppAuthSchema,
                $module::AppPluginSchema,
            >(database, backend, input)
            .await?;
            (
                $module::wallet_address::Entity.table_name().to_owned(),
                storage,
            )
        }};
    }
    let (table, actual_storage) = match (backend, name) {
        (DbBackend::Sqlite, "default") => generated!(sqlite_default),
        (DbBackend::Sqlite, "legacy") => generated!(sqlite_legacy),
        (DbBackend::Sqlite, "custom") => generated!(sqlite_custom),
        (DbBackend::Postgres, "default") => generated!(postgres_default),
        (DbBackend::Postgres, "custom") => generated!(postgres_custom),
        (DbBackend::MySql, "default") => generated!(mysql_default),
        (DbBackend::MySql, "custom") => generated!(mysql_custom),
        _ => return Err(format!("Unsupported Wallet catalog {backend:?}/{name}").into()),
    };
    let mut observation = case
        .get("observation")
        .and_then(Value::as_object)
        .ok_or("Missing Wallet observation")?
        .clone();
    let storage = observation
        .remove("storage")
        .ok_or("Missing Wallet storage observation")?;
    let mut expected_storage = storage
        .as_object()
        .ok_or("Expected Wallet storage object")?
        .clone();
    // JavaScript driver tags and SIWE callback counts belong to the Bun contract.
    // Rust compares every row value through native SQL decoding and the full column catalog.
    let _ = expected_storage
        .remove("rawTypes")
        .ok_or("Missing upstream driver type observations")?;
    let _ = expected_storage
        .remove("siweCallbacks")
        .ok_or("Missing upstream SIWE callback observation")?;
    assert_eq!(
        actual_storage,
        Value::Object(expected_storage),
        "{backend:?} Wallet storage {name}"
    );
    if backend == DbBackend::Sqlite {
        assert!(observation.is_empty());
        let (actual, ddl) = super::sqlite_catalog::observe(
            database,
            &table,
            "The generated WalletAddress table exists in the SQLite catalog",
        )
        .await?;
        eprintln!(
            "{}",
            json!({"case": name, "ddl": ddl, "upstreamDdl": case.get("ddl")})
        );
        assert_eq!(
            Some(&actual),
            case.get("catalog"),
            "SQLite Wallet catalog {name}"
        );
    } else {
        let columns = server_catalog::observe(database, backend, [table.clone()]).await?;
        assert_eq!(
            Some(&columns),
            case.get("columns"),
            "{backend:?} Wallet columns {name}"
        );
        let actual = server_catalog_indexes::observe(database, backend, &table).await?;
        assert_eq!(
            actual,
            Value::Object(observation),
            "{backend:?} Wallet indexes and foreign keys {name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn generated_wallet_catalog_and_storage_match_pinned_sqlite() -> TestResult {
    let (input, cases) = cases("sqlite")?;
    for case in cases {
        let database = Database::connect("sqlite::memory:").await?;
        let result = check(&database, DbBackend::Sqlite, &input, &case).await;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_wallet_catalog_and_storage_match_upstream() -> TestResult {
    let (input, cases) = cases("postgres")?;
    for case in cases {
        let input = input.clone();
        server_catalog::in_postgres_catalog(|database| async move {
            check(&database, DbBackend::Postgres, &input, &case).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream catalog fixture"]
async fn live_mysql_wallet_catalog_and_storage_match_upstream() -> TestResult {
    let (input, cases) = cases("mysql")?;
    for case in cases {
        let input = input.clone();
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &input, &case).await
        })
        .await?;
    }
    Ok(())
}
