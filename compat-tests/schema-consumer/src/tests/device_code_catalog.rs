use super::{
    server_catalog_indexes,
    server_catalog_support::{self as server_catalog, TestResult},
};
use better_auth::{
    AuthConfig, AuthSchema, FieldDate,
    config::IdGeneration,
    prelude::{CreateDeviceCode, CreateUser, UpdateDeviceCode},
    seaorm::{
        Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel, SeaOrmPluginSchema,
        SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{
            ConnectionTrait, DbBackend, EntityName, EntityTrait, Statement,
            entity::prelude::DateTimeUtc,
        },
    },
    store::AuthStore,
};
use serde_json::{Value, json};

mod sqlite_default {
    include!(env!("BETTER_AUTH_DEVICE_CODE_SQLITE_DEFAULT_SCHEMA"));
}
mod sqlite_legacy {
    include!(env!("BETTER_AUTH_DEVICE_CODE_SQLITE_LEGACY_SCHEMA"));
}
mod sqlite_custom {
    include!(env!("BETTER_AUTH_DEVICE_CODE_SQLITE_CUSTOM_SCHEMA"));
}
mod sqlite_serial {
    include!(env!("BETTER_AUTH_DEVICE_CODE_SQLITE_SERIAL_SCHEMA"));
}
mod postgres_default {
    include!(env!("BETTER_AUTH_DEVICE_CODE_POSTGRES_DEFAULT_SCHEMA"));
}
mod postgres_custom {
    include!(env!("BETTER_AUTH_DEVICE_CODE_POSTGRES_CUSTOM_SCHEMA"));
}
mod mysql_default {
    include!(env!("BETTER_AUTH_DEVICE_CODE_MYSQL_DEFAULT_SCHEMA"));
}
mod mysql_custom {
    include!(env!("BETTER_AUTH_DEVICE_CODE_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/device-code-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing DeviceCode catalog cases")?;
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
        serde_json::from_str(include_str!("../../device-code-catalog-config.json"))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing DeviceCode catalog case name")?;
        assert_eq!(case.get("configuration"), configurations.get(name));
    }
    Ok(cases.clone())
}

async fn check_storage<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    generation: IdGeneration,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(generation);
    let store = SeaOrmStore::<S>::new(config, database.clone()).with_plugin_schema::<P>();
    let store: &dyn AuthStore<S> = &store;
    assert!(!P::DeviceCode::is_id_reference(&P::DeviceCode::column(
        "user_id"
    )?));
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Device catalog owner")
                .with_email("device-catalog@example.test"),
        )
        .await?;
    let owner_id = owner.id.typed()?.clone();
    let expires_at: FieldDate = "2030-01-02T03:04:05.123Z".parse::<DateTimeUtc>()?.into();
    let created = store
        .create_device_code(CreateDeviceCode {
            device_code: "ordinary-catalog-device".into(),
            user_code: "CATALOG".into(),
            user_id: None,
            expires_at: expires_at.clone(),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5.0),
            client_id: Some("ordinary-catalog-client".into()),
            scope: Some("profile".to_owned()).into(),
            additional_fields: Default::default(),
        })
        .await?;
    assert_eq!(created.user_id, None);
    assert_eq!(created.device_code, "ordinary-catalog-device");
    assert_eq!(created.user_code, "CATALOG");
    assert_eq!(created.expires_at, expires_at);
    assert_eq!(created.status, "pending");
    assert_eq!(created.last_polled_at, None);
    assert_eq!(created.polling_interval, Some(5.0));
    assert_eq!(
        created.client_id.typed()?.as_deref(),
        Some("ordinary-catalog-client")
    );
    assert_eq!(created.scope.typed()?.as_deref(), Some("profile"));
    assert!(created.additional_fields.is_empty());
    assert_eq!(
        store
            .get_device_code_by_device_code(&created.device_code)
            .await?,
        Some(created.clone())
    );
    let initial_rows = <P::DeviceCode as SeaOrmPluginModel>::Entity::find()
        .all(database)
        .await?;
    assert_eq!(initial_rows.len(), 1);
    assert_eq!(initial_rows[0].record()?, created);
    let updated = store
        .update_device_code(
            &created.id,
            UpdateDeviceCode {
                user_id: Some(Some(owner_id.clone())),
                ..Default::default()
            },
        )
        .await?;
    let mut expected = created;
    expected.user_id = Some(owner_id);
    assert_eq!(updated, expected);
    assert_eq!(
        store
            .get_device_code_by_user_code(&expected.user_code)
            .await?,
        Some(expected.clone())
    );
    let stored_rows = <P::DeviceCode as SeaOrmPluginModel>::Entity::find()
        .all(database)
        .await?;
    assert_eq!(stored_rows.len(), 1);
    assert_eq!(stored_rows[0].record()?, expected);
    Ok(())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing DeviceCode catalog case name")?;
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            check_storage::<$module::AppAuthSchema, $module::AppPluginSchema>(
                database,
                IdGeneration::Random,
            )
            .await?;
            $module::device_code::Entity.table_name().to_owned()
        }};
    }
    let table = match (backend, name) {
        (DbBackend::Sqlite, "default") => generated!(sqlite_default),
        (DbBackend::Sqlite, "legacy") => generated!(sqlite_legacy),
        (DbBackend::Sqlite, "custom") => generated!(sqlite_custom),
        (DbBackend::Postgres, "default") => generated!(postgres_default),
        (DbBackend::Postgres, "custom") => generated!(postgres_custom),
        (DbBackend::MySql, "default") => generated!(mysql_default),
        (DbBackend::MySql, "custom") => generated!(mysql_custom),
        _ => return Err(format!("Unsupported DeviceCode catalog {backend:?}/{name}").into()),
    };
    if backend == DbBackend::Sqlite {
        let (actual, ddl) = super::sqlite_catalog::observe(
            database,
            &table,
            "the generated DeviceCode table exists in the SQLite catalog",
        )
        .await?;
        eprintln!(
            "{}",
            json!({"case": name, "ddl": ddl, "upstreamDdl": case.get("ddl")})
        );
        assert_eq!(
            Some(&actual),
            case.get("catalog"),
            "SQLite DeviceCode {name}"
        );
    } else {
        let columns = server_catalog::observe(database, backend, [table.clone()]).await?;
        assert_eq!(
            Some(&columns),
            case.get("columns"),
            "{backend:?} DeviceCode columns {name}"
        );
        let observation = server_catalog_indexes::observe(database, backend, &table).await?;
        assert_eq!(
            Some(&observation),
            case.get("observation"),
            "{backend:?} DeviceCode indexes and foreign keys {name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn generated_device_code_catalog_matches_pinned_sqlite() -> TestResult {
    for case in cases("sqlite")? {
        let database = Database::connect("sqlite::memory:").await?;
        let result = check(&database, DbBackend::Sqlite, &case).await;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn generated_serial_device_code_keeps_user_id_as_nullable_text() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    let result = async {
        sqlite_serial::create_auth_tables(&database).await?;
        check_storage::<sqlite_serial::AppAuthSchema, sqlite_serial::AppPluginSchema>(
            &database,
            IdGeneration::Serial,
        )
        .await?;
        let persisted = sqlite_serial::device_code::Entity::find()
            .one(&database)
            .await?
            .ok_or("Missing ordinary DeviceCode row")?;
        let user_id: &Option<String> = &persisted.user_id;
        assert_eq!(user_id.as_deref(), Some("1"));
        let raw = database.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT typeof(id) AS id_type, typeof(userId) AS user_type, userId AS owner FROM deviceCode",
        )).await?.ok_or("Missing ordinary DeviceCode SQL row")?;
        assert_eq!(raw.try_get::<String>("", "id_type")?, "integer");
        assert_eq!(raw.try_get::<String>("", "user_type")?, "text");
        assert_eq!(raw.try_get::<String>("", "owner")?, "1");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }.await;
    database.close().await?;
    result
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_device_code_catalog_matches_upstream() -> TestResult {
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
async fn live_mysql_device_code_catalog_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
