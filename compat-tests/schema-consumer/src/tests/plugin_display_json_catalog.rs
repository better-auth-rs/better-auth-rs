use super::*;
use better_auth::{
    __private_core::store::ApiKeyStore,
    AuthConfig, AuthRecordFields,
    config::{IdGeneration, IdGenerator},
    prelude::{ApiKey, CreateApiKey, UpdateApiKey},
};

mod sqlite {
    include!(env!("BETTER_AUTH_NATIVE_API_KEY_SQLITE_SCHEMA"));
}
mod postgres {
    include!(env!("BETTER_AUTH_NATIVE_API_KEY_POSTGRES_SCHEMA"));
}
mod mysql {
    include!(env!("BETTER_AUTH_NATIVE_API_KEY_MYSQL_SCHEMA"));
}

pub(super) async fn compare(
    database: &DatabaseConnection,
    table: &str,
    expected: &Value,
) -> TestResult {
    let (columns, constraints) = if database.get_database_backend() == DbBackend::Sqlite {
        let (catalog, _) =
            super::super::sqlite_catalog::observe(database, table, "The API Key table must exist")
                .await?;
        (
            catalog["columns"].clone(),
            json!({"indexes": catalog["indexes"], "foreignKeys": catalog["foreignKeys"]}),
        )
    } else {
        (
            server_catalog::observe(
                database,
                database.get_database_backend(),
                [table.to_owned()],
            )
            .await?,
            super::super::server_catalog_indexes::observe(
                database,
                database.get_database_backend(),
                table,
            )
            .await?,
        )
    };
    assert_eq!(
        columns, expected["columns"],
        "{table} complete column catalog"
    );
    assert_eq!(
        constraints, expected["constraints"],
        "{table} complete indexes and foreign keys"
    );
    Ok(())
}

fn input() -> CreateApiKey {
    CreateApiKey {
        additional_fields: Default::default(),
        reference_id: "owner-without-user-row".into(),
        config_id: "default".into(),
        name: None.into(),
        start: None,
        prefix: None,
        key_hash: "shared-native-key".into(),
        refill_interval: None,
        refill_amount: None,
        enabled: true.into(),
        rate_limit_enabled: true,
        rate_limit_time_window: None,
        rate_limit_max: None,
        remaining: None,
        expires_at: None,
        permissions: None,
        metadata: None,
    }
}

fn observed(row: &ApiKey) -> TestResult<Value> {
    let mut fields = row.field_values()?;
    // Store timestamps use the runtime clock; the display contract checks fixed timestamp values.
    fields.retain(|name, _| {
        !matches!(
            name.as_str(),
            "createdAt" | "updatedAt" | "lastRefillAt" | "lastRequest" | "expiresAt"
        )
    });
    Ok(Value::Object(fields.json()?))
}

fn store<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    id: &str,
) -> SeaOrmStore<S, better_auth::seaorm::OrganizationModels, P> {
    let id = id.to_owned();
    let mut config = AuthConfig::new("native-apikey-catalog-at-least-32-characters");
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(id.clone()))
        })));
    SeaOrmStore::<S>::new(config, database.clone()).with_plugin_schema::<P>()
}

async fn storage<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    expected: &Value,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let first = store::<S, P>(database, "native-null-flags");
    let key = first.create_api_key(input()).await?;
    let backend = database.get_database_backend();
    let assignments = [
        "enabled",
        "rateLimitEnabled",
        "refillInterval",
        "refillAmount",
        "rateLimitTimeWindow",
        "rateLimitMax",
        "requestCount",
        "remaining",
    ]
    .map(|field| format!("{} = NULL", quote(backend, field)))
    .join(", ");
    let parameter = if backend == DbBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    database
        .execute_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "UPDATE {} SET {assignments} WHERE {} = {parameter}",
                quote(backend, "apikey"),
                quote(backend, "id")
            ),
            [key.id.typed()?.clone().into()],
        ))
        .await?;
    let row = first
        .get_api_key_by_id("native-null-flags")
        .await?
        .ok_or("Missing nullable API Key")?;
    assert_eq!(observed(&row)?, expected["nullFlags"]);
    assert_eq!(row.enabled.field_value(), FieldValue::Null);
    assert_eq!(row.rate_limit_enabled.field_value(), FieldValue::Null);

    let long = store::<S, P>(database, "native-long-text");
    let text = |field| format!("{field}:{}", "x".repeat(300));
    long.create_api_key(CreateApiKey {
        name: Some(text("name")).into(),
        start: Some(text("start").into()),
        prefix: Some(text("prefix")),
        permissions: Some(text("permissions")),
        metadata: Some(text("metadata")),
        ..input()
    })
    .await?;
    let row = long
        .get_api_key_by_id("native-long-text")
        .await?
        .ok_or("Missing long-text API Key")?;
    assert_eq!(observed(&row)?, expected["longText"]);
    assert_eq!(
        first
            .count_api_keys_by_reference("owner-without-user-row")
            .await?,
        2
    );

    let cases = expected["numeric"]
        .as_array()
        .ok_or("Missing numeric storage observations")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case["name"].as_str())
            .collect::<Vec<_>>(),
        vec![
            Some("integer"),
            Some("fraction"),
            Some("negative-fraction"),
            Some("outside-int32")
        ]
    );
    for case in cases {
        let name = case["name"].as_str().ok_or("Missing numeric case name")?;
        let id = format!("native-number-{name}");
        let numeric = store::<S, P>(database, &id);
        let key = numeric.create_api_key(input()).await?;
        let value = case["input"].as_f64().ok_or("Missing numeric input")?;
        let result = numeric
            .update_api_key(
                &key.id,
                UpdateApiKey {
                    refill_interval: Some(value),
                    refill_amount: Some(value),
                    rate_limit_time_window: Some(value),
                    rate_limit_max: Some(value),
                    request_count: Some(value),
                    remaining: Some(value),
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(
            result.is_ok(),
            case["accepted"]
                .as_bool()
                .ok_or("Missing numeric acceptance")?,
            "{name}: Rust result {result:?}; upstream error {}",
            case["error"]
        );
        let row = numeric
            .get_api_key_by_id(&id)
            .await?
            .ok_or("Numeric update lost its row")?;
        assert_eq!(observed(&row)?, case["row"], "{name} stored numeric values");
    }
    Ok(())
}

pub(super) async fn check_native(database: DatabaseConnection, backend: &str) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/fixtures/plugin-display-json-{backend}-1.7.6.json"
    ));
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let expected = fixture
        .get("apiKeyCatalog")
        .ok_or("Missing native API Key catalog")?;
    macro_rules! check {
        ($schema:ident) => {{
            $schema::create_auth_tables(&database).await?;
            compare(&database, "apikey", expected).await?;
            storage::<$schema::AppAuthSchema, $schema::AppPluginSchema>(
                &database,
                &expected["storage"],
            )
            .await
        }};
    }
    match backend {
        "sqlite" => check!(sqlite),
        "postgres" => check!(postgres),
        "mysql" => check!(mysql),
        _ => Err("Unknown native API Key backend".into()),
    }
}
