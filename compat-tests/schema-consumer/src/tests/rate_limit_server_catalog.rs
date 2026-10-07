use super::server_catalog_support::{self as server_catalog, TestResult};
use better_auth::seaorm::{
    __private_chrono as chrono, DatabaseConnection, SeaOrmPluginModel, SeaOrmPluginSchema,
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, EntityName, EntityTrait, Iden, Statement},
};
use better_auth::{AuthConfig, AuthSchema, middleware::EndpointRateLimit, store::RateLimitStore};
use serde::Deserialize;
use serde_json::{Value, json};

mod postgres_default {
    include!(env!(
        "BETTER_AUTH_RATE_LIMIT_SERVER_POSTGRES_DEFAULT_SCHEMA"
    ));
}

mod postgres_custom {
    include!(env!("BETTER_AUTH_RATE_LIMIT_SERVER_POSTGRES_CUSTOM_SCHEMA"));
}

mod mysql_default {
    include!(env!("BETTER_AUTH_RATE_LIMIT_SERVER_MYSQL_DEFAULT_SCHEMA"));
}

mod mysql_custom {
    include!(env!("BETTER_AUTH_RATE_LIMIT_SERVER_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/rate-limit-{backend}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing RateLimit catalog cases")?;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names, vec![Some("default"), Some("custom")]);
    let configurations: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/jwk-rate-limit-catalog-config.json"
    )))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing RateLimit catalog case name")?;
        let configuration = configurations
            .get(name)
            .ok_or("Missing RateLimit catalog configuration")?;
        let configuration = match configuration.get("rateLimit") {
            Some(rate_limit) => json!({ "rateLimit": rate_limit }),
            None => json!({}),
        };
        assert_eq!(
            case.get("configuration"),
            Some(&configuration),
            "Generated RateLimit configuration for {name}"
        );
    }
    Ok(cases.clone())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing RateLimit catalog case name")?;
    let table = match (backend, name) {
        (DbBackend::Postgres, "default") => {
            let _schema = postgres_default::AppAuthSchema;
            let _plugins = std::marker::PhantomData::<postgres_default::AppPluginSchema>;
            postgres_default::create_auth_tables(database).await?;
            postgres_default::rate_limit::Entity.table_name().to_owned()
        }
        (DbBackend::Postgres, "custom") => {
            let _schema = postgres_custom::AppAuthSchema;
            let _plugins = std::marker::PhantomData::<postgres_custom::AppPluginSchema>;
            postgres_custom::create_auth_tables(database).await?;
            postgres_custom::rate_limit::Entity.table_name().to_owned()
        }
        (DbBackend::MySql, "default") => {
            let _schema = mysql_default::AppAuthSchema;
            let _plugins = std::marker::PhantomData::<mysql_default::AppPluginSchema>;
            mysql_default::create_auth_tables(database).await?;
            mysql_default::rate_limit::Entity.table_name().to_owned()
        }
        (DbBackend::MySql, "custom") => {
            let _schema = mysql_custom::AppAuthSchema;
            let _plugins = std::marker::PhantomData::<mysql_custom::AppPluginSchema>;
            mysql_custom::create_auth_tables(database).await?;
            mysql_custom::rate_limit::Entity.table_name().to_owned()
        }
        _ => return Err(format!("Unsupported RateLimit catalog {backend:?}/{name}").into()),
    };
    let actual = server_catalog::observe(database, backend, [table]).await?;
    assert_eq!(
        &actual,
        case.get("columns")
            .ok_or("Missing upstream RateLimit catalog columns")?,
        "{backend:?} RateLimit catalog {name}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_rate_limit_catalog_matches_upstream() -> TestResult {
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
async fn live_mysql_rate_limit_catalog_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFixture {
    version: String,
    database: String,
    cases: Vec<RuntimeCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCase {
    name: String,
    configuration: Value,
    rule: CounterRule,
    key: String,
    steps: Vec<CounterStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterRule {
    window: f64,
    max: f64,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CounterStep {
    allowed: bool,
    retry_after: Option<f64>,
    row: CounterRow,
    raw_count: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CounterRow {
    id: String,
    key: String,
    count: f64,
    last_request: String,
}

fn runtime_cases(backend: &str) -> TestResult<Vec<RuntimeCase>> {
    let fixture: RuntimeFixture = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/rate-limit-{backend}-runtime-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.database, backend);
    let catalogs = cases(backend)?;
    assert_eq!(fixture.cases.len(), catalogs.len());
    for (case, catalog) in fixture.cases.iter().zip(catalogs) {
        assert_eq!(
            Some(case.name.as_str()),
            catalog.get("name").and_then(Value::as_str)
        );
        assert_eq!(Some(&case.configuration), catalog.get("configuration"));
        assert_eq!(case.rule.window, 600.0);
        assert_eq!(case.rule.max, 100.0);
        assert_eq!(case.steps.len(), 2);
        assert!(!case.key.is_empty());
    }
    Ok(fixture.cases)
}

fn quote(backend: DbBackend, name: &str) -> String {
    match backend {
        DbBackend::Postgres => format!("\"{}\"", name.replace('"', "\"\"")),
        _ => format!("`{}`", name.replace('`', "``")),
    }
}

async fn observe_counter<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    case: &RuntimeCase,
) -> TestResult<Vec<CounterStep>> {
    let store =
        SeaOrmStore::<S>::new(AuthConfig::default(), database.clone()).with_plugin_schema::<P>();
    let rule = EndpointRateLimit {
        window: case.rule.window,
        max_requests: case.rule.max,
    };
    let backend = database.get_database_backend();
    let table = quote(
        backend,
        <P::RateLimit as SeaOrmPluginModel>::Entity::default().table_name(),
    );
    let count = quote(backend, &P::RateLimit::column("count")?.to_string());
    let last_request = quote(backend, &P::RateLimit::column("last_request")?.to_string());
    let parameter = if backend == DbBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    let mut first_id = None;
    let mut steps = Vec::new();
    for expected in [1, 2] {
        let started = chrono::Utc::now().timestamp_millis();
        let decision = store
            .consume_rate_limit(&case.key, rule, case.rule.window)
            .await?;
        let finished = chrono::Utc::now().timestamp_millis();
        assert!(decision.allowed);
        assert_eq!(decision.retry_after, None);
        let rows = <P::RateLimit as SeaOrmPluginModel>::Entity::find()
            .all(database)
            .await?;
        assert_eq!(rows.len(), 1);
        let row = rows[0].record()?;
        let id = row.id.typed()?;
        assert!(!id.is_empty());
        assert_eq!(first_id.get_or_insert_with(|| id.clone()), id);
        assert_eq!(row.key, case.key);
        assert_eq!(row.count, f64::from(expected));
        assert!(started <= row.last_request && row.last_request <= finished);
        let raw = database.query_all_raw(Statement::from_sql_and_values(backend,
            format!("SELECT {count} AS count, {last_request} AS last_request FROM {table} WHERE id = {parameter}"),
            [id.clone().into()],
        )).await?;
        assert_eq!(raw.len(), 1);
        let raw_count: i32 = raw[0].try_get("", "count")?;
        assert_eq!(raw_count, expected);
        assert_eq!(raw[0].try_get::<i64>("", "last_request")?, row.last_request);
        steps.push(CounterStep {
            allowed: decision.allowed,
            retry_after: decision.retry_after,
            row: CounterRow {
                id: "<counter-id>".into(),
                key: row.key,
                count: row.count,
                last_request: "<last-request>".into(),
            },
            raw_count,
        });
    }
    Ok(steps)
}

async fn check_counter(
    database: &DatabaseConnection,
    backend: DbBackend,
    case: &RuntimeCase,
) -> TestResult {
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            observe_counter::<$module::AppAuthSchema, $module::AppPluginSchema>(database, case)
                .await?
        }};
    }
    let actual = match (backend, case.name.as_str()) {
        (DbBackend::Postgres, "default") => generated!(postgres_default),
        (DbBackend::Postgres, "custom") => generated!(postgres_custom),
        (DbBackend::MySql, "default") => generated!(mysql_default),
        (DbBackend::MySql, "custom") => generated!(mysql_custom),
        _ => return Err(format!("Unsupported RateLimit runtime {backend:?}/{}", case.name).into()),
    };
    assert_eq!(
        actual, case.steps,
        "{backend:?}/{} ordinary counter lifecycle",
        case.name
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream runtime fixture"]
async fn live_postgres_rate_limit_counter_matches_upstream() -> TestResult {
    for case in runtime_cases("postgres")? {
        server_catalog::in_postgres_catalog(|database| async move {
            check_counter(&database, DbBackend::Postgres, &case).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream runtime fixture"]
async fn live_mysql_rate_limit_counter_matches_upstream() -> TestResult {
    for case in runtime_cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check_counter(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
