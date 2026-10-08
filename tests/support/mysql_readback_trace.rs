use better_auth_seaorm::sea_orm::{DatabaseConnection, Statement, sea_query::Value as SqlValue};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::{Subscriber, span::Id};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

#[derive(Clone, Debug)]
pub(super) enum Event {
    Callback(Value),
    Sql { statement: Statement, failed: bool },
    Transaction(&'static str),
}

#[derive(Clone, Default)]
pub(super) struct Trace(Arc<Mutex<Vec<Event>>>);

impl Trace {
    pub(super) fn callback(&self, value: Value) {
        self.0
            .lock()
            .expect("MySQL callback trace")
            .push(Event::Callback(value));
    }

    pub(super) fn take(&self) -> Vec<Event> {
        std::mem::take(&mut *self.0.lock().expect("MySQL readback trace"))
    }

    pub(super) fn capture(&self, database: &mut DatabaseConnection) {
        let trace = self.clone();
        database.set_metric_callback(move |info| {
            trace.0.lock().expect("MySQL SQL trace").push(Event::Sql {
                statement: info.statement.clone(),
                failed: info.failed,
            });
        });
    }
}

impl<S> Layer<S> for Trace
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_close(&self, id: Id, context: Context<'_, S>) {
        let span = context
            .span(&id)
            .expect("completed SeaORM transaction span");
        let metadata = span.metadata();
        if metadata.target() == "sea_orm::database::transaction"
            && matches!(metadata.name(), "begin" | "commit" | "rollback")
        {
            // Metric callbacks omit transaction control. Closed spans observe completed control operations.
            self.0
                .lock()
                .expect("MySQL transaction trace")
                .push(Event::Transaction(metadata.name()));
        }
    }
}

pub(super) const JWK_COLUMNS: [&str; 7] = [
    "id",
    "stored_public_key",
    "stored_private_key",
    "stored_created_at",
    "stored_expires_at",
    "stored_algorithm",
    "stored_curve",
];

const CATALOG_SQL: &str = "select `columns`.`COLUMN_NAME`, `columns`.`COLUMN_DEFAULT`, `columns`.`TABLE_NAME`, `columns`.`TABLE_SCHEMA`, `tables`.`TABLE_TYPE`, `tables`.`ENGINE`, `columns`.`IS_NULLABLE`, `columns`.`DATA_TYPE`, `columns`.`EXTRA`, `columns`.`COLUMN_COMMENT` from `information_schema`.`columns` as `columns` inner join `information_schema`.`tables` as `tables` on `columns`.`TABLE_CATALOG` = `tables`.`TABLE_CATALOG` and `columns`.`TABLE_SCHEMA` = `tables`.`TABLE_SCHEMA` and `columns`.`TABLE_NAME` = `tables`.`TABLE_NAME` where `columns`.`TABLE_SCHEMA` = database() and `columns`.`TABLE_NAME` != ? and `columns`.`TABLE_NAME` != ? order by `columns`.`TABLE_NAME`, `columns`.`ORDINAL_POSITION`";

fn parameters(statement: &Statement) -> Value {
    json!(
        statement
            .values
            .as_ref()
            .map(|values| values
                .0
                .iter()
                .map(|value| {
                    match value {
                        value if value == &value.as_null() => Value::Null,
                        SqlValue::String(Some(value)) => json!(value),
                        SqlValue::BigUnsigned(Some(value)) => json!(value),
                        SqlValue::Unsigned(Some(value)) => json!(value),
                        SqlValue::BigInt(Some(value)) => json!(value),
                        SqlValue::Int(Some(value)) => json!(value),
                        SqlValue::Bool(Some(value)) => json!(value),
                        value => panic!("Unspecified SQL parameter representation: {value:?}"),
                    }
                })
                .collect::<Vec<_>>())
            .unwrap_or_default()
    )
}

fn driver_parameters(expected: &Value) -> Vec<Value> {
    expected
        .as_array()
        .expect("captured SQL parameters")
        .iter()
        .map(|value| {
            if value.get("type").and_then(Value::as_str) == Some("date") {
                let instant = value["value"].as_str().expect("captured valid Date");
                let date = instant
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .expect("captured valid timestamp");
                json!(date.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
            } else {
                value.clone()
            }
        })
        .collect()
}

fn projection(table: &str, columns: &[&str]) -> String {
    columns
        .iter()
        .map(|column| format!("`{table}`.`{column}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn jwk_sql(expected: &Value) -> (String, Value) {
    let mut parameters = driver_parameters(&expected["parameters"]);
    let sql = match expected["sql"].as_str().expect("captured SQL") {
        "SELECT LAST_INSERT_ID() as id" => "SELECT LAST_INSERT_ID() as id".to_owned(),
        "insert into `readback_jwks` (`stored_public_key`, `stored_private_key`, `stored_created_at`, `stored_expires_at`, `stored_algorithm`) values (?, ?, ?, ?, ?)" => "INSERT INTO `readback_jwks` (`stored_public_key`, `stored_private_key`, `stored_created_at`, `stored_expires_at`, `stored_algorithm`) VALUES (?, ?, ?, ?, ?)".to_owned(),
        "insert into `readback_jwks` (`stored_public_key`, `stored_private_key`, `stored_created_at`, `stored_expires_at`, `stored_algorithm`, `id`) values (?, ?, ?, ?, ?, ?)" => "INSERT INTO `readback_jwks` (`stored_public_key`, `stored_private_key`, `stored_created_at`, `stored_expires_at`, `stored_algorithm`, `id`) VALUES (?, ?, ?, ?, ?, ?)".to_owned(),
        "select * from `readback_jwks` where `id` = ? limit ?" => {
            let predicate = if parameters[0].is_number() {
                assert_eq!(parameters.remove(0), json!(1), "captured serial ID");
                "`readback_jwks`.`id` = 1"
            } else { "`readback_jwks`.`id` = ?" };
            format!("SELECT {} FROM `readback_jwks` WHERE {predicate} LIMIT ?", projection("readback_jwks", &JWK_COLUMNS))
        },
        "select * from `readback_jwks` where `stored_public_key` = ? limit ?" => format!("SELECT {} FROM `readback_jwks` WHERE `readback_jwks`.`stored_public_key` = ? LIMIT ?", projection("readback_jwks", &JWK_COLUMNS)),
        "select * from `readback_jwks` where `stored_private_key` = ? limit ?" => format!("SELECT {} FROM `readback_jwks` WHERE `readback_jwks`.`stored_private_key` = ? LIMIT ?", projection("readback_jwks", &JWK_COLUMNS)),
        "select * from `readback_jwks` where `stored_public_key` = ? and `stored_private_key` = ? and `stored_created_at` = ? and `stored_expires_at` is null and `stored_algorithm` = ? limit ?" => format!("SELECT {} FROM `readback_jwks` WHERE `readback_jwks`.`stored_public_key` = ? AND `readback_jwks`.`stored_private_key` = ? AND `readback_jwks`.`stored_created_at` = ? AND `readback_jwks`.`stored_expires_at` IS NULL AND `readback_jwks`.`stored_algorithm` = ? LIMIT ?", projection("readback_jwks", &JWK_COLUMNS)),
        sql => panic!("Unspecified upstream SQL boundary: {sql}"),
    };
    (sql, json!(parameters))
}

pub(super) fn check_jwk(
    actual: Vec<Event>,
    expected: &[Value],
    first_operation: bool,
    label: &str,
) {
    let mut catalog_queries = 0;
    let expected = expected
        .iter()
        .filter(|event| {
            if event.get("sql").and_then(Value::as_str) == Some(CATALOG_SQL) {
                assert_eq!(event["level"], "query");
                assert_eq!(
                    event["parameters"],
                    json!(["kysely_migration", "kysely_migration_lock"])
                );
                catalog_queries += 1;
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();
    // Rust models declare columns statically; Kysely discovers its tables once per adapter.
    assert_eq!(
        catalog_queries,
        usize::from(first_operation),
        "{label} explicit catalog boundary"
    );
    assert_eq!(
        actual.len(),
        expected.len(),
        "{label} complete ordered trace: {actual:#?}"
    );
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let label = format!("{label} event {index}");
        match actual {
            Event::Callback(value) => assert_eq!(value, expected, "{label} callback"),
            Event::Transaction(operation) => assert_eq!(
                expected,
                &json!({
                    "phase": "sql", "level": "query", "sql": operation, "parameters": [],
                }),
                "{label} transaction boundary"
            ),
            Event::Sql { statement, failed } => {
                assert_eq!(expected["phase"], "sql", "{label}");
                assert_eq!(*failed, expected["level"] == "error", "{label} result");
                let (sql, values) = jwk_sql(expected);
                assert_eq!(statement.sql, sql, "{label} exact SeaORM SQL");
                assert_eq!(
                    parameters(statement),
                    values,
                    "{label} complete bound parameters"
                );
                if *failed {
                    check_missing_id_error(&expected["error"]);
                }
            }
        }
    }
}

pub(super) fn check_missing_id_error(error: &Value) {
    assert_eq!(
        error,
        &json!({
            "name": "Error",
            "message": "Unknown column 'id' in 'where clause'",
            "properties": {
                "code": "ER_BAD_FIELD_ERROR", "errno": 1054, "sqlState": "42S22",
                "sqlMessage": "Unknown column 'id' in 'where clause'",
                "sql": "select * from `readback_jwks` where `id` = 1 limit 1",
            },
        })
    );
}

fn lifecycle_sql(expected: &Value) -> (String, Value) {
    let mut parameters = driver_parameters(&expected["parameters"]);
    let user_columns = [
        "id",
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
    ];
    let session_columns = [
        "id",
        "expiresAt",
        "token",
        "createdAt",
        "updatedAt",
        "ipAddress",
        "userAgent",
        "userId",
    ];
    let verification_columns = [
        "id",
        "identifier",
        "value",
        "expiresAt",
        "createdAt",
        "updatedAt",
    ];
    let sql = match expected["sql"].as_str().expect("captured lifecycle SQL") {
        "insert into `user` (`name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt`, `id`) values (?, ?, ?, ?, ?, ?, ?)" => {
            assert_eq!(parameters[2], json!(1), "upstream MySQL boolean input encoding");
            parameters[2] = json!(true);
            "INSERT INTO `user` (`name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt`, `id`) VALUES (?, ?, ?, ?, ?, ?, ?)".to_owned()
        },
        "insert into `session` (`expiresAt`, `token`, `createdAt`, `updatedAt`, `ipAddress`, `userAgent`, `userId`, `id`) values (?, ?, ?, ?, ?, ?, ?, ?)" => "INSERT INTO `session` (`expiresAt`, `token`, `createdAt`, `updatedAt`, `ipAddress`, `userAgent`, `userId`, `id`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)".to_owned(),
        "insert into `verification` (`identifier`, `value`, `expiresAt`, `createdAt`, `updatedAt`, `id`) values (?, ?, ?, ?, ?, ?)" => "INSERT INTO `verification` (`identifier`, `value`, `expiresAt`, `createdAt`, `updatedAt`, `id`) VALUES (?, ?, ?, ?, ?, ?)".to_owned(),
        "select * from `user` where `id` = ? limit ?" => format!("SELECT {} FROM `user` WHERE `user`.`id` = ? LIMIT ?", projection("user", &user_columns)),
        "select * from `session` where `id` = ? limit ?" => format!("SELECT {} FROM `session` WHERE `session`.`id` = ? LIMIT ?", projection("session", &session_columns)),
        "select * from `verification` where `id` = ? limit ?" => format!("SELECT {} FROM `verification` WHERE `verification`.`id` = ? LIMIT ?", projection("verification", &verification_columns)),
        sql => panic!("Unspecified lifecycle SQL boundary: {sql}"),
    };
    (sql, json!(parameters))
}

fn lifecycle_projection(case: &super::lifecycle::Case) -> super::contract::TestResult<Vec<Value>> {
    let mut expected = Vec::new();
    let mut secondary_phases = Vec::new();
    for event in &case.trace {
        let phase = event["phase"].as_str().expect("captured lifecycle phase");
        if matches!(phase, "cache:get" | "cache:set") {
            if secondary_phases.is_empty() {
                let before = case
                    .trace
                    .iter()
                    .find(|event| event["phase"] == "before:plugin")
                    .expect("captured before hook");
                let original = super::contract::revive_fields(&before["data"]["fields"])?;
                let mut actual = original.clone();
                actual.extend(super::contract::revive_fields(&case.patch["fields"])?);
                expected.push(if case.model == "session" {
                    json!({"phase": "writer:session", "original": super::lifecycle::observe(Some(original))?, "actual": super::lifecycle::observe(Some(actual))?})
                } else {
                    json!({"phase": "writer:verification", "actual": super::lifecycle::observe(Some(actual))?})
                });
            }
            secondary_phases.push(phase);
        } else if event.get("sql").and_then(Value::as_str)
            == Some(
                "select `primary`.* from (select * from `user` where `user`.`id` = ?) as `primary`",
            )
        {
            assert_eq!(case.model, "session");
            assert_eq!(event["parameters"], json!(["owner-a"]));
            assert_eq!(event["level"], "query");
            secondary_phases.push("cache:user-read");
        } else if case.model == "user" && phase == "before:plugin" {
            assert_eq!(
                event["data"]["keys"],
                json!([
                    "createdAt",
                    "updatedAt",
                    "name",
                    "email",
                    "emailVerified",
                    "image",
                    "id"
                ])
            );
            expected.push(
                json!({"phase": "before:plugin", "data": {"fields": event["data"]["fields"]}}),
            );
        } else {
            expected.push(event.clone());
        }
    }
    let writer_runs = case.secondary && !case.cancel && !(case.deferred && case.after_error);
    let phases: &[&str] = if !writer_runs {
        &[]
    } else if case.model == "session" {
        &["cache:get", "cache:set", "cache:user-read", "cache:set"]
    } else {
        &["cache:set"]
    };
    assert_eq!(
        secondary_phases, phases,
        "{} explicitly excluded production-secondary scope",
        case.name
    );
    let cache_entries = if !writer_runs {
        0
    } else if case.model == "session" {
        2
    } else {
        1
    };
    assert_eq!(
        case.cache.len(),
        cache_entries,
        "{} fixed-clock fixture scope",
        case.name
    );
    Ok(expected)
}

pub(super) fn check_lifecycle(
    actual: Vec<Event>,
    case: &super::lifecycle::Case,
) -> super::contract::TestResult {
    // The custom writer observes the real lifecycle handoff. Production cache bytes, TTLs, and user loading need a shared clock.
    let expected = lifecycle_projection(case)?;
    assert_eq!(
        actual.len(),
        expected.len(),
        "{} complete lifecycle trace: {actual:#?}",
        case.name
    );
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let label = format!("{} event {index}", case.name);
        match actual {
            Event::Callback(value) => assert_eq!(
                value, &expected,
                "{label} callback or complete writer arguments"
            ),
            Event::Transaction(operation) => assert_eq!(
                expected,
                json!({
                    "phase": "sql", "level": "query", "sql": operation, "parameters": [],
                }),
                "{label} transaction boundary"
            ),
            Event::Sql { statement, failed } => {
                assert!(!failed, "{label} lifecycle SQL must succeed");
                assert_eq!(expected["phase"], "sql", "{label}");
                assert_eq!(expected["level"], "query", "{label}");
                let (sql, values) = lifecycle_sql(&expected);
                assert_eq!(statement.sql, sql, "{label} exact SeaORM SQL");
                assert_eq!(
                    parameters(statement),
                    values,
                    "{label} complete bound parameters"
                );
            }
        }
    }
    Ok(())
}
