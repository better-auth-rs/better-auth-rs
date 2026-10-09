use super::*;
use better_auth_seaorm::sea_orm::ConnectOptions;

fn expected_date(case: &Value, backend: &str) -> TestResult<Value> {
    let expected = case["expectedDate"]
        .get(backend)
        .unwrap_or(&case["expectedDate"]);
    let Some(date) = expected.get("localDate").and_then(Value::as_str) else {
        return Ok(expected.clone());
    };
    let date = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")?
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_local_timezone(chrono::Local)
        .single()
        .ok_or("Fixture local date must be unambiguous")?
        .with_timezone(&chrono::Utc);
    Ok(contract::observe(&date.into())?)
}

async fn create_tables(database: &DatabaseConnection, backend: &str) -> TestResult {
    migrator::run_migrations(database).await?;
    seed_records(database).await?;
    let statements = if backend == "postgres" {
        vec![
            "ALTER TABLE users ALTER COLUMN name DROP NOT NULL, ALTER COLUMN name TYPE NUMERIC USING NULL::NUMERIC, ALTER COLUMN created_at DROP DEFAULT, ALTER COLUMN created_at TYPE DATE USING created_at::DATE, ALTER COLUMN created_at DROP NOT NULL",
            "ALTER TABLE accounts ALTER COLUMN access_token TYPE NUMERIC USING NULL::NUMERIC, ALTER COLUMN access_token_expires_at TYPE DATE USING access_token_expires_at::DATE",
        ]
    } else {
        vec![
            "SET SESSION sql_mode = ''",
            "ALTER TABLE users MODIFY name DECIMAL(65, 30) NULL, MODIFY created_at DATE NULL",
            "ALTER TABLE accounts MODIFY access_token DECIMAL(65, 30) NULL, MODIFY access_token_expires_at DATE NULL",
        ]
    };
    for statement in statements {
        let _ = database.execute_unprepared(statement).await?;
    }
    Ok(())
}

async fn set_values(database: &DatabaseConnection, case: &Value) -> TestResult {
    for (table, number, date) in [
        ("users", "name", "created_at"),
        ("accounts", "access_token", "access_token_expires_at"),
    ] {
        let value = |name: &str| {
            case[name]
                .as_str()
                .map_or_else(|| "NULL".to_owned(), |value| format!("'{value}'"))
        };
        let _ = database
            .execute_unprepared(&format!(
                "UPDATE {table} SET {number} = {}, {date} = {}",
                value("numeric"),
                value("date")
            ))
            .await?;
    }
    Ok(())
}

async fn stored(database: &DatabaseConnection) -> TestResult<Value> {
    let backend = database.get_database_backend();
    let cast = if backend == DbBackend::Postgres {
        "TEXT"
    } else {
        "CHAR"
    };
    let mut snapshot = Vec::new();
    for (table, number, date) in [
        ("users", "name", "created_at"),
        ("accounts", "access_token", "access_token_expires_at"),
    ] {
        let row = database
            .query_one_raw(Statement::from_string(
                backend,
                format!("SELECT CAST({number} AS {cast}) AS number_value, CAST({date} AS {cast}) AS date_value FROM {table}"),
            ))
            .await?
            .unwrap();
        snapshot.push(json!({
            "numeric": row.try_get::<Option<String>>("", "number_value")?,
            "date": row.try_get::<Option<String>>("", "date_value")?,
        }));
    }
    Ok(json!({"selected": snapshot, "complete": complete_storage(database).await?}))
}

pub(super) async fn complete_storage(database: &DatabaseConnection) -> TestResult<Value> {
    let backend = database.get_database_backend();
    let mut result = Vec::new();
    for table in ["users", "accounts"] {
        let sql = match backend {
            DbBackend::Postgres => format!(
                "SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '{table}' ORDER BY ordinal_position"
            ),
            DbBackend::MySql => format!(
                "SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}' ORDER BY ORDINAL_POSITION"
            ),
            DbBackend::Sqlite => {
                format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid")
            }
            _ => {
                return Err(format!("Unsupported raw-column snapshot backend: {backend:?}").into());
            }
        };
        let columns = database
            .query_all_raw(Statement::from_string(backend, sql))
            .await?
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        let quote = if backend == DbBackend::MySql {
            '`'
        } else {
            '"'
        };
        let fields = columns
            .iter()
            .map(|name| format!("'{name}', {quote}{name}{quote}"))
            .collect::<Vec<_>>()
            .join(", ");
        let expression = match backend {
            DbBackend::Postgres => "row_to_json(stored)::TEXT".to_owned(),
            DbBackend::MySql => format!("CAST(JSON_OBJECT({fields}) AS CHAR)"),
            DbBackend::Sqlite => format!("json_object({fields})"),
            _ => {
                return Err(format!("Unsupported raw-column snapshot backend: {backend:?}").into());
            }
        };
        let rows = database
            .query_all_raw(Statement::from_string(
                backend,
                format!("SELECT {expression} AS record FROM {table} AS stored ORDER BY id"),
            ))
            .await?
            .iter()
            .map(|row| {
                Ok(serde_json::from_str::<Value>(
                    &row.try_get::<String>("", "record")?,
                )?)
            })
            .collect::<TestResult<Vec<_>>>()?;
        result.push(json!({"table": table, "columns": columns, "rows": rows}));
    }
    Ok(result.into())
}

async fn check(database: DatabaseConnection, backend: &str) -> TestResult {
    create_tables(&database, backend).await?;
    let cases: Value = serde_json::from_str(include_str!(
        "../fixtures/user-account-raw-column-cases.json"
    ))?;
    for case in cases["serverCases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case.get("backend").is_none_or(|value| value == backend))
    {
        set_values(&database, case).await?;
        let before = stored(&database).await?;
        let date = expected_date(case, backend)?;
        let mut fields = cases["serverFields"].clone();
        for field in fields.as_array_mut().unwrap() {
            field["raw"] = if field["source"] == "numeric" {
                case["expectedNumeric"][backend].clone()
            } else {
                date.clone()
            };
            if field.get("expected").is_none() {
                field["expected"] = field["raw"].clone();
            }
        }
        let configured = json!({"fields": fields});
        for joins in [false, true] {
            for reject in [false, true] {
                let events = Events::default();
                let store = SeaOrmStore::<BundledSchema>::new(
                    config(&configured, joins, reject, &events),
                    database.clone(),
                );
                for operation in cases["operations"].as_array().unwrap() {
                    events.lock().unwrap().clear();
                    let name = operation["name"].as_str().unwrap();
                    let result = read(&store, name).await;
                    let label = format!(
                        "{backend}, {}, joins={joins}, reject={reject}, {name}",
                        case["name"]
                    );
                    let mut expected_events = Vec::new();
                    let mut failed = false;
                    for model in operation["models"].as_array().unwrap() {
                        for field in configured["fields"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|field| field["model"] == *model)
                        {
                            let field_label = format!(
                                "{}.{}",
                                model.as_str().unwrap(),
                                field["name"].as_str().unwrap()
                            );
                            expected_events.push(json!([field_label, field["raw"]]));
                            if reject && field_label == "account.accessTokenExpiresAt" {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            break;
                        }
                    }
                    assert_eq!(*events.lock().unwrap(), expected_events, "{label}");
                    if failed {
                        assert_eq!(
                            result.unwrap_err().instrumentation_message(),
                            "raw-column-stop",
                            "{label}"
                        );
                    } else {
                        for (model, record) in result? {
                            assert_complete_record(
                                &cases,
                                &configured["fields"],
                                model,
                                &record,
                                &label,
                            )?;
                            for field in configured["fields"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|field| field["model"] == model)
                            {
                                assert_eq!(
                                    contract::observe(&record[field["name"].as_str().unwrap()])?,
                                    field["expected"],
                                    "{label}, {model}"
                                );
                            }
                        }
                    }
                    assert_eq!(
                        stored(&database).await?,
                        before,
                        "{label} unchanged storage"
                    );
                }
            }
        }
    }
    Ok(())
}

async fn isolated(backend: &'static str) -> TestResult {
    let variable = if backend == "postgres" {
        "BETTER_AUTH_TEST_POSTGRES_URL"
    } else {
        "BETTER_AUTH_TEST_MYSQL_URL"
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_raw_columns_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == "postgres" {
        (
            format!("CREATE SCHEMA {name}"),
            format!("SET search_path TO {name}"),
            format!("DROP SCHEMA {name} CASCADE"),
        )
    } else {
        (
            format!("CREATE DATABASE `{name}`"),
            format!("USE `{name}`"),
            format!("DROP DATABASE `{name}`"),
        )
    };
    let _ = database.execute_unprepared(&create).await?;
    let worker = database.clone();
    let result = tokio::spawn(async move {
        let _ = worker.execute_unprepared(&select).await?;
        check(worker, backend).await
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_raw_numeric_and_date_columns() -> TestResult {
    isolated("postgres").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_raw_decimal_and_date_columns() -> TestResult {
    isolated("mysql").await
}
