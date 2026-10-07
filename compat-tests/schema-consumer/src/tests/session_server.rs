use super::{
    server_catalog::{mysql as mysql_default, postgres as postgres_default},
    server_catalog_support::{self as server_catalog, TestResult},
};
use better_auth::{
    AuthConfig, AuthSchema, BetterAuth,
    prelude::{AuthUser, CreateUser},
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel, SeaOrmSessionModel,
        SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ConnectionTrait, DbBackend, EntityName, Iden, Statement},
    },
    store::SessionUpdate,
};
use serde_json::{Map, Value, json};

const ORIGIN: &str = "http://catalog.example.test";
const SECRET: &str = "ordinary-server-catalog-secret-at-least-32-characters";

mod postgres_custom {
    include!(env!("BETTER_AUTH_SESSION_SERVER_POSTGRES_CUSTOM_SCHEMA"));
}
mod mysql_custom {
    include!(env!("BETTER_AUTH_SESSION_SERVER_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<(Value, Vec<Value>)> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/session-{backend}-server-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let input = fixture.get("input").ok_or("Missing Session input")?;
    assert_eq!(
        input,
        &json!({
            "expiresIn":3600,
            "initial":{"ipAddress":"192.0.2.10","userAgent":"catalog-session/1"},
            "update":{"ipAddress":"192.0.2.20","userAgent":"catalog-session/2"},
        })
    );
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Session cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![Some("default"), Some("custom")]
    );
    let configurations: Value =
        serde_json::from_str(include_str!("../../session-catalog-config.json"))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing case name")?;
        assert_eq!(case.get("configuration"), configurations.get(name));
    }
    Ok((input.clone(), cases.clone()))
}

fn text<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing string {field}").into())
}

fn timestamp(value: &Value, field: &str) -> TestResult<i64> {
    Ok(chrono::DateTime::parse_from_rfc3339(text(value, field)?)?.timestamp_millis())
}

fn quote(backend: DbBackend, name: &str) -> String {
    match backend {
        DbBackend::Postgres => format!("\"{}\"", name.replace('"', "\"\"")),
        _ => format!("`{}`", name.replace('`', "``")),
    }
}

async fn stored<M: SeaOrmSessionModel>(
    database: &DatabaseConnection,
    token: &str,
) -> TestResult<Value> {
    let backend = database.get_database_backend();
    let columns = [
        ("id", "id"),
        ("expires_at", "expiresAt"),
        ("token", "token"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
        ("ip_address", "ipAddress"),
        ("user_agent", "userAgent"),
        ("user_id", "userId"),
    ]
    .into_iter()
    .map(|(field, alias)| {
        Ok(format!(
            "{} AS {}",
            quote(backend, &M::field_column(field)?.to_string()),
            quote(backend, alias)
        ))
    })
    .collect::<TestResult<Vec<_>>>()?
    .join(", ");
    let table = quote(backend, M::Entity::default().table_name());
    let token_column = quote(backend, &M::token_column().to_string());
    let parameter = if backend == DbBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    let rows = database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!("SELECT {columns} FROM {table} WHERE {token_column} = {parameter}"),
            [token.into()],
        ))
        .await?;
    let mut values = Vec::new();
    for row in rows {
        let mut value = Map::new();
        for field in ["id", "token", "userId"] {
            value.insert(field.into(), json!(row.try_get::<String>("", field)?));
        }
        for field in ["ipAddress", "userAgent"] {
            value.insert(
                field.into(),
                json!(row.try_get::<Option<String>>("", field)?),
            );
        }
        for field in ["expiresAt", "createdAt", "updatedAt"] {
            let date: chrono::DateTime<chrono::Utc> = row.try_get("", field)?;
            value.insert(
                field.into(),
                json!(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            );
        }
        values.push(Value::Object(value));
    }
    Ok(Value::Array(values))
}

async fn read_session<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    owner_id: &str,
) -> TestResult<Value> {
    let Some(session) = auth.store().get_session(token).await? else {
        return Ok(Value::Null);
    };
    let owner = auth
        .store()
        .get_user_by_id(session.user_id.typed()?)
        .await?
        .ok_or("Missing session owner")?;
    assert_eq!(owner.id().display_string()?, owner_id);
    Ok(serde_json::to_value(session)?)
}

fn visible(mut session: Value, updated_at: &str) -> Value {
    session["id"] = json!("<session-id>");
    session["token"] = json!("<session-token>");
    session["userId"] = json!("<owner-id>");
    session["createdAt"] = json!("<created-at>");
    session["expiresAt"] = json!("<expires-at>");
    session["updatedAt"] = json!(updated_at);
    session
}

fn visible_rows(rows: Value, updated_at: &str) -> TestResult<Value> {
    let rows = rows.as_array().ok_or("Missing stored rows")?;
    Ok(Value::Array(
        rows.iter()
            .cloned()
            .map(|row| visible(row, updated_at))
            .collect(),
    ))
}

async fn observe_session<S>(database: &DatabaseConnection, input: &Value) -> TestResult<Value>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let expires_in = input
        .get("expiresIn")
        .and_then(Value::as_i64)
        .ok_or("Missing session lifetime")?;
    let initial = input
        .get("initial")
        .ok_or("Missing initial client fields")?;
    let update = input.get("update").ok_or("Missing update client fields")?;
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_expires_in(chrono::Duration::seconds(expires_in));
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let auth = BetterAuth::<S>::new(config.clone())
        .store(SeaOrmStore::<S>::new(config, database.clone()))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Session catalog owner")
                .with_email("owner@session-catalog.test"),
        )
        .await?;
    let owner_id = owner.id().display_string()?;
    let started = chrono::Utc::now().timestamp_millis();
    let created = serde_json::to_value(
        auth.context()
            .session_manager()
            .create_session(
                &owner,
                Some(text(initial, "ipAddress")?.to_owned()),
                Some(text(initial, "userAgent")?.to_owned()),
            )
            .await?,
    )?;
    let created_finished = chrono::Utc::now().timestamp_millis();
    for field in ["id", "token"] {
        assert!(!text(&created, field)?.is_empty());
    }
    assert_eq!(text(&created, "userId")?, owner_id);
    assert_eq!(created.get("ipAddress"), initial.get("ipAddress"));
    assert_eq!(created.get("userAgent"), initial.get("userAgent"));
    for field in ["createdAt", "updatedAt", "expiresAt"] {
        let offset = if field == "expiresAt" {
            expires_in * 1000
        } else {
            0
        };
        let time = timestamp(&created, field)?;
        assert!(started + offset <= time && time <= created_finished + offset);
    }
    let token = text(&created, "token")?;
    let read = read_session(&auth, token, &owner_id).await?;
    assert_eq!(read, created);
    let stored_created = stored::<S::Session>(database, token).await?;
    assert_eq!(stored_created, json!([created]));
    let updated_started = chrono::Utc::now().timestamp_millis();
    let updated = serde_json::to_value(
        auth.store()
            .update_session_with_writer(
                token,
                SessionUpdate {
                    ip_address: Some(Some(text(update, "ipAddress")?.to_owned())),
                    user_agent: Some(Some(text(update, "userAgent")?.to_owned())),
                    ..Default::default()
                },
                None,
            )
            .await?
            .ok_or("Missing updated session")?,
    )?;
    let updated_finished = chrono::Utc::now().timestamp_millis();
    for field in ["id", "token", "userId", "createdAt", "expiresAt"] {
        assert_eq!(updated.get(field), created.get(field));
    }
    assert_eq!(updated.get("ipAddress"), update.get("ipAddress"));
    assert_eq!(updated.get("userAgent"), update.get("userAgent"));
    let updated_at = timestamp(&updated, "updatedAt")?;
    assert!(updated_started <= updated_at && updated_at <= updated_finished);
    let reread = read_session(&auth, token, &owner_id).await?;
    assert_eq!(reread, updated);
    let stored_updated = stored::<S::Session>(database, token).await?;
    assert_eq!(stored_updated, json!([updated]));
    auth.store().delete_session(token).await?;
    let deleted = read_session(&auth, token, &owner_id).await?;
    assert_eq!(deleted, Value::Null);
    let stored_deleted = stored::<S::Session>(database, token).await?;
    assert_eq!(stored_deleted, json!([]));
    let retained_owner = auth
        .store()
        .get_user_by_id(&owner_id)
        .await?
        .ok_or("Owner was deleted")?;
    assert_eq!(retained_owner.id().display_string()?, owner_id);
    Ok(json!({
        "created":visible(created, "<initial-updated-at>"), "read":visible(read, "<initial-updated-at>"),
        "updated":visible(updated, "<updated-at>"), "reread":visible(reread, "<updated-at>"),
        "storedCreated":visible_rows(stored_created, "<initial-updated-at>")?,
        "storedUpdated":visible_rows(stored_updated, "<updated-at>")?,
        "deleted":deleted, "storedDeleted":stored_deleted, "ownerRetained":true,
    }))
}

async fn check(
    database: &DatabaseConnection,
    backend: DbBackend,
    input: &Value,
    case: &Value,
) -> TestResult {
    let name = text(case, "name")?;
    macro_rules! observe {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            let columns = server_catalog::observe(
                database,
                backend,
                [$module::session::Entity.table_name().to_owned()],
            )
            .await?;
            let observation = observe_session::<$module::AppAuthSchema>(database, input).await?;
            assert_eq!(
                Some(&observation),
                case.get("observation"),
                "{backend:?}/{name} rows"
            );
            columns
        }};
    }
    let columns = match (backend, name) {
        (DbBackend::Postgres, "default") => observe!(postgres_default),
        (DbBackend::Postgres, "custom") => observe!(postgres_custom),
        (DbBackend::MySql, "default") => observe!(mysql_default),
        (DbBackend::MySql, "custom") => observe!(mysql_custom),
        _ => return Err(format!("Unsupported Session catalog {backend:?}/{name}").into()),
    };
    assert_eq!(
        &columns,
        case.get("columns").ok_or("Missing Session columns")?,
        "{backend:?}/{name} columns"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream fixture"]
async fn live_postgres_session_storage_matches_upstream() -> TestResult {
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
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream fixture"]
async fn live_mysql_session_storage_matches_upstream() -> TestResult {
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
