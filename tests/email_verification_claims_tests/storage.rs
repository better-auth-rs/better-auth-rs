use super::*;
use better_auth_core::FieldDate;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};

pub(super) async fn sqlite() -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    for sql in [
        "PRAGMA foreign_keys = ON",
        "CREATE TABLE user (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, emailVerified BOOLEAN NOT NULL DEFAULT 0, image TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
        "CREATE TABLE session (id TEXT NOT NULL PRIMARY KEY, expiresAt TIMESTAMP NOT NULL, token TEXT NOT NULL UNIQUE, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL, ipAddress TEXT, userAgent TEXT, userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE)",
        "CREATE TABLE account (id TEXT NOT NULL PRIMARY KEY, accountId TEXT NOT NULL, providerId TEXT NOT NULL, userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE, accessToken TEXT, refreshToken TEXT, idToken TEXT, accessTokenExpiresAt TIMESTAMP, refreshTokenExpiresAt TIMESTAMP, scope TEXT, password TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
        "CREATE TABLE verification (id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt TIMESTAMP NOT NULL, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
    ] {
        let _ = database
            .execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>, existing: bool) -> TestResult {
    let date = FieldDate::from_milliseconds(ISSUED_AT as f64);
    let _ = store
        .create_user(CreateUser {
            id: Some("claims-owner".into()),
            name: Some("Claims Owner".into()).into(),
            email: Some(EMAIL.into()),
            email_verified: Some(false),
            image: None::<String>.into(),
            created_at: Some(date.clone()),
            updated_at: Some(date.clone()),
            ..Default::default()
        })
        .await?;
    if existing {
        let _ = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: "claims-owner".into(),
                expires_at: FieldDate::from_milliseconds((ISSUED_AT + 3_600_000) as f64),
                ip_address: Some("203.0.113.8".into()),
                user_agent: Some("email-claims-contract".into()),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: FieldMap::from([
                    ("id".into(), "claims-existing-session".into()),
                    ("token".into(), "existing-claims-session-token".into()),
                    ("createdAt".into(), date.clone().into()),
                    ("updatedAt".into(), date.into()),
                ]),
            })
            .await?;
    }
    Ok(())
}

pub(super) async fn snapshot<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    database: Option<&DatabaseConnection>,
) -> TestResult<Value> {
    if let Some(database) = database {
        return sqlite_snapshot(database).await;
    }
    let (users, count) = store
        .list_users(ListUsersParams {
            limit: Some(100.0),
            sort_by: Some("id".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let mut user_rows = Vec::new();
    let mut sessions = Vec::new();
    let mut accounts = Vec::new();
    let baseline = config(None);
    for user in users {
        let view = better_auth_core::wire::UserView::with_internal_fields(
            &user,
            &baseline.user,
            &Default::default(),
        )
        .await?;
        user_rows.push(values::observe(&FieldMap::from(view).into())?);
        for session in store.get_user_sessions(user.id.typed()?).await? {
            sessions.push(values::observe(&FieldMap::from(session).into())?);
        }
        for account in store.get_user_accounts(user.id.typed()?).await? {
            accounts.push(values::observe(&account.internal_fields()?.into())?);
        }
    }
    // The Memory store has no Verification inventory API; only observed collections belong here.
    Ok(json!({"user": user_rows, "session": sessions, "account": accounts}))
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["user", "session", "account", "verification"] {
        let columns = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA table_info(\"{table}\")"),
            ))
            .await?;
        let names = columns
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(!names.is_empty(), "Missing captured table {table}");
        let fields = names
            .iter()
            .map(|name| {
                format!(
                    "'{}', \"{}\"",
                    name.replace('\'', "''"),
                    name.replace('"', "\"\"")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let rows = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT json_object({fields}) AS data FROM \"{table}\" ORDER BY \"id\""),
            ))
            .await?;
        let mut observed = Vec::new();
        for row in rows {
            let mut record = values::capture(&row.try_get::<String>("", "data")?)?;
            // Compare persisted instants at the captured millisecond precision without dropping columns.
            for name in [
                "createdAt",
                "updatedAt",
                "expiresAt",
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
            ] {
                if let Some(Value::String(value)) = record.get_mut(name) {
                    *value = value
                        .parse::<chrono::DateTime<chrono::Utc>>()?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            observed.push(record);
        }
        let _ = tables.insert(table.into(), Value::Array(observed));
    }
    Ok(Value::Object(tables))
}
