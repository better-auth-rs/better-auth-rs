use super::*;

pub(super) async fn sqlite() -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    for sql in [
        "PRAGMA foreign_keys = ON",
        "CREATE TABLE user (id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, emailVerified BOOLEAN NOT NULL, image TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
        "CREATE TABLE account (id TEXT PRIMARY KEY, accountId TEXT NOT NULL, providerId TEXT NOT NULL, userId TEXT NOT NULL REFERENCES user(id), accessToken TEXT, refreshToken TEXT, idToken TEXT, accessTokenExpiresAt TIMESTAMP, refreshTokenExpiresAt TIMESTAMP, scope TEXT, password TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
        "CREATE TABLE session (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, userId TEXT NOT NULL REFERENCES user(id), expiresAt TIMESTAMP NOT NULL, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL, ipAddress TEXT, userAgent TEXT)",
        "CREATE TABLE verification (id TEXT PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt TIMESTAMP NOT NULL, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL)",
    ] {
        let _ = database
            .execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>, now: i64) -> TestResult {
    let date = FieldDate::from_milliseconds(now as f64);
    let _ = store
        .create_user(CreateUser {
            id: Some("duration-owner".into()),
            name: Some("Duration Owner".into()).into(),
            email: Some("owner@oauth-token-duration.test".into()),
            email_verified: Some(true),
            image: None::<String>.into(),
            created_at: Some(date.clone()),
            updated_at: Some(date.clone()),
            ..Default::default()
        })
        .await?;
    let _ = store
        .create_session(CreateSession {
            user_id: "duration-owner".into(),
            expires_at: FieldDate::from_milliseconds((now + 3_600_000) as f64),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: FieldMap::from([
                ("token".into(), "duration-owner-session-token".into()),
                ("createdAt".into(), date.clone().into()),
                ("updatedAt".into(), date.clone().into()),
            ]),
        })
        .await?;
    let _ = store
        .create_account(CreateAccount {
            id: "duration-account".into(),
            account_id: "duration-subject".into(),
            provider_id: "duration".into(),
            user_id: "duration-owner".into(),
            access_token: Some("duration-old-access".into()).into(),
            refresh_token: Some("duration-old-refresh".into()).into(),
            id_token: Some("duration-old-id".into()).into(),
            access_token_expires_at: Some(FieldDate::from_milliseconds((now - 1000) as f64)).into(),
            refresh_token_expires_at: Some(FieldDate::from_milliseconds((now + 7_200_000) as f64))
                .into(),
            scope: Some("openid email profile".into()).into(),
            password: None::<String>.into(),
            created_at: date.clone().into(),
            updated_at: date.into(),
            ..Default::default()
        })
        .await?;
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
        .list_users(better_auth_core::ListUsersParams {
            limit: Some(100.0),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let mut user_rows = Vec::new();
    let mut accounts = Vec::new();
    let mut sessions = Vec::new();
    for user in users {
        let view = better_auth_core::wire::UserView::with_internal_fields(
            &user,
            &config().user,
            &Default::default(),
        )
        .await?;
        user_rows.push(values::observe(&FieldMap::from(view).into())?);
        for account in store.get_user_accounts(user.id.typed()?).await? {
            accounts.push(values::observe(&account.internal_fields()?.into())?);
        }
        for session in store.get_user_sessions(user.id.typed()?).await? {
            sessions.push(values::observe(&FieldMap::from(session).into())?);
        }
    }
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
        let fields = names
            .iter()
            .map(|name| format!("'{name}', \"{name}\""))
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
            let mut record: Value = serde_json::from_str(&row.try_get::<String>("", "data")?)?;
            for name in [
                "createdAt",
                "updatedAt",
                "expiresAt",
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
            ] {
                if let Some(Value::String(value)) = record.get_mut(name) {
                    *value = value
                        .parse::<DateTime<Utc>>()?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            observed.push(record);
        }
        let _ = tables.insert(table.into(), Value::Array(observed));
    }
    Ok(Value::Object(tables))
}

pub(super) fn assert_snapshot(actual: &Value, expected: &Value, sqlite: bool) {
    if sqlite {
        assert_eq!(actual, expected);
    } else {
        assert_eq!(
            actual,
            &json!({"user": expected["user"], "session": expected["session"], "account": expected["account"]})
        );
        // The Memory API exposes rows through owner projections and has no Verification inventory query.
        assert_eq!(expected["verification"], json!([]));
    }
}
