use super::*;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use std::collections::BTreeMap;

pub(super) async fn sqlite(scenario: &Scenario) -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = ON",
        ))
        .await?;
    let foreign_keys = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys",
        ))
        .await?
        .ok_or("Missing foreign_keys setting")?;
    assert_eq!(foreign_keys.try_get::<i64>("", "foreign_keys")?, 1);
    let (image_constraint, owner_constraint, token_constraint) = match scenario.relation.as_str() {
        "alternate-account-reference" => ("", "", " REFERENCES user(id) ON DELETE CASCADE"),
        "reverse-user-reference-many" => (" REFERENCES account(id) ON DELETE CASCADE", "", ""),
        "unique-account-reference" => ("", " UNIQUE REFERENCES user(id) ON DELETE CASCADE", ""),
        value => return Err(format!("Unknown physical relation: {value}").into()),
    };
    let user = format!(
        r#"CREATE TABLE user (
        id TEXT NOT NULL PRIMARY KEY, name TEXT, email TEXT NOT NULL UNIQUE,
        emailVerified BOOLEAN NOT NULL DEFAULT 0, image TEXT{image_constraint},
        createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
    )"#
    );
    let account = format!(
        r#"CREATE TABLE account (
        id TEXT NOT NULL PRIMARY KEY, accountId TEXT, providerId TEXT NOT NULL,
        userId TEXT{owner_constraint}, accessToken TEXT{token_constraint}, refreshToken TEXT,
        idToken TEXT, accessTokenExpiresAt TIMESTAMP, refreshTokenExpiresAt TIMESTAMP,
        scope TEXT, password TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
    )"#
    );
    for sql in [user, account,
        r#"CREATE TABLE session (
            id TEXT NOT NULL PRIMARY KEY, expiresAt TIMESTAMP NOT NULL, token TEXT NOT NULL UNIQUE,
            createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL, ipAddress TEXT, userAgent TEXT,
            userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE
        )"#.into(),
        r#"CREATE TABLE verification (
            id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL,
            expiresAt TIMESTAMP NOT NULL, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
        )"#.into(),
    ] {
        let _ = database.execute_raw(Statement::from_string(DbBackend::Sqlite, sql)).await?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    scenario: &Scenario,
) -> TestResult {
    let date: FieldDate = "2030-01-02T03:04:05Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    for model in if scenario.many {
        ["account", "user"]
    } else {
        ["user", "account"]
    } {
        if model == "user" {
            for suffix in ["a", "b", "c"] {
                let image = if scenario.many {
                    if suffix == "a" {
                        "account-b".into()
                    } else {
                        "account-a".into()
                    }
                } else {
                    format!("image-{suffix}")
                };
                let _ = store
                    .create_user(CreateUser {
                        id: Some(format!("user-{suffix}")),
                        name: Some(format!("User {suffix}")).into(),
                        email: Some(format!("{suffix}@account-user-auth-boundary.test")),
                        email_verified: Some(true),
                        image: Some(image).into(),
                        created_at: Some(date.clone()),
                        updated_at: Some(date.clone()),
                        ..Default::default()
                    })
                    .await?;
            }
        } else {
            for suffix in ["a", "b"] {
                let account_id = if scenario.accounts_one {
                    format!("user-{suffix}")
                } else if suffix == "a" {
                    "external-owner".into()
                } else {
                    "external-decoy".into()
                };
                let _ = store
                    .create_account(CreateAccount {
                        id: format!("account-{suffix}").into(),
                        account_id: account_id.into(),
                        provider_id: if scenario.accounts_one {
                            "credential"
                        } else {
                            "google"
                        }
                        .into(),
                        user_id: format!("user-{suffix}").into(),
                        access_token: Some(
                            if suffix == "a" { "user-b" } else { "user-a" }.to_owned(),
                        )
                        .into(),
                        refresh_token: None::<String>.into(),
                        id_token: None::<String>.into(),
                        access_token_expires_at: None::<FieldDate>.into(),
                        refresh_token_expires_at: None::<FieldDate>.into(),
                        scope: None::<String>.into(),
                        password: scenario
                            .accounts_one
                            .then(|| PASSWORD_HASH.to_owned())
                            .into(),
                        created_at: date.clone().into(),
                        updated_at: date.clone().into(),
                        ..Default::default()
                    })
                    .await?;
            }
        }
    }
    Ok(())
}

pub(super) async fn snapshot<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    database: Option<&DatabaseConnection>,
    issued_tokens: &[String],
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
    let mut accounts = Vec::new();
    let mut sessions = BTreeMap::new();
    let mut projected_users = Vec::new();
    let baseline = config::baseline();
    for user in &users {
        let projected = better_auth_core::wire::UserView::with_internal_fields(
            user,
            &baseline.user,
            &Default::default(),
        )
        .await?;
        projected_users.push(values::observe(&FieldMap::from(projected).into())?);
        accounts.extend(store.get_user_accounts(user.id.typed()?).await?);
        for session in store.get_user_sessions(user.id.typed()?).await? {
            insert_session(&mut sessions, session)?;
        }
    }
    for token in issued_tokens {
        if let Some(session) = store.get_session(token).await? {
            insert_session(&mut sessions, session)?;
        }
    }
    Ok(json!({
        "user": projected_users,
        "account": accounts.iter().map(|account| values::observe(&account.internal_fields()?.into())).collect::<AuthResult<Vec<_>>>()?,
        "session": sessions.into_values().collect::<Vec<_>>(),
    }))
}

fn insert_session(
    sessions: &mut BTreeMap<String, Value>,
    session: better_auth_core::wire::SessionView,
) -> TestResult {
    let value = values::observe(&FieldMap::from(session.clone()).into())?;
    if let Some(previous) = sessions.insert(session.id.typed()?.clone(), value.clone()) {
        assert_eq!(
            previous, value,
            "Owner lookup and token lookup must return the same Session"
        );
    }
    Ok(())
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["user", "account", "session", "verification"] {
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
            let mut record: Value = serde_json::from_str(&row.try_get::<String>("", "data")?)?;
            // Driver timestamp text differs; compare the persisted instants and preserve every other SQLite value.
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

pub(super) fn assert_snapshot(actual: &Value, expected: &Value, sqlite: bool, case: &Case) {
    if sqlite {
        assert_eq!(actual, expected, "{case:?}: complete SQLite rows");
    } else {
        // The public Memory adapter exposes projections, including own Undefined for an absent Session owner.
        let mut sessions = expected["session"].clone();
        if let Some(rows) = sessions.as_array_mut() {
            for row in rows {
                if row.get("userId").is_none() {
                    row["userId"] = json!({"type": "undefined"});
                }
            }
        }
        assert_eq!(
            actual,
            &json!({"user": expected["user"], "account": expected["account"], "session": sessions}),
            "{case:?}: Memory adapter projection"
        );
        assert_eq!(
            expected["verification"],
            json!([]),
            "The captured scenario does not touch Verification"
        );
    }
}
