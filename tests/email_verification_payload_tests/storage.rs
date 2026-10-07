use super::*;
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

pub(super) async fn projected<S: AuthSchema>(store: &dyn AuthStore<S>) -> TestResult<Value> {
    let (users, count) = store
        .list_users(ListUsersParams {
            limit: Some(100.0),
            sort_by: Some("id".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let mut users_out = Vec::new();
    let mut sessions = Vec::new();
    let mut accounts = Vec::new();
    for user in users {
        sessions.extend(store.get_user_sessions(user.id.typed()?).await?);
        accounts.extend(store.get_user_accounts(user.id.typed()?).await?);
        users_out.push(
            UserView::with_internal_fields(&user, &config().user, &Default::default()).await?,
        );
    }
    Ok(json!({"user": users_out, "session": sessions, "account": accounts}))
}

pub(super) fn assert_projected(actual: &Value, expected: &Value) {
    let mut users = required(expected, "/user").clone();
    for user in users.as_array_mut().expect("Captured User rows") {
        // Revive SQLite booleans and upstream Date observations at the adapter projection boundary.
        let email_verified = user
            .get_mut("emailVerified")
            .expect("Captured User emailVerified");
        if let Some(value) = email_verified.as_i64() {
            assert!(matches!(value, 0 | 1));
            *email_verified = json!(value == 1);
        }
        for field in ["createdAt", "updatedAt"] {
            let date = user.get_mut(field).expect("Captured User date");
            if date.get("type").and_then(Value::as_str) == Some("date") {
                *date = required(date, "/value").clone();
            }
        }
    }
    assert_eq!(
        actual,
        &json!({"user": users, "session": required(expected, "/session"), "account": required(expected, "/account")})
    );
    assert_eq!(required(expected, "/verification"), &json!([]));
}

pub(super) async fn sqlite(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["users", "sessions", "accounts", "verifications"] {
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
        assert!(!names.is_empty(), "Missing bundled table {table}");
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
        let rows = rows
            .iter()
            .map(|row| {
                Ok(serde_json::from_str::<Value>(
                    &row.try_get::<String>("", "data")?,
                )?)
            })
            .collect::<TestResult<Vec<_>>>()?;
        let _ = tables.insert(table.into(), json!(rows));
    }
    Ok(Value::Object(tables))
}
