use super::*;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Schema, Statement};

pub(super) async fn sqlite() -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    let backend = database.get_database_backend();
    let schema = Schema::new(backend);
    for statement in [
        schema.create_table_from_entity(core_models::user::Entity),
        schema.create_table_from_entity(core_models::session::Entity),
        schema.create_table_from_entity(models::account::Entity),
        schema.create_table_from_entity(core_models::verification::Entity),
    ] {
        let _ = database.execute_raw(backend.build(&statement)).await?;
    }
    let _ = database
        .execute_raw(Statement::from_string(
            backend,
            "CREATE TABLE badge (id TEXT PRIMARY KEY NOT NULL, label TEXT NOT NULL)".to_owned(),
        ))
        .await?;
    let _ = database
        .execute_raw(Statement::from_string(
            backend,
            "INSERT INTO badge (id, label) VALUES ('badge-a', 'Stored badge')".to_owned(),
        ))
        .await?;
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>) -> TestResult {
    let date: FieldDate = "2030-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    let expiry: FieldDate = "2032-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    for suffix in ["a", "b"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(format!("User {suffix}")).into(),
                email: Some(format!("{suffix}@custom-model-join-reference.test")),
                email_verified: Some(true),
                image: Some(format!("image-{suffix}")).into(),
                created_at: Some(date.clone()),
                updated_at: Some(date.clone()),
                ..Default::default()
            })
            .await?;
        let _ = store
            .create_account(CreateAccount {
                id: format!("account-{suffix}").into(),
                account_id: format!("external-{suffix}").into(),
                provider_id: "provider".into(),
                user_id: format!("user-{suffix}").into(),
                access_token: Some(format!("access-{suffix}")).into(),
                refresh_token: Some(format!("refresh-{suffix}")).into(),
                id_token: Some(format!("identity-{suffix}")).into(),
                access_token_expires_at: Some(expiry.clone()).into(),
                refresh_token_expires_at: Some(expiry.clone()).into(),
                scope: Some("read".to_owned()).into(),
                password: Some(format!("hash-{suffix}")).into(),
                created_at: date.clone().into(),
                updated_at: date.clone().into(),
                additional_fields: [("badgeId".into(), "badge-a".into())].into(),
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
    let baseline = config(None, false, None);
    let mut projected = Vec::new();
    let mut sessions = Vec::new();
    let mut accounts = Vec::new();
    for user in users {
        projected.push(values::observe(&user_fields(&user, &baseline).await?)?);
        sessions.extend(
            store
                .get_user_sessions(user.id.typed()?)
                .await?
                .into_iter()
                .map(|session| values::observe(&FieldMap::from(session).into()))
                .collect::<AuthResult<Vec<_>>>()?,
        );
        accounts.extend(
            store
                .get_user_accounts(user.id.typed()?)
                .await?
                .into_iter()
                .map(|account| values::observe(&account.internal_fields()?.into()))
                .collect::<AuthResult<Vec<_>>>()?,
        );
    }
    Ok(json!({"user":projected,"session":sessions,"account":accounts}))
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["user", "session", "account", "verification", "badge"] {
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

pub(super) fn assert_snapshot(actual: &Value, expected: &Value, sqlite: bool) {
    if sqlite {
        assert_eq!(actual, expected);
    } else {
        assert_eq!(
            actual,
            &json!({"user":expected["user"],"session":expected["session"],"account":expected["account"]})
        );
        println!(
            "Unpaired Memory persistence: Verification enumeration and custom badge storage have no Store API."
        );
    }
}
