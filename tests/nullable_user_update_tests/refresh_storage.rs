use super::*;
use better_auth_core::ListUsersParams;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Schema, Statement};

pub(super) async fn sqlite() -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    let schema = Schema::new(database.get_database_backend());
    for table in [
        schema.create_table_from_entity(models::user::Entity),
        schema.create_table_from_entity(models::account::Entity),
        schema.create_table_from_entity(models::session::Entity),
        schema.create_table_from_entity(models::verification::Entity),
    ] {
        let _ = database.execute(&table).await?;
    }
    Ok(database)
}

pub(super) async fn snapshot<S: AuthSchema>(
    raw: &dyn AuthStore<S>,
    database: Option<&DatabaseConnection>,
    cache: &Cache,
    config: &AuthConfig,
) -> TestResult<Value> {
    let database = if let Some(database) = database {
        sqlite_snapshot(database).await?
    } else {
        let (users, count) = raw
            .list_users(ListUsersParams {
                limit: Some(100.0),
                sort_by: Some("id".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await?;
        assert_eq!(users.len(), count);
        let mut projected = Vec::new();
        let mut accounts = Vec::new();
        let mut sessions = Vec::new();
        for user in users {
            projected.push(observed_user(Some(&user), config).await?);
            for account in raw.get_user_accounts(user.id.typed()?).await? {
                accounts.push(values::observe(&account.internal_fields()?.into())?);
            }
            for session in raw.get_user_sessions(user.id.typed()?).await? {
                sessions.push(values::observe(&FieldMap::from(session).into())?);
            }
        }
        json!({"user": projected, "account": accounts, "session": sessions})
    };
    Ok(json!({"database": database, "cache": cache.snapshot()?}))
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
        let fields = columns
            .iter()
            .map(|row| {
                let name = row.try_get::<String>("", "name")?;
                Ok(format!(
                    "'{}', \"{}\"",
                    name.replace('\'', "''"),
                    name.replace('"', "\"\"")
                ))
            })
            .collect::<Result<Vec<_>, better_auth_seaorm::sea_orm::DbErr>>()?
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
                        .parse::<chrono::DateTime<Utc>>()?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            observed.push(record);
        }
        let _ = tables.insert(table.into(), Value::Array(observed));
    }
    Ok(Value::Object(tables))
}
