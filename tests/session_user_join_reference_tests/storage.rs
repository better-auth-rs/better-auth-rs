use super::*;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Schema, Statement};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
mod session {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "session", row_presence)]
    #[sea_orm(table_name = "session")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        pub token: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "ipAddress")]
        pub ip_address: Option<String>,
        #[sea_orm(column_name = "userAgent")]
        pub user_agent: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "ownerRef")]
        pub owner_ref: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) struct Core;
impl AuthSchema for Core {
    type User = <core_models::Core as AuthSchema>::User;
    type Account = <core_models::Core as AuthSchema>::Account;
    type Session = session::Model;
    type Verification = <core_models::Core as AuthSchema>::Verification;
}

pub(super) async fn sqlite() -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    let backend = database.get_database_backend();
    let schema = Schema::new(backend);
    for statement in [
        schema.create_table_from_entity(core_models::user::Entity),
        schema.create_table_from_entity(session::Entity),
        schema.create_table_from_entity(core_models::account::Entity),
        schema.create_table_from_entity(core_models::verification::Entity),
    ] {
        let _ = database.execute_raw(backend.build(&statement)).await?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>, scenario: &str) -> TestResult {
    let date: FieldDate = "2030-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    let selected = !matches!(
        scenario,
        "default" | "removed-reference" | "second-optional-user-reference"
    );
    let reverse = scenario.starts_with("reverse-");
    let many = scenario.starts_with("reverse-user-reference-many");
    let missing = scenario.ends_with("-empty") || scenario.ends_with("-missing");
    for suffix in if selected {
        &["a", "b", "c"][..]
    } else {
        &["a", "b"][..]
    } {
        let image = if !reverse {
            Some(format!("image-{suffix}"))
        } else if *suffix == "a" {
            Some("session-b".into())
        } else if !missing && (*suffix == "b" || many) {
            Some("session-a".into())
        } else {
            None
        };
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(format!("User {suffix}")).into(),
                email: Some(format!("{suffix}@session-user-join-reference.test")),
                email_verified: Some(true),
                image: image.into(),
                created_at: Some(date.clone()),
                updated_at: Some(date.clone()),
                ..Default::default()
            })
            .await?;
    }
    for suffix in if selected {
        &["a", "b"][..]
    } else {
        &["a"][..]
    } {
        let token = if *suffix == "a" {
            TOKEN.into()
        } else {
            format!("{TOKEN}-b")
        };
        let owner = if *suffix == "a" { "user-b" } else { "user-a" };
        let _ = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: format!("user-{suffix}").into(),
                expires_at: "2100-01-02T03:04:05.000Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()?
                    .into(),
                ip_address: Some("203.0.113.8".into()),
                user_agent: Some("session-user-join-reference".into()),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: [
                    ("token".into(), token.into()),
                    ("createdAt".into(), date.clone().into()),
                    ("updatedAt".into(), date.clone().into()),
                    ("ownerRef".into(), owner.into()),
                ]
                .into(),
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
    let baseline = config("default", false, None);
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
            for name in ["createdAt", "updatedAt", "expiresAt"] {
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
        assert_eq!(expected["verification"], json!([]));
        println!(
            "Unpaired Memory observation boundary: Verification has no enumeration API; compare complete User/Session/Account projections."
        );
    }
}
