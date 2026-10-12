use super::*;
use better_auth_core::AuthError;
use better_auth_seaorm::{
    OrganizationModels, SeaOrmStore,
    sea_orm::{self, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, Value},
    store::__private_test_support::bundled_schema::BundledSchema,
};
use sea_orm::sqlx::{Column, Row, TypeInfo, ValueRef};

mod organization {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "organization")]
    #[sea_orm(table_name = "organization")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM generates public trait implementations for this private fixture model."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        pub metadata: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM generates public trait implementations for this private fixture relation."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod invitation {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "invitation")]
    #[sea_orm(table_name = "invitation")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM generates public trait implementations for this private fixture model."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        #[sea_orm(column_name = "recipient_address")]
        pub email: String,
        pub role: String,
        pub status: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "inviterId")]
        pub inviter_id: String,
        // Disabled teams declare no physical column; raw projection must not request this typed slot.
        #[sea_orm(column_name = "teamId")]
        pub team_id: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM generates public trait implementations for this private fixture relation."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type Models = OrganizationModels<
    organization::Model,
    better_auth_seaorm::store::entities::member::Model,
    invitation::Model,
>;
type Store = SeaOrmStore<BundledSchema, Models>;

const TABLES: [&str; 7] = [
    "user",
    "session",
    "account",
    "verification",
    "organization",
    "member",
    "invitation",
];

fn database_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::internal(format!("Native email SQLite contract: {error}"))
}

fn parameter(value: &Json) -> AuthResult<Value> {
    match value {
        Json::Null => Ok(Value::String(None)),
        Json::String(value) => Ok(value.clone().into()),
        Json::Bool(value) => Ok((*value).into()),
        Json::Number(value) => value
            .as_i64()
            .map(Into::into)
            .ok_or_else(|| AuthError::internal("Captured SQLite number must be an integer")),
        _ => Err(AuthError::internal("Captured SQLite cell must be a scalar")),
    }
}

pub(super) async fn store(
    case: &Json,
    config: Arc<AuthConfig>,
) -> AuthResult<(Arc<Store>, DatabaseConnection)> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    // Preserve source column order and TEXT affinity; the selector contract depends on numeric-to-text comparison.
    for sql in [
        "CREATE TABLE user (id TEXT PRIMARY KEY, name TEXT, email TEXT, emailVerified INTEGER, image TEXT, createdAt TEXT, updatedAt TEXT)",
        "CREATE TABLE session (id TEXT PRIMARY KEY)",
        "CREATE TABLE account (id TEXT PRIMARY KEY)",
        "CREATE TABLE verification (id TEXT PRIMARY KEY)",
        "CREATE TABLE organization (id TEXT PRIMARY KEY, name TEXT, slug TEXT, logo TEXT, createdAt TEXT, metadata TEXT)",
        "CREATE TABLE member (id TEXT PRIMARY KEY, organizationId TEXT, userId TEXT, role TEXT, createdAt TEXT)",
        "CREATE TABLE invitation (id TEXT PRIMARY KEY, organizationId TEXT, recipient_address TEXT, role TEXT, status TEXT, expiresAt TEXT, createdAt TEXT, inviterId TEXT)",
    ] {
        let _ = database
            .execute_unprepared(sql)
            .await
            .map_err(database_error)?;
    }
    let source = test_helpers::native_source::source_value(&case["before"])?;
    for table in TABLES {
        let rows = source[table]
            .as_array()
            .ok_or_else(|| AuthError::internal("Captured SQLite table is missing"))?;
        for row in rows {
            let fields = row
                .as_object()
                .ok_or_else(|| AuthError::internal("Captured SQLite row is not an object"))?;
            let columns = fields
                .keys()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = vec!["?"; fields.len()].join(", ");
            let values = fields
                .values()
                .map(parameter)
                .collect::<AuthResult<Vec<_>>>()?;
            let _ = database
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    format!("INSERT INTO \"{table}\" ({columns}) VALUES ({placeholders})"),
                    values,
                ))
                .await
                .map_err(database_error)?;
        }
    }
    let store = SeaOrmStore::<BundledSchema>::new(config, database.clone())
        .with_organization_schema::<Models>();
    Ok((Arc::new(store), database))
}

pub(super) async fn snapshot(database: &DatabaseConnection) -> AuthResult<FieldValue> {
    let mut tables = FieldMap::new();
    for table in TABLES {
        let rows = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT * FROM \"{table}\" ORDER BY \"id\""),
            ))
            .await
            .map_err(database_error)?;
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let row = row.try_as_sqlite_row().ok_or_else(|| {
                AuthError::internal("SQLite snapshot requires a SQLite driver row")
            })?;
            let mut fields = FieldMap::new();
            for column in row.columns() {
                let name = column.name();
                let raw = row.try_get_raw(name).map_err(database_error)?;
                let value = if raw.is_null() {
                    FieldValue::Null
                } else {
                    match raw.type_info().name() {
                        "INTEGER" => {
                            FieldValue::from(row.try_get::<i64, _>(name).map_err(database_error)?)
                        }
                        "REAL" => {
                            FieldValue::from(row.try_get::<f64, _>(name).map_err(database_error)?)
                        }
                        "TEXT" => FieldValue::from(
                            row.try_get::<String, _>(name).map_err(database_error)?,
                        ),
                        other => {
                            return Err(AuthError::internal(format!(
                                "Unexpected SQLite snapshot cell: {other}"
                            )));
                        }
                    }
                };
                let _ = fields.insert(name.into(), value);
            }
            values.push(FieldValue::from(fields));
        }
        let _ = tables.insert(table.into(), values.into());
    }
    Ok(tables.into())
}
