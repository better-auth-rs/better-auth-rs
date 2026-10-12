#![expect(
    clippy::indexing_slicing,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

//! Replay bare SQL adapter operations through the production record engine.

use super::SeaOrmStore;
use crate::{
    SeaOrmPluginModel,
    store::{bundled_schema::BundledSchema, map_db_err, plugin_models::Entity},
};
use better_auth_core as auth_core;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldMap, FieldValue, store::schema::EntityRole,
};
use sea_orm::sqlx::{Column, Row};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, QueryOrder,
    QueryTrait,
};
use serde_json::Value;
use std::marker::PhantomData;

#[path = "../../../../tests/support/shared_column_contract.rs"]
mod contract;

#[path = "../../../../tests/support/observation_replay.rs"]
mod replay;
#[path = "../../../../tests/support/replay_failures.rs"]
mod replay_failures;
use replay::assert_replay;
use replay_failures::ReplayFailures;

// The record engine reads raw driver values; these entities supply only physical table and column metadata.
// Runtime declarations select the actual model role. Generated model types have a separate consumer contract.
macro_rules! sql_model {
    ($module:ident, $table:literal, $( $field:ident => $column:literal ),* $(,)?) => {
        #[expect(unreachable_pub, reason = "SeaORM derives require public fixture entity types")]
        mod $module {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, DeriveEntityModel, crate::AuthEntity)]
            #[sea_orm(table_name = $table)]
            #[auth(role = "jwk")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[sea_orm(column_name = "shared_value")]
                pub shared_value: Option<String>,
                $(
                    #[sea_orm(column_name = $column)]
                    pub $field: Option<String>,
                )*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

sql_model!(user, "user",
    email => "email", email_verified => "emailVerified", image => "image",
    created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(session, "session",
    expires_at => "expiresAt", token => "token", created_at => "createdAt",
    updated_at => "updatedAt", user_agent => "userAgent", user_id => "userId",
    active_organization_id => "activeOrganizationId", active_team_id => "activeTeamId",
);
sql_model!(account, "account",
    provider_id => "providerId", user_id => "userId", access_token => "accessToken",
    refresh_token => "refreshToken", id_token => "idToken",
    access_token_expires_at => "accessTokenExpiresAt", refresh_token_expires_at => "refreshTokenExpiresAt",
    scope => "scope", password => "password", created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(verification, "verification",
    value => "value", expires_at => "expiresAt", created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(organization, "organization",
    slug => "slug", logo => "logo", created_at => "createdAt", metadata => "metadata",
);
sql_model!(member, "member",
    organization_id => "organizationId", user_id => "userId", created_at => "createdAt",
);
sql_model!(invitation, "invitation",
    organization_id => "organizationId", email => "email", role => "role", team_id => "teamId",
    expires_at => "expiresAt", created_at => "createdAt", inviter_id => "inviterId",
);
sql_model!(team, "team",
    organization_id => "organizationId", member_count => "memberCount",
    created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(team_member, "teamMember",
    user_id => "userId", membership_key => "membershipKey", created_at => "createdAt",
);
sql_model!(organization_role, "organizationRole",
    organization_id => "organizationId", permission => "permission",
    created_at => "createdAt", updated_at => "updatedAt",
);

struct Adapter<M> {
    store: SeaOrmStore<BundledSchema>,
    role: EntityRole,
    model: String,
    metadata: PhantomData<fn() -> M>,
}

#[auth_core::__private_async_trait::async_trait]
impl<M: SeaOrmPluginModel> contract::Adapter for Adapter<M> {
    async fn execute(&self, method: &str, input: FieldValue) -> AuthResult<FieldValue> {
        assert_eq!(input.model_property("model")?, self.model.clone().into());
        let connection = self.store.connection();
        let model = self.store.plugin_record_model::<M>(self.role);
        match method {
            "create" => {
                assert_eq!(input.model_property("forceAllowId")?, true.into());
                model
                    .create(
                        connection,
                        crate::store::create_readback::ReadbackScope::Direct(connection),
                        &self.model,
                        input.model_property("data")?,
                        true,
                    )
                    .await
                    .map(|row| row.map_or(FieldValue::Null, Into::into))
            }
            "findOne" => model
                .find_by_id(connection, &contract::identifier(&input)?)
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "update" => model
                .update_by_id(
                    connection,
                    &contract::identifier(&input)?,
                    input.model_property("update")?,
                )
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "delete" => {
                model
                    .delete_by_id(connection, &contract::identifier(&input)?)
                    .await?;
                Ok(FieldValue::Undefined)
            }
            _ => Err(AuthError::internal("Unknown captured adapter method")),
        }
    }

    async fn stored(&self) -> AuthResult<Vec<FieldMap>> {
        let connection = self.store.connection();
        let rows = connection
            .query_all_raw(
                crate::store::plugin_rows::select_all::<Entity<M>>()
                    .order_by_asc(M::column("id")?)
                    .build(connection.get_database_backend()),
            )
            .await
            .map_err(map_db_err)?;
        rows.into_iter()
            .map(|row| {
                let columns = if let Some(raw) = row.try_as_sqlite_row() {
                    column_names(raw)
                } else if let Some(raw) = row.try_as_pg_row() {
                    column_names(raw)
                } else if let Some(raw) = row.try_as_mysql_row() {
                    column_names(raw)
                } else {
                    return Err(AuthError::internal(
                        "The shared-column contract requires a supported SQL driver row",
                    ));
                };
                columns
                    .into_iter()
                    .map(|column| {
                        Ok((
                            column.clone(),
                            crate::store::plugin_rows::value(&row, &column)?,
                        ))
                    })
                    .collect()
            })
            .collect()
    }
}

fn column_names<R: Row>(row: &R) -> Vec<String> {
    row.columns()
        .iter()
        .map(|column| column.name().to_owned())
        .collect()
}

async fn prepare(database: &DatabaseConnection, case: &Value, model: &str) -> AuthResult<()> {
    let backend = database.get_database_backend();
    let quote = if backend == DbBackend::MySql {
        '`'
    } else {
        '"'
    };
    let id_type = if backend == DbBackend::MySql {
        "VARCHAR(36)"
    } else {
        "TEXT"
    };
    // Parent records supply the capture's referenced IDs; only the target table belongs to this contract.
    for (parent, id) in [
        ("user", "owner"),
        ("organization", "workspace"),
        ("team", "team"),
    ] {
        if parent != model {
            let _ = database
                .execute_unprepared(&format!(
                    "CREATE TABLE {quote}{parent}{quote} (id {id_type} PRIMARY KEY)"
                ))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!(
                    "INSERT INTO {quote}{parent}{quote} (id) VALUES ('{id}')"
                ))
                .await
                .map_err(map_db_err)?;
        }
    }
    if backend != DbBackend::Sqlite {
        let migration = case["catalog"]["migration"]["initialSql"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Missing captured server migration"))?;
        let table = format!("create table {quote}{model}{quote} (");
        let index_table = format!(" on {quote}{model}{quote} (");
        let mut tables = 0;
        for statement in migration
            .split(';')
            .map(str::trim)
            .filter(|sql| !sql.is_empty())
        {
            assert!(
                statement.starts_with("create table ") || statement.starts_with("create index ")
            );
            if statement.starts_with(&table) {
                tables += 1;
            } else if !(statement.starts_with("create index ") && statement.contains(&index_table))
            {
                continue;
            }
            let _ = database
                .execute_unprepared(statement)
                .await
                .map_err(map_db_err)?;
        }
        assert_eq!(
            tables, 1,
            "The frozen migration must define one target table"
        );
        return Ok(());
    }
    let declarations = case["catalog"]["ddl"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing captured SQLite DDL"))?;
    for kind in ["table", "index"] {
        for declaration in declarations
            .iter()
            .filter(|declaration| declaration["type"] == kind)
        {
            if let Some(sql) = declaration["sql"].as_str() {
                let _ = database.execute_unprepared(sql).await.map_err(map_db_err)?;
            }
        }
    }
    Ok(())
}

async fn replay<M: SeaOrmPluginModel>(
    case: &Value,
    database: DatabaseConnection,
) -> AuthResult<()> {
    let (runtime, role, trace) = contract::runtime(case)?;
    let model = case["model"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing captured SQL model"))?;
    prepare(&database, case, model).await?;
    let mut store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database);
    store.model_fields = runtime;
    contract::run(
        &Adapter::<M> {
            store,
            role,
            model: model.to_owned(),
            metadata: PhantomData,
        },
        case,
        &trace,
    )
    .await
}

async fn replay_case(case: &Value, database: DatabaseConnection) -> AuthResult<()> {
    match case["model"].as_str() {
        Some("user") => replay::<user::Model>(case, database).await,
        Some("session") => replay::<session::Model>(case, database).await,
        Some("account") => replay::<account::Model>(case, database).await,
        Some("verification") => replay::<verification::Model>(case, database).await,
        Some("organization") => replay::<organization::Model>(case, database).await,
        Some("member") => replay::<member::Model>(case, database).await,
        Some("invitation") => replay::<invitation::Model>(case, database).await,
        Some("team") => replay::<team::Model>(case, database).await,
        Some("teamMember") => replay::<team_member::Model>(case, database).await,
        Some("organizationRole") => replay::<organization_role::Model>(case, database).await,
        _ => Err(AuthError::internal("Unknown captured SQL model")),
    }
}

#[tokio::test]
async fn shared_record_crud_matches_all_pinned_sqlite_column_collisions() -> AuthResult<()> {
    for case in contract::cases("sqlite")? {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(map_db_err)?;
        replay_case(&case, database).await?;
    }
    Ok(())
}

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

async fn isolated_server(backend: &str, case: Value) -> TestResult {
    let variable = match backend {
        "postgres" => "BETTER_AUTH_TEST_POSTGRES_URL",
        "mysql" => "BETTER_AUTH_TEST_MYSQL_URL",
        _ => return Err("Unknown shared-column server backend".into()),
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_shared_columns_{}", uuid::Uuid::new_v4().simple());
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
        replay_case(&case, worker).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result??;
    Ok(())
}

async fn replay_server(backend: &str) -> TestResult {
    let mut failures = Vec::new();
    for case in contract::cases(backend)? {
        let label = format!("{backend}/{}/{}", case["model"], case["mode"]);
        if let Err(error) = isolated_server(backend, case).await {
            eprintln!("Shared-column replay failed: {label}: {error}");
            failures.push(error);
        }
    }
    if let Some(error) = failures.into_iter().next() {
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_shared_column_contract() -> TestResult {
    replay_server("postgres").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_shared_column_contract() -> TestResult {
    replay_server("mysql").await
}
