use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError,
    error::DatabaseError,
    organization_fields::OrganizationFields,
    store::{OrganizationRoleStore, OrganizationStore},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
        EntityTrait, QueryOrder, Schema, Set,
    },
    store::{__private_test_support::bundled_schema::BundledSchema, entities::organization_role},
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract requires backend syntax errors, zero callbacks, and complete storage preservation"
)]
async fn check(database: DatabaseConnection) -> TestResult {
    let backend = database.get_database_backend();
    let _ = database
        .execute(&Schema::new(backend).create_table_from_entity(organization_role::Entity))
        .await?;
    let created_at = chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    for (id, organization_id, role) in [
        ("target", "target-org", "reader"),
        ("unrelated", "other-org", "writer"),
    ] {
        let _ = organization_role::ActiveModel {
            id: Set(id.into()),
            organization_id: Set(organization_id.into()),
            role: Set(role.into()),
            permission: Set(json!({})),
            created_at: Set(created_at),
            updated_at: Set(None),
        }
        .insert(&database)
        .await?;
    }
    let before = organization_role::Entity::find()
        .order_by_asc(organization_role::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 2);
    let trace = Trace::default();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    store.configure_organization_fields(OrganizationFields {
        organization_role: UserConfig {
            additional_fields: Some(
                [(
                    "role".into(),
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                record(&input_trace, "role-input")?;
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                record(&output_trace, "role-output")?;
                                Ok(value)
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
        ..Default::default()
    })?;
    let result = store.query_organization_roles("target-org", &[]).await;
    match backend {
        DbBackend::Sqlite => assert!(result?.is_empty()),
        DbBackend::Postgres | DbBackend::MySql => {
            let Err(AuthError::Database(DatabaseError::Query(message))) = result else {
                return Err(AuthError::internal(format!(
                    "Empty role IN must retain the {backend:?} query error: {result:?}"
                ))
                .into());
            };
            if backend == DbBackend::Postgres {
                assert_eq!(
                    message,
                    "Query Error: error returned from database: syntax error at or near \")\""
                );
            } else {
                // SQLx prepares placeholders; mysql2 interpolates values in the upstream diagnostic.
                let near = message
                    .strip_prefix("Query Error: error returned from database: 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '")
                    .and_then(|message| message.strip_suffix("' at line 1"))
                    .ok_or_else(|| AuthError::internal(format!("Unexpected MySQL syntax diagnostic: {message}")))?;
                assert!(near.starts_with(')'), "{message}");
            }
        }
        _ => {
            return Err(
                AuthError::internal(format!("Unsupported test backend: {backend:?}")).into(),
            );
        }
    }
    assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
    assert_eq!(
        organization_role::Entity::find()
            .order_by_asc(organization_role::Column::Id)
            .all(&database)
            .await?,
        before
    );
    Ok(())
}

async fn isolated(backend: DbBackend) -> TestResult {
    let variable = if backend == DbBackend::Postgres {
        "BETTER_AUTH_TEST_POSTGRES_URL"
    } else {
        "BETTER_AUTH_TEST_MYSQL_URL"
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_empty_role_in_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == DbBackend::Postgres {
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
    // A separate task preserves database cleanup when a contract assertion panics.
    let result = tokio::spawn(async move {
        let _ = worker.execute_unprepared(&select).await?;
        check(worker).await
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

#[tokio::test]
async fn sqlite_empty_role_in_returns_no_rows_and_preserves_storage() -> TestResult {
    check(Database::connect("sqlite::memory:").await?).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_empty_role_in_retains_syntax_error_and_preserves_storage() -> TestResult {
    isolated(DbBackend::Postgres).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_empty_role_in_retains_syntax_error_and_preserves_storage() -> TestResult {
    isolated(DbBackend::MySql).await
}
