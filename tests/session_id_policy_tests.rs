#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, FieldMap, FieldValue,
    id::IdGeneration,
    store::{SessionStore, database_hooks::SessionUpdate},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
        EntityTrait, IntoActiveModel, Schema,
    },
    store::{__private_test_support::bundled_schema::BundledSchema, entities::session},
};
use std::sync::{Arc, Mutex, OnceLock, Weak};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Store = SeaOrmStore<BundledSchema>;

#[path = "session_id_policy_tests/create.rs"]
mod create;

#[derive(Clone, Copy)]
enum Read {
    None,
    Existing,
    Missing,
}

fn seed() -> TestResult<session::Model> {
    let date = "2030-01-02T03:04:05Z".parse::<chrono::DateTime<chrono::Utc>>()?;
    Ok(session::Model {
        id: "7".into(),
        token: "session-token".into(),
        user_id: "owner".into(),
        expires_at: date + chrono::Duration::hours(1),
        created_at: date,
        updated_at: date,
        ip_address: Some("127.0.0.1".into()),
        user_agent: Some("ID-policy-test".into()),
        impersonated_by: None,
        active_organization_id: Some("before".into()),
        active_team_id: None,
        active: true,
    })
}

async fn reset(database: &DatabaseConnection) -> TestResult<session::Model> {
    let _ = session::Entity::delete_many().exec(database).await?;
    let row = seed()?;
    let _ = row.clone().into_active_model().insert(database).await?;
    Ok(row)
}

fn id_policy() -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some("ignored_id_column".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("Application ID input must be replaced"))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal(
                    "Application ID output must be replaced",
                ))
            })),
        }),
        ..Default::default()
    }
}

async fn check_update(
    database: &DatabaseConnection,
    mode: IdGeneration,
    supplied: &str,
    expected: &str,
    id_first: bool,
    read: Read,
) -> TestResult {
    let target = Arc::new(OnceLock::<Weak<Store>>::new());
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let callback_target = target.clone();
    let callback_events = events.clone();
    let label = UserFieldConfig {
        field_name: Some("active_organization_id".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = callback_target.clone();
                let events = callback_events.clone();
                async move {
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Session ID event lock poisoned"))?
                        .push("input".into());
                    if !matches!(read, Read::None) {
                        let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                            AuthError::internal("Session callback store is unavailable")
                        })?;
                        let token = if matches!(read, Read::Existing) {
                            "session-token"
                        } else {
                            "missing-token"
                        };
                        let found = store.get_session(token).await?;
                        let event = match found {
                            Some(row) => format!("read:{}", row.id.typed()?),
                            None => "read:missing".into(),
                        };
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("Session ID event lock poisoned"))?
                            .push(event);
                    }
                    Ok(value)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(mode);
    config.session.additional_fields = Some(
        if id_first {
            [("id".into(), id_policy()), ("label".into(), label)]
        } else {
            [("label".into(), label), ("id".into(), id_policy())]
        }
        .into(),
    );
    let store = Arc::new(Store::new(config, database.clone()));
    target
        .set(Arc::downgrade(&store))
        .map_err(|_| "Session callback store was already assigned")?;
    let mut stored = reset(database).await?;
    let updated_at = stored.updated_at + chrono::Duration::minutes(1);
    let result = store
        .update_session_with_writer(
            &stored.token,
            SessionUpdate {
                id: Some(supplied.into()),
                token: Some("updated-token".into()),
                updated_at: Some(updated_at.into()),
                additional_fields: FieldMap::from([("label".into(), "after".into())]),
                ..Default::default()
            },
            None,
        )
        .await?
        .ok_or("Session update returned no row")?;
    assert_eq!(result.id.typed()?, expected);
    assert_eq!(result.token, "updated-token");
    assert_eq!(result.updated_at, updated_at.into());
    assert_eq!(
        result.additional_fields.get("label"),
        Some(&FieldValue::from("after"))
    );
    stored.id = expected.into();
    stored.token = "updated-token".into();
    stored.updated_at = updated_at;
    stored.active_organization_id = Some("after".into());
    assert_eq!(session::Entity::find().all(database).await?, [stored]);
    let expected_events = match read {
        Read::None => vec!["input"],
        Read::Existing => vec!["input", "read:7"],
        Read::Missing => vec!["input", "read:missing"],
    };
    assert_eq!(
        *events
            .lock()
            .map_err(|_| "Session ID event lock poisoned")?,
        expected_events
    );
    Ok(())
}

async fn check_aliases(database: &DatabaseConnection) -> TestResult {
    for id_first in [true, false] {
        for supplied in [FieldValue::from("100"), FieldValue::Undefined] {
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
            let alias = UserFieldConfig {
                field_name: Some("id".into()),
                ..Default::default()
            };
            config.session.additional_fields = Some(
                if id_first {
                    [("id".into(), id_policy()), ("aliasId".into(), alias)]
                } else {
                    [("aliasId".into(), alias), ("id".into(), id_policy())]
                }
                .into(),
            );
            let store = Store::new(config, database.clone());
            let mut stored = reset(database).await?;
            let updated_at = stored.updated_at + chrono::Duration::minutes(1);
            let expected = if id_first || supplied.is_undefined() {
                "200"
            } else {
                "100"
            };
            let result = store
                .update_session_with_writer(
                    &stored.token,
                    SessionUpdate {
                        id: Some("300".into()),
                        updated_at: Some(updated_at.into()),
                        additional_fields: FieldMap::from([
                            ("id".into(), supplied),
                            ("aliasId".into(), "200".into()),
                        ]),
                        ..Default::default()
                    },
                    None,
                )
                .await?
                .ok_or("Aliased session update returned no row")?;
            assert_eq!(result.id.typed()?, expected);
            stored.id = expected.into();
            stored.updated_at = updated_at;
            assert_eq!(session::Entity::find().all(database).await?, [stored]);
        }
    }
    Ok(())
}

async fn contract(database: DatabaseConnection) -> TestResult {
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend()).create_table_from_entity(session::Entity),
        )
        .await?;
    // Pinned 1.7.6 get-id-field.mjs applies Number only while the ID input policy survives.
    for (input, expected) in [
        ("1e2", "100"),
        ("0x65", "101"),
        ("00102", "102"),
        ("", "7"),
        ("invalid", "7"),
    ] {
        check_update(
            &database,
            IdGeneration::Serial,
            input,
            expected,
            true,
            Read::None,
        )
        .await?;
    }
    check_update(&database, IdGeneration::Random, "", "7", true, Read::None).await?;
    let uuid = "f79b497c-7d3b-4ff7-a20d-407fd259f788";
    let uuid_input = if database.get_database_backend() == DbBackend::Postgres {
        "7"
    } else {
        uuid
    };
    for (id_first, read, expected) in [
        (true, Read::None, uuid_input),
        (false, Read::Missing, uuid),
        (false, Read::Existing, uuid),
        (true, Read::Missing, uuid_input),
    ] {
        check_update(
            &database,
            IdGeneration::Uuid,
            uuid,
            expected,
            id_first,
            read,
        )
        .await?;
    }
    for id_first in [true, false] {
        for (input, converted) in [("00101", "101"), ("invalid", "7"), ("", "7")] {
            let expected = if id_first { converted } else { input };
            check_update(
                &database,
                IdGeneration::Serial,
                input,
                expected,
                id_first,
                Read::Existing,
            )
            .await?;
        }
    }
    check_update(
        &database,
        IdGeneration::Serial,
        "invalid",
        "7",
        false,
        Read::Missing,
    )
    .await?;
    check_aliases(&database).await?;
    create::contract(&database).await
}

#[tokio::test]
async fn sqlite_session_ids_follow_input_policy_and_schema_order() -> TestResult {
    contract(Database::connect("sqlite::memory:").await?).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_session_ids_follow_input_policy_and_schema_order() -> TestResult {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_session_ids_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        contract(worker).await
    })
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated test databases"]
async fn live_mysql_session_ids_reselect_the_written_id_or_token() -> TestResult {
    let mut url = reqwest::Url::parse(&std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?)?;
    let admin = Database::connect(url.as_str()).await?;
    let name = format!("ba_session_ids_{}", uuid::Uuid::new_v4().simple());
    let _ = admin
        .execute_unprepared(&format!("CREATE DATABASE `{name}`"))
        .await?;
    url.set_path(&name);
    let result = async {
        let database = Database::connect(url.as_str()).await?;
        let worker = database.clone();
        let result = tokio::spawn(async move { contract(worker).await }).await;
        let closed = database.close().await;
        result??;
        closed?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = admin
        .execute_unprepared(&format!("DROP DATABASE `{name}`"))
        .await;
    let closed = admin.close().await;
    let _ = cleanup?;
    closed?;
    result
}
