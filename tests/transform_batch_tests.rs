#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM derives require public generated entity types"
)]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession,
    CreateUser, CreateVerification, SchemaValue, store::EphemeralStore, types::ListUsersParams,
    user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore,
    sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    store::{__private_test_support::migrator, entities},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, MutexGuard};

mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "batch_sessions")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
        pub first: Option<String>,
        pub second: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
struct AppSchema;
impl AuthSchema for AppSchema {
    type User = entities::user::Model;
    type Session = session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

#[derive(Default)]
struct Trace {
    events: Vec<String>,
    failures: Vec<&'static str>,
    armed: bool,
}
impl Trace {
    fn reset(&mut self, failures: &[&'static str]) {
        self.events.clear();
        self.failures = failures.to_vec();
        self.armed = true;
    }
}
fn locked(trace: &Mutex<Trace>) -> AuthResult<MutexGuard<'_, Trace>> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Fixture trace mutex was poisoned"))
}
fn pair<T>(rows: &[T]) -> AuthResult<&[T; 2]> {
    rows.try_into()
        .map_err(|_| AuthError::internal("Expected exactly two fixture rows"))
}
fn original_name(id: &str, ids: &[String; 2]) -> AuthResult<&'static str> {
    if id == ids[0] {
        Ok("A")
    } else if id == ids[1] {
        Ok("B")
    } else {
        Err(AuthError::internal("Returned fixture ID is unknown"))
    }
}
fn field(name: &'static str, trace: &Arc<Mutex<Trace>>) -> UserFieldConfig {
    let trace = trace.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                let mut trace = locked(&trace)?;
                if !trace.armed {
                    return Ok(value);
                }
                let raw = value
                    .as_ref()
                    .and_then(Value::as_str)
                    .ok_or_else(|| AuthError::internal("Fixture output field must be a string"))?;
                let event = format!("{name}:{raw}");
                trace.events.push(event.clone());
                if trace.failures.contains(&event.as_str()) {
                    return Err(AuthError::Config(event));
                }
                Ok(Some(json!(format!("{raw}:{}", trace.events.len()))))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn config(trace: &Arc<Mutex<Trace>>) -> AuthConfig {
    let mut config = AuthConfig::default();
    for name in ["name", "image"] {
        let _ = config
            .user
            .fields_mut()
            .insert(name.into(), field(name, trace));
    }
    for name in ["first", "second"] {
        let _ = config
            .session
            .fields_mut()
            .insert(name.into(), field(name, trace));
    }
    for name in ["accountId", "providerId"] {
        let _ = config
            .account
            .additional_fields
            .insert(name.into(), field(name, trace));
    }
    for name in ["identifier", "value"] {
        let _ = config
            .verification
            .additional_fields
            .insert(name.into(), field(name, trace));
    }
    config
}
fn reset(trace: &Mutex<Trace>, failures: &[&'static str]) -> AuthResult<()> {
    locked(trace)?.reset(failures);
    Ok(())
}
fn events(trace: &Mutex<Trace>) -> AuthResult<Vec<String>> {
    Ok(locked(trace)?.events.clone())
}
async fn check<S: AuthSchema>(
    store: &impl AuthStore<S>,
    trace: &Arc<Mutex<Trace>>,
    backend: &str,
) -> AuthResult<()> {
    let mut ids = Vec::new();
    for name in ["A", "B"] {
        let mut input = CreateUser::new()
            .with_name(name)
            .with_email(format!("{name}@batch.test"));
        input.image = Some(format!("{name}.png")).into();
        ids.push(store.create_user(input).await?.id.typed()?.clone());
    }
    let ids = pair(&ids)?;
    reset(trace, &[])?;
    let (users, total) = store
        .list_users(ListUsersParams {
            sort_by: Some("email".into()),
            sort_direction: Some("desc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    let users = pair(&users)?;
    assert_eq!(
        events(trace)?,
        ["name:B", "name:A", "image:B.png", "image:A.png"]
    );
    assert_eq!(users[0].name.json()?, Some(json!("B:1")));
    assert_eq!(users[1].image.json()?, Some(json!("A.png:4")));
    assert_eq!(users[0].id.typed()?, &ids[1]);
    reset(trace, &[])?;
    let users = store.list_users_by_ids(ids, 10.0).await?;
    let users = pair(&users)?;
    let names = [
        original_name(users[0].id.typed()?, ids)?,
        original_name(users[1].id.typed()?, ids)?,
    ];
    assert_ne!(names[0], names[1]);
    assert_eq!(
        events(trace)?,
        [
            format!("name:{}", names[0]),
            format!("name:{}", names[1]),
            format!("image:{}.png", names[0]),
            format!("image:{}.png", names[1])
        ]
    );
    for (index, (user, name)) in users.iter().zip(names).enumerate() {
        assert_eq!(
            user.name.json()?,
            Some(json!(format!("{}:{}", name, index + 1)))
        );
        assert_eq!(
            user.image.json()?,
            Some(json!(format!("{}.png:{}", name, index + 3)))
        );
    }
    reset(trace, &[])?;
    let user = store
        .get_user_by_id(&ids[0])
        .await?
        .ok_or_else(|| AuthError::internal("Created fixture user is missing"))?;
    assert_eq!(events(trace)?, ["name:A", "image:A.png"]);
    let _ =
        better_auth_core::UserView::with_fields(&user, &config(trace).user, &Default::default())
            .await?;
    assert_eq!(events(trace)?, ["name:A", "image:A.png"]);
    for (failures, expected, message) in [
        (
            vec!["name:A"],
            vec!["name:A", "name:B", "image:B.png"],
            "name:A",
        ),
        (
            vec!["name:B"],
            vec!["name:A", "name:B", "image:A.png"],
            "name:B",
        ),
        (
            vec!["image:A.png"],
            vec!["name:A", "name:B", "image:A.png", "image:B.png"],
            "image:A.png",
        ),
        (
            vec!["name:B", "image:A.png"],
            vec!["name:A", "name:B", "image:A.png"],
            "name:B",
        ),
        (vec!["name:A", "name:B"], vec!["name:A", "name:B"], "name:A"),
    ] {
        reset(trace, &failures)?;
        let error = match store
            .list_users(ListUsersParams {
                sort_by: Some("email".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await
        {
            Err(error) => error,
            Ok(_) => {
                return Err(AuthError::internal(
                    "Expected the configured callback error",
                ));
            }
        };
        assert!(matches!(error, AuthError::Config(ref value) if value == message));
        assert_eq!(events(trace)?, expected);
    }
    locked(trace)?.armed = false;
    let mut tokens = Vec::new();
    let mut account_ids = Vec::new();
    for name in ["A", "B"] {
        let account = store
            .create_account(CreateAccount {
                account_id: name.into(),
                provider_id: "normal".into(),
                user_id: ids[0].clone().into(),
                ..Default::default()
            })
            .await?;
        account_ids.push(account.id.typed()?.clone());
        tokens.push(
            store
                .create_session(CreateSession {
                    user_id: ids[0].clone().into(),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    additional_fields: serde_json::from_value(
                        json!({"first":name,"second":format!("{name}.png")}),
                    )?,
                })
                .await?
                .token,
        );
        let _ = store
            .create_verification(CreateVerification {
                identifier: "batch".into(),
                value: name.into(),
                expires_at: SchemaValue::Typed(
                    "2020-01-01T00:00:00Z"
                        .parse::<DateTimeUtc>()
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                ),
                ..Default::default()
            })
            .await?;
    }
    reset(trace, &[])?;
    let accounts = store.get_user_accounts(&ids[0]).await?;
    let accounts = pair(&accounts)?;
    let account_ids = pair(&account_ids)?;
    let names = [
        original_name(accounts[0].id.typed()?, account_ids)?,
        original_name(accounts[1].id.typed()?, account_ids)?,
    ];
    assert_ne!(names[0], names[1]);
    assert_eq!(
        events(trace)?,
        [
            format!("accountId:{}", names[0]),
            format!("accountId:{}", names[1]),
            "providerId:normal".into(),
            "providerId:normal".into()
        ]
    );
    for (index, (account, name)) in accounts.iter().zip(names).enumerate() {
        assert_eq!(
            account.account_id.json()?,
            Some(json!(format!("{name}:{}", index + 1)))
        );
        assert_eq!(
            account.provider_id.json()?,
            Some(json!(format!("normal:{}", index + 3)))
        );
    }
    reset(trace, &[])?;
    let sessions = store.get_user_sessions(&ids[0]).await?;
    let sessions = pair(&sessions)?;
    let token_pair = pair(&tokens)?;
    let names = [
        original_name(&sessions[0].token, token_pair)?,
        original_name(&sessions[1].token, token_pair)?,
    ];
    assert_ne!(names[0], names[1]);
    assert_eq!(
        events(trace)?,
        [
            format!("first:{}", names[0]),
            format!("first:{}", names[1]),
            format!("second:{}.png", names[0]),
            format!("second:{}.png", names[1])
        ]
    );
    for (index, (session, name)) in sessions.iter().zip(names).enumerate() {
        assert_eq!(
            session.additional_fields.get("first"),
            Some(&json!(format!("{name}:{}", index + 1)))
        );
        assert_eq!(
            session.additional_fields.get("second"),
            Some(&json!(format!("{name}.png:{}", index + 3)))
        );
    }
    reset(trace, &[])?;
    let snapshots = store.get_session_snapshots(&tokens, true).await?;
    let snapshots = pair(&snapshots)?;
    let tokens = pair(&tokens)?;
    let names = [
        original_name(&snapshots[0].0.token, tokens)?,
        original_name(&snapshots[1].0.token, tokens)?,
    ];
    assert_ne!(names[0], names[1]);
    let mut expected = vec![
        format!("first:{}", names[0]),
        format!("first:{}", names[1]),
        format!("second:{}.png", names[0]),
        format!("second:{}.png", names[1]),
    ];
    let captured: Value =
        serde_json::from_str(include_str!("fixtures/fallback-continuation-1.7.6.json"))?;
    let captured = captured["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case["backend"] == backend && case["kind"] == "session" && case["mode"] == "sync"
            })
        })
        .ok_or_else(|| AuthError::internal("Pinned session continuation fixture missing"))?;
    for event in captured["events"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Pinned events missing"))?
    {
        match event[0].as_str() {
            Some("name") => expected.push("name:A".into()),
            Some("detail") => expected.push("image:A.png".into()),
            _ => {}
        }
    }
    assert_eq!(events(trace)?, expected);
    for (index, ((session, _), name)) in snapshots.iter().zip(names).enumerate() {
        assert_eq!(
            session.additional_fields.get("first"),
            Some(&json!(format!("{}:{}", name, index + 1)))
        );
        assert_eq!(
            session.additional_fields.get("second"),
            Some(&json!(format!("{}.png:{}", name, index + 3)))
        );
    }
    reset(trace, &[])?;
    assert_eq!(store.delete_expired_verifications().await?, 2);
    let events = events(trace)?;
    assert!(
        events == ["identifier:batch", "identifier:batch", "value:A", "value:B"]
            || events == ["identifier:batch", "identifier:batch", "value:B", "value:A"]
    );
    Ok(())
}

#[tokio::test]
async fn memory_lists_project_by_field_and_preserve_errors() -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Trace::default()));
    check(
        &EphemeralStore::new(config(&trace).into()),
        &trace,
        "memory",
    )
    .await
}
#[tokio::test]
async fn sqlite_lists_project_by_field_and_preserve_errors() -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let db = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&db)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(session::Entity))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    check(
        &SeaOrmStore::<AppSchema>::new(config(&trace), db),
        &trace,
        "sqlite",
    )
    .await
}
