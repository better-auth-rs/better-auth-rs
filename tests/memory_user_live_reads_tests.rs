#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed captured fixture keys and local setup must exist; failures stop the contract immediately."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateAccount, CreateSession, CreateUser,
    ListUsersParams, UpdateUser,
    store::{AccountStore, EphemeralStore, JoinValue, SessionStore, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::UserView,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type UpdateUserFn = Arc<
    dyn Fn(UpdateUser) -> futures_util::future::BoxFuture<'static, AuthResult<UserView>>
        + Send
        + Sync,
>;

#[derive(Default)]
struct Trace {
    enabled: AtomicBool,
    nested: AtomicBool,
    update_user: Mutex<Option<UpdateUserFn>>,
    events: Mutex<Vec<Value>>,
}

fn display(user: &UserView) -> Value {
    json!({"name": user.name, "image": user.image})
}

fn configuration(case: &Value, trace: &Arc<Trace>) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = case["joins"].as_bool();
    config.advanced.database.default_find_many_limit = Some(1.0);
    let callback = trace.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let trace = callback.clone();
                    async move {
                        if !trace.enabled.load(Ordering::SeqCst)
                            || trace.nested.load(Ordering::SeqCst)
                        {
                            return Ok(value);
                        }
                        trace
                            .events
                            .lock()
                            .unwrap()
                            .push(json!(["name", value.json()?]));
                        trace.nested.store(true, Ordering::SeqCst);
                        let update_user =
                            trace.update_user.lock().unwrap().as_ref().unwrap().clone();
                        let changed = update_user(UpdateUser {
                            image: Some("image-after".into()).into(),
                            ..Default::default()
                        })
                        .await;
                        trace.nested.store(false, Ordering::SeqCst);
                        let _ = changed?;
                        trace
                            .events
                            .lock()
                            .unwrap()
                            .push(json!(["display-write", "image-after"]));
                        Ok(format!("{}-visible", value.as_str().unwrap()).into())
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    config
}

fn attach_store<S: AuthSchema, T: UserStore<S> + 'static>(store: &Arc<T>, trace: &Arc<Trace>) {
    let store = Arc::downgrade(store);
    *trace.update_user.lock().unwrap() = Some(Arc::new(move |update| {
        let store = store.upgrade().unwrap();
        Box::pin(async move { store.update_user("ordinary-user", update).await })
    }));
}

fn configured(case: &Value, trace: &Arc<Trace>) -> Arc<EphemeralStore> {
    let store = Arc::new(EphemeralStore::new(Arc::new(configuration(case, trace))));
    attach_store::<better_auth_core::store::StatelessSchema, _>(&store, trace);
    store
}

fn user_input() -> CreateUser {
    CreateUser {
        id: Some("ordinary-user".into()),
        name: Some("ordinary-name".into()).into(),
        image: Some("image-before".into()).into(),
        email: Some("ordinary@user-read.test".into()),
        email_verified: Some(true),
        ..Default::default()
    }
}

async fn seed(store: &EphemeralStore) -> AuthResult<String> {
    let _ = store.create_user(user_input()).await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: "ordinary-user".into(),
            user_agent: None,
            ip_address: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
            expires_at: "2099-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
                .into(),
        })
        .await?;
    let _ = store
        .create_account(CreateAccount {
            id: "ordinary-account".into(),
            account_id: "ordinary-account".into(),
            provider_id: "ordinary-provider".into(),
            user_id: "ordinary-user".into(),
            ..Default::default()
        })
        .await?;
    Ok(session.token.typed()?.clone())
}

#[tokio::test]
async fn ordinary_user_reads_keep_later_display_fields_live() -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/memory-user-live-reads-1.7.6.json"))?;
    for case in fixture["cases"].as_array().unwrap() {
        let path = case["path"].as_str().unwrap();
        let variants: &[&str] = if path == "point" {
            &["string", "field", "value"]
        } else {
            &["default"]
        };
        for variant in variants {
            let trace = Arc::new(Trace::default());
            let store = configured(case, &trace);
            let token = seed(&store).await?;
            trace.enabled.store(true, Ordering::SeqCst);
            let users = match path {
                "point" => vec![match *variant {
                    "field" => store
                        .get_user_by_id_field(&"ordinary-user".into())
                        .await?
                        .unwrap(),
                    "value" => store
                        .get_user_by_id_value(&"ordinary-user".into())
                        .await?
                        .unwrap(),
                    _ => store.get_user_by_id("ordinary-user").await?.unwrap(),
                }],
                "email" => vec![
                    store
                        .get_user_by_email("ordinary@user-read.test")
                        .await?
                        .unwrap(),
                ],
                "user-accounts" => vec![
                    store
                        .get_user_with_accounts("ordinary@user-read.test")
                        .await?
                        .unwrap()
                        .user,
                ],
                "list" => {
                    store
                        .list_users(ListUsersParams {
                            limit: Some(1.0),
                            sort_by: Some("name".into()),
                            sort_direction: Some("asc".into()),
                            ..Default::default()
                        })
                        .await?
                        .0
                }
                "ids" => {
                    store
                        .list_users_by_ids(&["ordinary-user".into()], 1.0)
                        .await?
                }
                "owner" => {
                    let owner = store
                        .get_account_owner("ordinary-provider", "ordinary-account")
                        .await?
                        .unwrap();
                    let JoinValue::One(owner_user) = owner.user else {
                        return Err(AuthError::internal("Expected a single Account owner"));
                    };
                    vec![owner_user.unwrap()]
                }
                "sessions" => store
                    .get_session_snapshots(&[token], false)
                    .await?
                    .into_iter()
                    .map(|(_, data)| Ok(data.unwrap().into_typed()?.unwrap().user))
                    .collect::<AuthResult<Vec<_>>>()?,
                _ => {
                    return Err(better_auth_core::AuthError::internal(
                        "Unknown captured user read path",
                    ));
                }
            };
            trace.enabled.store(false, Ordering::SeqCst);
            let stored = store.get_user_by_id("ordinary-user").await?.unwrap();
            assert_eq!(
                json!({
                    "path": path, "joins": case["joins"], "events": *trace.events.lock().unwrap(),
                    "result": users.iter().map(display).collect::<Vec<_>>(), "stored": display(&stored)
                }),
                *case,
                "{variant}"
            );
        }
    }
    Ok(())
}

async fn observe_write<S: AuthSchema>(
    store: &impl UserStore<S>,
    trace: &Trace,
    path: &str,
    expected_image: &str,
) -> AuthResult<()> {
    if path == "update" {
        let _ = store.create_user(user_input()).await?;
    }
    trace.enabled.store(true, Ordering::SeqCst);
    let result = if path == "create" {
        store.create_user(user_input()).await?
    } else {
        store
            .update_user(
                "ordinary-user",
                UpdateUser {
                    image: Some("image-before".into()).into(),
                    ..Default::default()
                },
            )
            .await?
    };
    trace.enabled.store(false, Ordering::SeqCst);
    let stored = store.get_user_by_id("ordinary-user").await?.unwrap();
    assert_eq!(
        display(&result),
        json!({"name":"ordinary-name-visible", "image":expected_image})
    );
    assert_eq!(
        display(&stored),
        json!({"name":"ordinary-name", "image":"image-after"})
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            json!(["name", "ordinary-name"]),
            json!(["display-write", "image-after"])
        ]
    );
    Ok(())
}

#[tokio::test]
async fn memory_user_writes_keep_later_output_fields_live() -> AuthResult<()> {
    for path in ["create", "update"] {
        let trace = Arc::new(Trace::default());
        let store = configured(&json!({"joins": false}), &trace);
        observe_write(store.as_ref(), &trace, path, "image-after").await?;
    }
    Ok(())
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
async fn sqlite_user_writes_keep_the_returned_row_snapshot() -> AuthResult<()> {
    use better_auth_seaorm::{
        SeaOrmStore,
        sea_orm::Database,
        store::__private_test_support::{bundled_schema::BundledSchema, migrator},
    };
    for path in ["create", "update"] {
        let trace = Arc::new(Trace::default());
        let config = Arc::new(configuration(&json!({"joins": false}), &trace));
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| {
                AuthError::internal(format!(
                    "Cannot connect User live-write SQLite fixture: {error}"
                ))
            })?;
        migrator::run_migrations(&database).await.map_err(|error| {
            AuthError::internal(format!(
                "Cannot migrate User live-write SQLite fixture: {error}"
            ))
        })?;
        let store = Arc::new(SeaOrmStore::<BundledSchema>::new(config, database));
        attach_store::<BundledSchema, _>(&store, &trace);
        observe_write(store.as_ref(), &trace, path, "image-before").await?;
    }
    Ok(())
}
