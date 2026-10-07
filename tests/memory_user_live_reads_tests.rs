#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed captured fixture keys and local setup must exist; failures stop the contract immediately."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateSession, CreateUser, ListUsersParams,
    UpdateUser,
    store::{AccountStore, EphemeralStore, JoinValue, SessionStore, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::UserView,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Trace {
    enabled: AtomicBool,
    nested: AtomicBool,
    store: Mutex<Weak<EphemeralStore>>,
    events: Mutex<Vec<Value>>,
}

fn display(user: &UserView) -> Value {
    json!({"name": user.name, "image": user.image})
}

fn configured(case: &Value, trace: &Arc<Trace>) -> Arc<EphemeralStore> {
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
                        let store = trace.store.lock().unwrap().upgrade().unwrap();
                        let changed = store
                            .update_user(
                                "ordinary-user",
                                UpdateUser {
                                    image: Some("image-after".into()).into(),
                                    ..Default::default()
                                },
                            )
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
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    *trace.store.lock().unwrap() = Arc::downgrade(&store);
    store
}

async fn seed(store: &EphemeralStore) -> AuthResult<String> {
    let _ = store
        .create_user(CreateUser {
            id: Some("ordinary-user".into()),
            name: Some("ordinary-name".into()).into(),
            image: Some("image-before".into()).into(),
            email: Some("ordinary@user-read.test".into()),
            email_verified: Some(true),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
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
    Ok(session.token)
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
