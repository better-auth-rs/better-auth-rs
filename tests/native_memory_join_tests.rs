#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The captured contract uses fixed fixture keys and fails immediately when setup or output shape changes."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateSession, CreateUser, FieldMap,
    FieldValue, UpdateAccount, UpdateUser,
    store::{
        AccountStore, EphemeralStore, JoinValue, SessionStore, UserStore,
        database_hooks::SessionUpdate,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::{SessionView, UserView},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Trace {
    events: Mutex<Vec<Value>>,
    enabled: AtomicBool,
    nested: AtomicBool,
    changed: AtomicBool,
    store: Mutex<Option<Arc<EphemeralStore>>>,
    first_started: Notify,
    second_finished: Notify,
    release_first: Notify,
}

impl Trace {
    fn event(&self, field: &str, value: &Value) {
        self.events.lock().unwrap().push(json!([field, value]));
    }
    fn before(
        &self,
        field: &str,
        mode: &str,
        parent: &str,
        value: &FieldValue,
    ) -> AuthResult<bool> {
        if !self.enabled.load(Ordering::SeqCst) || self.nested.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let value = value.json()?.unwrap();
        self.event(field, &value);
        if (mode == "parent-error" && field == parent && value == "A-agent")
            || (mode == "child-error" && field == "account.displayLabel" && value == "A-label-0")
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "ORDINARY_DISPLAY_FAILURE",
                message: "Ordinary display callback failed",
            });
        }
        if field == "user.image" && value == "B-image" {
            self.second_finished.notify_one();
        }
        Ok(true)
    }
    async fn update_display(&self, path: &str, live: bool) -> AuthResult<()> {
        self.nested.store(true, Ordering::SeqCst);
        let store = self.store.lock().unwrap().as_ref().unwrap().clone();
        let result = if path == "accounts" {
            store
                .update_account(
                    "account-a-0",
                    UpdateAccount {
                        additional_fields: [("displayLabel".into(), "A-label-0-after".into())]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    },
                )
                .await
                .map(|_| "A-label-0-after")
        } else {
            let update = if live {
                UpdateUser {
                    image: Some("image-after".into()).into(),
                    ..Default::default()
                }
            } else {
                UpdateUser {
                    name: Some("A-after".into()).into(),
                    ..Default::default()
                }
            };
            store
                .update_user(if live { "ordinary-user" } else { "user-a" }, update)
                .await
                .map(|_| if live { "image-after" } else { "A-after" })
        };
        self.nested.store(false, Ordering::SeqCst);
        self.event("display-write", &json!(result?));
        Ok(())
    }
}

fn display(value: FieldValue, enabled: bool) -> FieldValue {
    if enabled {
        format!("{}-visible", value.as_str().unwrap()).into()
    } else {
        value
    }
}

fn field(trace: &Arc<Trace>, path: &str, mode: &str, name: &str, parent: &str) -> UserFieldConfig {
    let trace = trace.clone();
    let path = path.to_owned();
    let mode = mode.to_owned();
    let name = name.to_owned();
    let parent = parent.to_owned();
    let output =
        if (mode == "parent-read" || mode == "parent-wait") && name == parent || mode == "live" {
            UserFieldTransform::new_async(move |value| {
                let trace = trace.clone();
                let (path, mode, name, parent) =
                    (path.clone(), mode.clone(), name.clone(), parent.clone());
                async move {
                    let enabled = trace.before(&name, &mode, &parent, &value)?;
                    if enabled {
                        if mode == "parent-wait" && value.as_str() == Some("A-agent") {
                            trace.first_started.notify_one();
                            trace.release_first.notified().await;
                        }
                        if (mode == "parent-read" || mode == "live")
                            && !trace.changed.swap(true, Ordering::SeqCst)
                        {
                            trace.update_display(&path, mode == "live").await?;
                        }
                    }
                    Ok(display(value, enabled))
                }
            })
        } else {
            UserFieldTransform::new(move |value| {
                let enabled = trace.before(&name, &mode, &parent, &value)?;
                Ok(display(value, enabled))
            })
        };
    UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn configured(case: &Value, trace: &Arc<Trace>) -> Arc<EphemeralStore> {
    configured_with_limit(case, trace, case["limit"].as_f64())
}

fn configured_with_limit(
    case: &Value,
    trace: &Arc<Trace>,
    limit: Option<f64>,
) -> Arc<EphemeralStore> {
    let path = case["path"].as_str().unwrap();
    let mode = case["mode"].as_str().unwrap();
    let parent = match path {
        "accounts" => "user.name",
        "owner" => "account.displayLabel",
        _ => "session.userAgent",
    };
    let mut config = AuthConfig::default();
    config.advanced.database.joins = case["joins"].as_bool();
    config.advanced.database.default_find_many_limit = limit;
    for (model, name) in [
        ("user", "name"),
        ("user", "image"),
        ("session", "userAgent"),
        ("account", "displayLabel"),
    ] {
        let policy = field(trace, path, mode, &format!("{model}.{name}"), parent);
        let fields = match model {
            "user" => config.user.fields_mut(),
            "session" => config.session.fields_mut(),
            _ => &mut config.account.additional_fields,
        };
        let _ = fields.insert(name.into(), policy);
    }
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    *trace.store.lock().unwrap() = Some(store.clone());
    store
}

async fn seed(store: &EphemeralStore) -> AuthResult<()> {
    let date = "2025-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    for label in ["A", "B", "C"] {
        let suffix = label.to_lowercase();
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(label.into()).into(),
                image: Some(format!("{label}-image")).into(),
                email: Some(format!("{suffix}@ordinary-native-join.test")),
                email_verified: Some(true),
                created_at: Some(date.into()),
                updated_at: Some(date.into()),
                ..Default::default()
            })
            .await?;
        let session = store
            .create_session(CreateSession {
                user_id: format!("user-{suffix}").into(),
                user_agent: Some(format!("{label}-agent")),
                expires_at: "2099-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
                    .into(),
                additional_fields: Default::default(),
                ip_address: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let _ = store
            .update_session_with_writer(
                &session.token,
                SessionUpdate {
                    token: Some(format!("ordinary-session-{suffix}")),
                    ..Default::default()
                },
                None,
            )
            .await?;
        for index in 0..3 {
            let _ = store
                .create_account(CreateAccount {
                    id: format!("account-{suffix}-{index}").into(),
                    user_id: format!("user-{suffix}").into(),
                    provider_id: "ordinary-provider".into(),
                    account_id: format!("ordinary-{suffix}-{index}").into(),
                    additional_fields: [(
                        "displayLabel".into(),
                        format!("{label}-label-{index}").into(),
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })
                .await?;
        }
    }
    Ok(())
}

fn user(user: &UserView) -> Value {
    json!({ "name": user.name, "image": user.image })
}
fn session(session: &SessionView, owner: &UserView) -> Value {
    let fields: FieldMap = session.clone().into();
    let fields = fields.json().unwrap();
    json!({ "userAgent": fields["userAgent"], "user": user(owner) })
}
async fn query(store: &EphemeralStore, path: &str) -> AuthResult<Value> {
    Ok(match path {
        "session" => {
            let (row, data) = store
                .get_session_snapshot("ordinary-session-a")
                .await?
                .unwrap();
            let owner = match data {
                Some(data) => data.into_typed()?.unwrap().user,
                None => store.get_user_by_id(row.user_id.typed()?).await?.unwrap(),
            };
            session(&row, &owner)
        }
        "sessions" => {
            let tokens = ["c", "b", "a"].map(|suffix| format!("ordinary-session-{suffix}"));
            let mut results = Vec::new();
            for (row, data) in store.get_session_snapshots(&tokens, false).await? {
                let owner = match data {
                    Some(data) => data.into_typed()?.unwrap().user,
                    None => store.get_user_by_id(row.user_id.typed()?).await?.unwrap(),
                };
                results.push(session(&row, &owner));
            }
            json!(results)
        }
        "owner" => {
            let owner = store
                .get_account_owner("ordinary-provider", "ordinary-a-0")
                .await?
                .unwrap();
            let JoinValue::One(owner_user) = owner.user else {
                return Err(AuthError::internal("Expected a single Account owner"));
            };
            json!({ "kind": "owned", "displayLabel": owner.account.additional_fields["displayLabel"].json()?, "user": user(owner_user.as_ref().unwrap()) })
        }
        "accounts" => {
            let joined = store
                .get_user_with_accounts("A@ordinary-native-join.test")
                .await?
                .unwrap();
            let JoinValue::Many(accounts) = joined.accounts else {
                return Err(AuthError::internal(
                    "Expected the Account relationship page",
                ));
            };
            json!({ "user": user(&joined.user), "accounts": accounts.iter().map(|account| account.additional_fields["displayLabel"].json()).collect::<AuthResult<Vec<_>>>()? })
        }
        _ => return Err(AuthError::internal("unknown normal join fixture path")),
    })
}

#[tokio::test]
async fn memory_native_and_fallback_core_reads_match_pinned_normal_contracts() -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-core-joins-1.7.6.json"))?;
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "memory" && case["path"] != "page")
    {
        let trace = Arc::new(Trace::default());
        let store = configured(case, &trace);
        seed(&store).await?;
        trace.enabled.store(true, Ordering::SeqCst);
        let path = case["path"].as_str().unwrap();
        let pending = query(&store, path);
        let outcome = if case["mode"] == "parent-wait" {
            let controller = async {
                trace.first_started.notified().await;
                trace.second_finished.notified().await;
                trace.event("controller", &json!("second-child-finished"));
                trace.release_first.notify_one();
            };
            let (result, ()) = tokio::join!(pending, controller);
            result
        } else {
            pending.await
        };
        trace.enabled.store(false, Ordering::SeqCst);
        match outcome {
            Ok(result) => {
                assert_eq!(result, case["result"], "{case}");
                assert_eq!(case["originalError"], false);
            }
            Err(AuthError::Upstream {
                status,
                code,
                message,
            }) => {
                assert_eq!(status, 400);
                assert_eq!(
                    json!({"status":"BAD_REQUEST", "code":code,"message":message}),
                    case["error"],
                    "{case}"
                );
                assert_eq!(case["originalError"], true);
            }
            Err(error) => return Err(error),
        }
        assert_eq!(
            json!(*trace.events.lock().unwrap()),
            case["events"],
            "{case}"
        );
        let mut stored_users = Vec::new();
        let mut stored_accounts = Vec::new();
        for suffix in ["a", "b", "c"] {
            stored_users.push(user(
                &store
                    .get_user_by_id(&format!("user-{suffix}"))
                    .await?
                    .unwrap(),
            ));
            for index in 0..3 {
                let account = store
                    .get_account("ordinary-provider", &format!("ordinary-{suffix}-{index}"))
                    .await?
                    .unwrap();
                stored_accounts.push(account.additional_fields["displayLabel"].json()?);
            }
        }
        assert_eq!(
            json!({"users":stored_users,"accounts":stored_accounts}),
            case["stored"],
            "{case}"
        );
        *trace.store.lock().unwrap() = None;
        count += 1;
    }
    assert_eq!(count, 28);
    Ok(())
}

#[tokio::test]
async fn native_user_child_reads_unconfigured_image_after_name_callback() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/native-memory-live-fields-1.7.6.json"
    ))?;
    for case in fixture["cases"].as_array().unwrap() {
        let path = case["path"].as_str().unwrap();
        let trace = Arc::new(Trace::default());
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(true);
        let _ = config
            .user
            .fields_mut()
            .insert("name".into(), field(&trace, path, "live", "name", "name"));
        let store = Arc::new(EphemeralStore::new(Arc::new(config)));
        *trace.store.lock().unwrap() = Some(store.clone());
        let _ = store
            .create_user(CreateUser {
                id: Some("ordinary-user".into()),
                name: Some("ordinary-name".into()).into(),
                image: Some("image-before".into()).into(),
                email: Some("ordinary@memory-join.test".into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
        let row = store
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
        trace.enabled.store(true, Ordering::SeqCst);
        let output = if path == "session" {
            store
                .get_session_snapshot(&row.token)
                .await?
                .unwrap()
                .1
                .unwrap()
                .into_typed()?
                .unwrap()
                .user
        } else {
            let owner = store
                .get_account_owner("ordinary-provider", "ordinary-account")
                .await?
                .unwrap();
            let JoinValue::One(owner_user) = owner.user else {
                return Err(AuthError::internal("Expected a single Account owner"));
            };
            owner_user.unwrap()
        };
        trace.enabled.store(false, Ordering::SeqCst);
        let stored = store.get_user_by_id("ordinary-user").await?.unwrap();
        assert_eq!(
            json!({"path":path,"events":*trace.events.lock().unwrap(),"result":user(&output),"stored":user(&stored)}),
            *case
        );
        *trace.store.lock().unwrap() = None;
    }
    Ok(())
}

#[tokio::test]
async fn memory_child_limits_keep_native_count_loop_and_fallback_slice() -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-core-join-limits-1.7.6.json"))?;
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "memory")
    {
        let limit = match case["limitKind"].as_str().unwrap() {
            "half" => 0.5,
            "oneAndHalf" => 1.5,
            "negativeOne" => -1.0,
            "nan" => f64::NAN,
            "positiveInfinity" => f64::INFINITY,
            "negativeInfinity" => f64::NEG_INFINITY,
            _ => return Err(AuthError::internal("unknown captured limit kind")),
        };
        let observed = &case["observation"];
        let trace = Arc::new(Trace::default());
        let store = configured_with_limit(observed, &trace, Some(limit));
        seed(&store).await?;
        trace.enabled.store(true, Ordering::SeqCst);
        let result = query(&store, "accounts").await?;
        trace.enabled.store(false, Ordering::SeqCst);
        assert_eq!(result, observed["result"], "{case}");
        assert_eq!(
            json!(*trace.events.lock().unwrap()),
            observed["events"],
            "{case}"
        );
        *trace.store.lock().unwrap() = None;
        count += 1;
    }
    assert_eq!(count, 12);
    Ok(())
}
