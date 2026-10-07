#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The pinned ordinary-data contract requires exact fixture shapes and controlled callback channels."
)]
#![allow(
    unreachable_pub,
    reason = "SeaORM fixture derives require public entity types"
)]

#[path = "native_core_join_tests/account.rs"]
mod account;
#[path = "native_core_join_tests/postgres.rs"]
mod postgres;

use better_auth_core::{
    AuthConfig, AuthError, AuthResponse, AuthResult, AuthSchema, CreateAccount, CreateSession,
    CreateUser, UpdateAccount, UpdateUser,
    store::{AccountStore, SessionStore, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::{SessionView, UserView},
};
use better_auth_seaorm::{
    SeaOrmSessionModel, SeaOrmStore,
    sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder,
        Schema,
    },
    store::entities,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot};

struct AppSchema;
impl AuthSchema for AppSchema {
    type User = entities::user::Model;
    type Session = entities::session::Model;
    type Account = account::Model;
    type Verification = entities::verification::Model;
}
type Store = SeaOrmStore<AppSchema>;

struct State {
    enabled: AtomicBool,
    nested: AtomicBool,
    changed: AtomicBool,
    events: Mutex<Vec<Value>>,
    gate: Mutex<Option<oneshot::Receiver<()>>>,
    started: mpsc::UnboundedSender<()>,
    finished: mpsc::UnboundedSender<()>,
    store: Mutex<Weak<Store>>,
}
impl State {
    fn event(&self, field: &str, value: &str) {
        self.events.lock().unwrap().push(json!([field, value]));
    }
}

fn failure() -> AuthError {
    AuthResponse::json(
        400,
        &json!({
            "code":"ORDINARY_DISPLAY_FAILURE", "message":"Ordinary display callback failed"
        }),
    )
    .unwrap()
    .with_header("x-ordinary-error", "original")
    .into()
}

fn field(state: &Arc<State>, path: &str, mode: &str, name: &'static str) -> UserFieldConfig {
    let (state, path, mode) = (state.clone(), path.to_owned(), mode.to_owned());
    let parent = match path.as_str() {
        "accounts" => "user.name",
        "owner" => "account.displayLabel",
        _ => "session.userAgent",
    };
    let output = if name == parent && matches!(mode.as_str(), "parent-read" | "parent-wait") {
        UserFieldTransform::new_async(move |value| {
            let (state, path, mode) = (state.clone(), path.clone(), mode.clone());
            async move {
                if !state.enabled.load(Ordering::Relaxed) || state.nested.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = value.as_str().unwrap().to_owned();
                state.event(name, &text);
                if mode == "parent-wait" && text == "A-agent" {
                    let gate = state.gate.lock().unwrap().take().unwrap();
                    state.started.send(()).unwrap();
                    gate.await
                        .map_err(|_| AuthError::internal("Ordinary display gate closed"))?;
                }
                if mode == "parent-read" && !state.changed.swap(true, Ordering::Relaxed) {
                    state.nested.store(true, Ordering::Relaxed);
                    let store = state.store.lock().unwrap().upgrade().unwrap();
                    let result = if path == "accounts" {
                        store
                            .update_account(
                                "account-a-0",
                                UpdateAccount {
                                    additional_fields: [(
                                        "displayLabel".into(),
                                        "A-label-0-after".into(),
                                    )]
                                    .into_iter()
                                    .collect(),
                                    ..Default::default()
                                },
                            )
                            .await
                            .map(|_| "A-label-0-after")
                    } else {
                        store
                            .update_user(
                                "user-a",
                                UpdateUser {
                                    name: Some("A-after".to_owned()).into(),
                                    ..Default::default()
                                },
                            )
                            .await
                            .map(|_| "A-after")
                    };
                    state.nested.store(false, Ordering::Relaxed);
                    state.event("display-write", result?);
                }
                Ok(format!("{text}-visible").into())
            }
        })
    } else {
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) || state.nested.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = value.as_str().unwrap();
            state.event(name, text);
            if (mode == "parent-error" && name == parent && text == "A-agent")
                || (mode == "child-error" && name == "account.displayLabel" && text == "A-label-0")
            {
                return Err(failure());
            }
            if name == "user.image" && text == "B-image" {
                state.finished.send(()).unwrap();
            }
            Ok(format!("{text}-visible").into())
        })
    };
    UserFieldConfig {
        required: Some(false),
        field_name: (name == "account.displayLabel").then(|| "label_value".into()),
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn create_tables(db: &DatabaseConnection) {
    let schema = Schema::new(db.get_database_backend());
    for statement in [
        schema.create_table_from_entity(entities::user::Entity),
        schema.create_table_from_entity(entities::session::Entity),
        schema.create_table_from_entity(account::Entity),
        schema.create_table_from_entity(entities::verification::Entity),
    ] {
        let _ = db.execute(&statement).await.unwrap();
    }
}

async fn seed(store: &Store, labels: &[&str], account_count: usize) {
    let now = "2025-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    let expires_at = "2099-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    for &label in labels {
        let suffix = label.to_lowercase();
        let user = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                created_at: Some(now.into()),
                updated_at: Some(now.into()),
                image: Some(format!("{label}-image")).into(),
                email_verified: Some(true),
                ..CreateUser::new()
                    .with_name(label)
                    .with_email(format!("{suffix}@ordinary-native-join.test"))
            })
            .await
            .unwrap();
        // The public session constructor generates tokens. Seed fixed ordinary rows to match the oracle's query order.
        let mut session = entities::session::Model::new_active(
            Some(format!("session-{suffix}")),
            format!("ordinary-session-{suffix}"),
            CreateSession {
                user_id: user.id.clone(),
                expires_at: expires_at.into(),
                ip_address: None,
                user_agent: Some(format!("{label}-agent")),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: Default::default(),
            },
            now,
        )
        .unwrap();
        entities::session::Model::set_expires_at(&mut session, expires_at);
        let _ = session.insert(store.connection()).await.unwrap();
        for index in 0..account_count {
            let _ = store
                .create_account(CreateAccount {
                    id: format!("account-{suffix}-{index}").into(),
                    account_id: format!("ordinary-{suffix}-{index}").into(),
                    provider_id: "ordinary-provider".into(),
                    user_id: user.id.clone(),
                    created_at: now.into(),
                    updated_at: now.into(),
                    additional_fields: [(
                        "displayLabel".into(),
                        format!("{label}-label-{index}").into(),
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }
}

fn display_user(user: &UserView) -> Value {
    json!({"name":user.name, "image":user.image})
}
fn display_session(session: &SessionView, user: &UserView) -> Value {
    let session = serde_json::to_value(session).unwrap();
    json!({"userAgent":session["userAgent"], "user":display_user(user)})
}
async fn query(store: &Store, path: &str) -> AuthResult<Value> {
    match path {
        "session" => {
            let Some((session, data)) = store.get_session_snapshot("ordinary-session-a").await?
            else {
                return Ok(Value::Null);
            };
            let user = match data {
                Some(data) => data.user,
                None => store.get_user_by_id_field(&session.user_id).await?.unwrap(),
            };
            Ok(display_session(&session, &user))
        }
        "sessions" => {
            let mut result = Vec::new();
            for (session, data) in store
                .get_session_snapshots(
                    &[
                        "ordinary-session-c".into(),
                        "ordinary-session-b".into(),
                        "ordinary-session-a".into(),
                    ],
                    false,
                )
                .await?
            {
                let user = match data {
                    Some(data) => data.user,
                    None => store.get_user_by_id_field(&session.user_id).await?.unwrap(),
                };
                result.push(display_session(&session, &user));
            }
            Ok(json!(result))
        }
        "owner" => {
            let owner = store
                .get_account_owner("ordinary-provider", "ordinary-a-0")
                .await?
                .unwrap();
            Ok(
                json!({"kind":"owned", "displayLabel":owner.account.additional_fields["displayLabel"].json()?,
                "user":owner.user.as_ref().map(display_user)}),
            )
        }
        _ => {
            let row = store
                .get_user_with_accounts("A@ordinary-native-join.test")
                .await?
                .unwrap();
            Ok(
                json!({"user":display_user(&row.user), "accounts":row.accounts.into_iter()
                .map(|account| account.additional_fields["displayLabel"].json()).collect::<AuthResult<Vec<_>>>()?}),
            )
        }
    }
}

struct Case {
    store: Arc<Store>,
    state: Arc<State>,
    started: mpsc::UnboundedReceiver<()>,
    finished: mpsc::UnboundedReceiver<()>,
    release: oneshot::Sender<()>,
}
impl Case {
    fn new(db: DatabaseConnection, fixture: &Value, limit: Option<f64>) -> Self {
        let path = fixture["path"].as_str().unwrap();
        let mode = fixture["mode"].as_str().unwrap();
        let (start, started) = mpsc::unbounded_channel();
        let (finish, finished) = mpsc::unbounded_channel();
        let (release, gate) = oneshot::channel();
        let state = Arc::new(State {
            enabled: AtomicBool::new(false),
            nested: AtomicBool::new(false),
            changed: AtomicBool::new(false),
            events: Mutex::default(),
            gate: Mutex::new(Some(gate)),
            started: start,
            finished: finish,
            store: Mutex::new(Weak::new()),
        });
        let mut config = AuthConfig::default();
        config.advanced.database.joins = fixture["joins"].as_bool();
        config.advanced.database.default_find_many_limit = limit;
        config.user.fields_mut().extend([
            ("name".into(), field(&state, path, mode, "user.name")),
            ("image".into(), field(&state, path, mode, "user.image")),
        ]);
        let _ = config.session.fields_mut().insert(
            "userAgent".into(),
            field(&state, path, mode, "session.userAgent"),
        );
        let _ = config.account.additional_fields.insert(
            "displayLabel".into(),
            field(&state, path, mode, "account.displayLabel"),
        );
        let store = Arc::new(Store::new(config, db));
        *state.store.lock().unwrap() = Arc::downgrade(&store);
        Self {
            store,
            state,
            started,
            finished,
            release,
        }
    }
}

async fn check_case(db: DatabaseConnection, fixture: &Value, limit: Option<f64>) {
    let path = fixture["path"].as_str().unwrap();
    let mode = fixture["mode"].as_str().unwrap();
    let Case {
        store,
        state,
        mut started,
        mut finished,
        release,
    } = Case::new(db, fixture, limit);
    seed(&store, &["A", "B", "C"], 3).await;
    state.enabled.store(true, Ordering::Relaxed);
    let controller = async {
        if mode == "parent-wait" {
            started.recv().await.unwrap();
            finished.recv().await.unwrap();
            state.event("controller", "second-child-finished");
            release.send(()).unwrap();
        }
    };
    let (result, ()) = tokio::join!(query(&store, path), controller);
    match result {
        Ok(result) => {
            assert_eq!(result, fixture["result"], "{fixture}");
            assert_eq!(fixture["originalError"], false);
        }
        Err(error) => {
            assert!(matches!(error, AuthError::Response(_)), "{error:?}");
            let response = error.to_auth_response();
            assert_eq!(response.status, 400);
            assert_eq!(
                response.headers.get("x-ordinary-error").map(String::as_str),
                Some("original")
            );
            let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            assert_eq!(
                json!({"status":"BAD_REQUEST", "code":body["code"], "message":body["message"]}),
                fixture["error"]
            );
            assert_eq!(fixture["originalError"], true);
        }
    }
    assert_eq!(
        json!(*state.events.lock().unwrap()),
        fixture["events"],
        "{fixture}"
    );
    let users = entities::user::Entity::find()
        .order_by_asc(entities::user::Column::Email)
        .all(store.connection())
        .await
        .unwrap();
    let accounts = account::Entity::find()
        .order_by_asc(account::Column::AccountId)
        .all(store.connection())
        .await
        .unwrap();
    assert_eq!(
        json!({
            "users":users.into_iter().map(|user| json!({"name":user.name,"image":user.image})).collect::<Vec<_>>(),
            "accounts":accounts.into_iter().map(|account| account.display_label).collect::<Vec<_>>()
        }),
        fixture["stored"]
    );
}

#[tokio::test]
async fn sqlite_core_joins_match_pinned_display_callbacks_and_snapshots() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-core-joins-1.7.6.json")).unwrap();
    for row in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "sqlite" && row["path"] != "page")
    {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        create_tables(&db).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case(db, row, row["limit"].as_f64()),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sqlite_native_child_caps_match_pinned_numeric_configuration() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-core-join-limits-1.7.6.json")).unwrap();
    for row in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "sqlite" && row["joins"] == true)
    {
        let limit = match row["limitKind"].as_str().unwrap() {
            "half" => 0.5,
            "oneAndHalf" => 1.5,
            "negativeOne" => -1.0,
            "nan" => f64::NAN,
            "positiveInfinity" => f64::INFINITY,
            "negativeInfinity" => f64::NEG_INFINITY,
            value => unreachable!("Unknown captured limit kind: {value}"),
        };
        let db = Database::connect("sqlite::memory:").await.unwrap();
        create_tables(&db).await;
        check_case(db, &row["observation"], Some(limit)).await;
    }
}

async fn check_optional_account(db: DatabaseConnection) {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(true);
    let store = Store::new(config, db);
    let _ = store
        .create_user(
            CreateUser::new()
                .with_name("No accounts")
                .with_email("no-accounts@ordinary-native-join.test"),
        )
        .await
        .unwrap();
    let row = store
        .get_user_with_accounts("no-accounts@ordinary-native-join.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.user.name.json().unwrap(), Some(json!("No accounts")));
    assert!(row.accounts.is_empty());
}

#[tokio::test]
async fn sqlite_native_join_preserves_a_user_without_accounts() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    create_tables(&db).await;
    check_optional_account(db).await;
}
