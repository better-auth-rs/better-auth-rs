#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin,
    endpoint_context::{EndpointContext, OwnedEndpointContext},
    password_management::PasswordManagementCallbacks,
    phone_number::{PhoneNumberCallbacks, PhoneNumberPlugin},
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::background::{BackgroundFuture, BackgroundTask, BackgroundTasks};
use better_auth_core::observability::{LogArgument, LogLevel, LogSink};
use better_auth_core::{AuthRequest, HttpMethod, PasswordHasher};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    gate: Notify,
    entered: Notify,
    finished: Notify,
    response_done: AtomicBool,
    events: Mutex<Vec<String>>,
    contexts: Mutex<Vec<Value>>,
    logs: Mutex<Vec<Value>>,
    tasks: Mutex<Vec<BackgroundTask>>,
}
impl State {
    fn event(&self, name: &str) {
        self.events.lock().unwrap().push(name.to_owned());
    }
    fn capture<S: AuthSchema>(&self, phase: &str, context: &EndpointContext<'_, S>) {
        let current = better_auth_core::hooks::current_request_hook_context().unwrap();
        assert_eq!(current.path.as_deref(), context.path);
        assert_eq!(current.body.as_ref(), Some(&context.body));
        self.contexts.lock().unwrap().push(json!({
            "phase":phase,"path":context.path,"body":context.body,
            "request":context.request.is_some(),
            "requestURL":context.request.and_then(AuthRequest::url).map(ToString::to_string),
            "baseURL":context.auth.base_url(),
        }));
    }
    fn sender<S: AuthSchema>(
        self: &Arc<Self>,
        sender: &'static str,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<BackgroundFuture>> {
        self.event("sender:start");
        self.capture("start", endpoint);
        self.entered.notify_one();
        if sender == "sync-throw" {
            self.finished.notify_one();
            return Err(AuthError::internal("sender-sync"));
        }
        if sender == "void" {
            self.event("sender:void");
            self.finished.notify_one();
            return Ok(None);
        }
        let state = self.clone();
        let endpoint: OwnedEndpointContext<S> = endpoint.to_owned();
        Ok(Some(Box::pin(async move {
            state.gate.notified().await;
            state.capture("released", &endpoint.as_endpoint());
            state.event("sender:released");
            state.finished.notify_one();
            if sender == "reject" {
                return Err(AuthError::internal("sender-async"));
            }
            Ok(())
        })))
    }
}
impl LogSink for State {
    fn log(&self, _: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        let message = message.to_string();
        if !message.starts_with("Failed to run background task") {
            return;
        }
        let error = arguments.first().map(|argument| match argument {
            LogArgument::Error(error) => {
                // Compare the application message, excluding AuthError's Display variant label.
                let display = error.to_string();
                display
                    .strip_prefix("Internal server error: ")
                    .unwrap_or(&display)
                    .to_owned()
            }
            argument => argument.to_string(),
        });
        self.event(&format!("log:{}", error.as_deref().unwrap_or("unknown")));
        self.logs
            .lock()
            .unwrap()
            .push(json!({"message":message,"error":error}));
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
        other => other.to_string(),
    }
}
async fn count(db: &DatabaseConnection) -> i64 {
    db.query_one_raw(Statement::from_string(
        DbBackend::Sqlite,
        "SELECT COUNT(*) AS count FROM verifications".to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "count")
    .unwrap()
}
async fn operation(auth: &BetterAuth<BundledSchema>, endpoint: &str, transport: &str) -> Value {
    let (path, body) = if endpoint == "reset" {
        (
            "/request-password-reset",
            json!({"email":"background@example.com","unknown":"input"}),
        )
    } else {
        (
            "/phone-number/send-otp",
            json!({"phoneNumber":"+15550000001","unknown":"input"}),
        )
    };
    let result = if transport == "http" {
        auth.handle_request(
            AuthRequest::from_parts(
                HttpMethod::Post,
                format!("/api/auth{path}"),
                [("content-type".into(), "application/json".into())].into(),
                Some(serde_json::to_vec(&body).unwrap()),
                None,
            )
            .with_url(
                format!("http://localhost:3000/api/auth{path}")
                    .parse()
                    .unwrap(),
            ),
        )
        .await
    } else {
        auth.call_endpoint(
            HttpMethod::Post,
            path,
            EndpointInput {
                body: Some(body),
                ..Default::default()
            },
        )
        .await
    };
    match result {
        Ok(response) => {
            json!({"status":response.status,"thrown":null,"body":String::from_utf8(response.body.into_bytes().unwrap()).unwrap()})
        }
        Err(error) => json!({"status":null,"thrown":message(error),"body":null}),
    }
}
async fn run(
    endpoint: &'static str,
    transport: &'static str,
    scheduling: &'static str,
    sender: &'static str,
) -> Value {
    let state = Arc::new(State::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let mut config = AuthConfig::new("background-contract-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000");
    config.logger.level = Some(LogLevel::Error);
    config.logger.log = Some(state.clone());
    if scheduling != "default" {
        let state = state.clone();
        config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
            state.event("handler:received");
            state.tasks.lock().unwrap().push(task);
            if scheduling == "handler-throw" {
                return Err(AuthError::internal("handler-sync"));
            }
            Ok(())
        }));
    }
    let reset = state.clone();
    let phone = state.clone();
    let auth = Arc::new(
        AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .plugin(
                PasswordManagementPlugin::new().callbacks(PasswordManagementCallbacks::<
                    BundledSchema,
                >::send_reset_password(
                    move |_, endpoint| reset.sender(sender, endpoint),
                )),
            )
            .plugin(
                PhoneNumberPlugin::new().callbacks(
                    PhoneNumberCallbacks::<BundledSchema>::default()
                        .send_otp(move |_, endpoint| phone.sender(sender, endpoint)),
                ),
            )
            .build()
            .await
            .unwrap(),
    );
    let signup = auth.call_endpoint(HttpMethod::Post,"/sign-up/email",EndpointInput {
        body:Some(json!({"name":"Background","email":"background@example.com","password":"fixture-password"})),..Default::default()
    }).await.unwrap();
    assert_eq!(signup.status, 200);
    let response_state = state.clone();
    let response_auth = auth.clone();
    let mut response = tokio::spawn(async move {
        let result = operation(&response_auth, endpoint, transport).await;
        response_state.response_done.store(true, Ordering::SeqCst);
        response_state.event("response");
        result
    });
    tokio::select! {
        biased;
        _ = state.entered.notified() => {},
        result = &mut response => panic!("response completed without sender: {result:?}"),
    }
    let before = count(&db).await;
    let asynchronous = sender == "resolve" || sender == "reject";
    let mut response = Some(response);
    let early = if !asynchronous || scheduling != "default" {
        Some(response.take().unwrap().await.unwrap())
    } else {
        None
    };
    let responded_before = state.response_done.load(Ordering::SeqCst);
    state.event("gate:release");
    state.gate.notify_one();
    let outcome = match early {
        Some(value) => value,
        None => response.take().unwrap().await.unwrap(),
    };
    state.finished.notified().await;
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    let mut task_states = Vec::new();
    for task in tasks {
        task.await.unwrap();
        task_states.push("fulfilled");
    }
    let after = count(&db).await;
    json!({"endpoint":endpoint,"transport":transport,"scheduling":scheduling,"sender":sender,
        "respondedBeforeRelease":responded_before,"storedBeforeRelease":before,"storedAfterResponse":after,
        "outcome":outcome,"events":*state.events.lock().unwrap(),"logs":*state.logs.lock().unwrap(),
        "contexts":*state.contexts.lock().unwrap(),"taskStates":task_states})
}
#[tokio::test]
async fn sqlite_notification_scheduling_matches_pinned_upstream() {
    let upstream: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-notification-upstream.json"
    ))
    .unwrap();
    for endpoint in ["reset", "phone"] {
        for transport in ["http", "native"] {
            for scheduling in ["default", "handler", "handler-throw"] {
                for sender in ["resolve", "reject", "sync-throw", "void"] {
                    let actual = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        run(endpoint, transport, scheduling, sender),
                    )
                    .await
                    .unwrap();
                    if let Ok(directory) = std::env::var("BACKGROUND_NOTIFICATION_RESULTS") {
                        std::fs::create_dir_all(&directory).unwrap();
                        std::fs::write(
                            std::path::Path::new(&directory)
                                .join(format!("{endpoint}-{transport}-{scheduling}-{sender}.json")),
                            serde_json::to_vec_pretty(&actual).unwrap(),
                        )
                        .unwrap();
                    }
                    let mut expected = upstream
                        .iter()
                        .find(|value| {
                            value["endpoint"] == endpoint
                                && value["transport"] == transport
                                && value["scheduling"] == scheduling
                                && value["sender"] == sender
                        })
                        .unwrap()
                        .clone();
                    // JS object identity is diagnostic. Compare every event and the retained
                    // endpoint path, validated body, original Request, URL and base URL.
                    for context in expected
                        .get_mut("contexts")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                    {
                        let _ = context.as_object_mut().unwrap().remove("sameContext");
                        let _ = context.as_object_mut().unwrap().remove("sameRequest");
                    }
                    assert_eq!(
                        actual, expected,
                        "{endpoint}/{transport}/{scheduling}/{sender}"
                    );
                }
            }
        }
    }
}
