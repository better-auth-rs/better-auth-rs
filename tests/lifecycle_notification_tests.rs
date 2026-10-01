#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use async_trait::async_trait;
use base64::Engine;
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, UserManagementPlugin,
    email_verification::{EmailVerificationCallbacks, VerificationEmail},
    endpoint_context::EndpointContext,
    user_management::UserManagementCallbacks,
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

const SECRET: &str = "lifecycle-notification-contract-secret-thirty-two-characters";
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
    fn event(&self, event: &str) {
        self.events.lock().unwrap().push(event.into());
    }
    fn capture<S: AuthSchema>(
        &self,
        phase: &str,
        message: &VerificationEmail,
        new_email: Option<&str>,
        endpoint: &EndpointContext<'_, S>,
    ) {
        let token = if endpoint.path == Some("/delete-user") {
            Value::Null
        } else {
            let part = message.token.split('.').nth(1).unwrap();
            let payload: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .unwrap(),
            )
            .unwrap();
            json!({"email":payload.get("email"),"updateTo":payload.get("updateTo"),"requestType":payload.get("requestType")})
        };
        let url: url::Url = message.url.parse().unwrap();
        self.contexts.lock().unwrap().push(json!({
            "phase":phase,"path":endpoint.path,"body":endpoint.body,
            "request":endpoint.request.is_some(),"requestPath":endpoint.request.and_then(AuthRequest::url).map(url::Url::path),
            "email":message.user.email,"verified":message.user.email_verified,"newEmail":new_email,
            "token":token,"urlPath":url.path(),"callbackURL":url.query_pairs().find(|(key,_)| key == "callbackURL").map(|(_,value)|value.into_owned()),
        }));
    }
    fn sender<S: AuthSchema>(
        self: &Arc<Self>,
        sender: &'static str,
        message: &VerificationEmail,
        new_email: Option<&str>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<BackgroundFuture>> {
        self.event("sender:start");
        self.capture("start", message, new_email, endpoint);
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
        let message = message.clone();
        let new_email = new_email.map(str::to_owned);
        let endpoint = endpoint.to_owned();
        Ok(Some(Box::pin(async move {
            state.gate.notified().await;
            state.capture(
                "released",
                &message,
                new_email.as_deref(),
                &endpoint.as_endpoint(),
            );
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
        let error = arguments.first().map(|argument| {
            let display = argument.to_string();
            display
                .strip_prefix("Internal server error: ")
                .unwrap_or(&display)
                .to_owned()
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
async fn snapshot(db: &DatabaseConnection) -> Value {
    let row = db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
        "SELECT email,email_verified,(SELECT COUNT(*) FROM verifications) AS verifications FROM users".to_owned()))
        .await.unwrap().unwrap();
    json!({"email":row.try_get::<String>("","email").unwrap(),"verified":row.try_get::<bool>("","email_verified").unwrap(),
        "verifications":row.try_get::<i64>("","verifications").unwrap()})
}
async fn operation(
    auth: &BetterAuth<BundledSchema>,
    endpoint: &str,
    transport: &str,
    cookie: String,
) -> Value {
    let mut path = "/change-email";
    let mut method = HttpMethod::Post;
    let mut body = Some(json!({"newEmail":"new@example.com","unknown":"drop"}));
    let mut query = std::collections::HashMap::new();
    if endpoint.starts_with("verify-") {
        path = "/verify-email";
        method = HttpMethod::Get;
        body = None;
        let mut payload = json!({"email":"old@example.com","updateTo":"new@example.com","iat":chrono::Utc::now().timestamp(),"exp":chrono::Utc::now().timestamp()+3600});
        if endpoint == "verify-confirm" {
            let _ = payload
                .as_object_mut()
                .unwrap()
                .insert("requestType".into(), json!("change-email-confirmation"));
        }
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &payload,
            &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        let _ = query.insert("token".to_owned(), token);
    } else if endpoint == "direct" {
        path = "/send-verification-email";
        body = Some(json!({"email":"old@example.com","unknown":"drop"}));
    } else if endpoint == "delete" {
        path = "/delete-user";
        body = Some(json!({"unknown":"drop"}));
    }
    let headers = [
        ("cookie".into(), cookie),
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://localhost:3000".into()),
    ]
    .into();
    let result = if transport == "http" {
        let mut url: url::Url = format!("http://localhost:3000/api/auth{path}")
            .parse()
            .unwrap();
        if !query.is_empty() {
            let _ = url.query_pairs_mut().extend_pairs(&query);
        }
        let mut request = AuthRequest::from_parts(
            method,
            format!("/api/auth{path}"),
            headers,
            body.map(|body| serde_json::to_vec(&body).unwrap()),
            None,
        )
        .with_url(url);
        request.query = Some(json!(query));
        auth.handle_request(request).await
    } else {
        auth.call_endpoint(
            method,
            path,
            EndpointInput {
                body,
                headers: Some(headers),
                query: Some(json!(query)),
                ..Default::default()
            },
        )
        .await
    };
    match result {
        Ok(response) => {
            json!({"status":response.status,"thrown":null,"cookie":response.headers.get_all("set-cookie").any(|value|value.starts_with("better-auth.session_token="))})
        }
        Err(error) => {
            json!({"status":null,"thrown":match error {AuthError::Internal(message)=>message,other=>other.to_string()},"cookie":false})
        }
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
    let mut config = AuthConfig::new(SECRET).base_url("http://localhost:3000");
    config.logger.level = LogLevel::Error;
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
    let verification = state.clone();
    let deletion = state.clone();
    let confirmation = state.clone();
    let mut callbacks = UserManagementCallbacks::<BundledSchema>::new()
        .delete_account_verification(move |message, endpoint| {
            deletion.sender(sender, message, None, endpoint)
        });
    if endpoint == "change-confirm" {
        callbacks = callbacks.change_email_confirmation(move |message, endpoint| {
            confirmation.sender(
                sender,
                &VerificationEmail {
                    user: message.user.clone(),
                    url: message.url.clone(),
                    token: message.token.clone(),
                },
                Some(&message.new_email),
                endpoint,
            )
        });
    }
    let auth = Arc::new(
        AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: false,
                ..Default::default()
            })
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .plugin(
                EmailVerificationPlugin::new()
                    .send_on_sign_up(false)
                    .callbacks(EmailVerificationCallbacks::<BundledSchema>::send(
                        move |message, endpoint| {
                            verification.sender(sender, message, None, endpoint)
                        },
                    )),
            )
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .update_without_verification(endpoint == "change-update")
                    .delete_user_enabled(true)
                    .callbacks(callbacks),
            )
            .build()
            .await
            .unwrap(),
    );
    let signup = auth.call_endpoint(HttpMethod::Post,"/sign-up/email",EndpointInput {
        body:Some(json!({"name":"Lifecycle","email":"old@example.com","password":"fixture-password"})),..Default::default()
    }).await.unwrap();
    assert_eq!(signup.status, 200);
    let cookie = signup
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let _ = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE users SET email_verified = ?",
            [(endpoint == "change-confirm").into()],
        ))
        .await
        .unwrap();
    let response_state = state.clone();
    let mut response = tokio::spawn(async move {
        let result = operation(&auth, endpoint, transport, cookie).await;
        response_state.response_done.store(true, Ordering::SeqCst);
        response_state.event("response");
        result
    });
    tokio::select! { biased; _ = state.entered.notified() => {}, result = &mut response => panic!("response completed without sender: {result:?}") }
    let before = snapshot(&db).await;
    let asynchronous = sender == "resolve" || sender == "reject";
    let scheduled = asynchronous && scheduling != "default" && endpoint != "direct";
    let mut response = Some(response);
    let early = if !asynchronous || scheduled {
        Some(response.take().unwrap().await.unwrap())
    } else {
        None
    };
    let responded_before = state.response_done.load(Ordering::SeqCst);
    state.event("gate:release");
    state.gate.notify_one();
    let outcome = match early {
        Some(outcome) => outcome,
        None => response.take().unwrap().await.unwrap(),
    };
    state.finished.notified().await;
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    let mut task_states = Vec::new();
    for task in tasks {
        task.await.unwrap();
        task_states.push("fulfilled");
    }
    let after = snapshot(&db).await;
    json!({"endpoint":endpoint,"transport":transport,"scheduling":scheduling,"sender":sender,
        "respondedBeforeRelease":responded_before,"storedBeforeRelease":before,"storedAfterResponse":after,
        "outcome":outcome,"events":*state.events.lock().unwrap(),"logs":*state.logs.lock().unwrap(),
        "contexts":*state.contexts.lock().unwrap(),"taskStates":task_states})
}

#[tokio::test]
async fn sqlite_lifecycle_notifications_match_pinned_upstream() {
    let upstream: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/lifecycle-notifications-upstream.json"
    ))
    .unwrap();
    for endpoint in [
        "change-update",
        "change-confirm",
        "change-verify",
        "verify-confirm",
        "verify-legacy",
        "direct",
        "delete",
    ] {
        for transport in ["http", "native"] {
            for (scheduling, sender) in [
                ("default", "resolve"),
                ("default", "reject"),
                ("handler", "resolve"),
                ("handler", "reject"),
                ("handler", "sync-throw"),
                ("handler", "void"),
                ("handler-throw", "reject"),
            ] {
                let actual = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    run(endpoint, transport, scheduling, sender),
                )
                .await
                .unwrap();
                if let Ok(directory) = std::env::var("LIFECYCLE_NOTIFICATION_RESULTS") {
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(
                        std::path::Path::new(&directory)
                            .join(format!("{endpoint}-{transport}-{scheduling}-{sender}.json")),
                        serde_json::to_vec_pretty(&actual).unwrap(),
                    )
                    .unwrap();
                }
                let expected = upstream
                    .iter()
                    .find(|value| {
                        value["endpoint"] == endpoint
                            && value["transport"] == transport
                            && value["scheduling"] == scheduling
                            && value["sender"] == sender
                    })
                    .unwrap();
                assert_eq!(
                    &actual, expected,
                    "{endpoint}/{transport}/{scheduling}/{sender}"
                );
            }
        }
    }
}
