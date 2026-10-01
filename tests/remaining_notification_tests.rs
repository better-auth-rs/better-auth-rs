#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, OrganizationPlugin,
    email_password::EmailPasswordCallbacks,
    endpoint_context::EndpointContext,
    organization::{
        OrganizationCallbacks,
        hooks::{OrganizationHooks, OrganizationInvitationEvent},
    },
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema};
use better_auth_core::{
    AuthRequest, HttpMethod, PasswordHasher,
    background::{BackgroundFuture, BackgroundTask, BackgroundTasks},
    observability::{LogArgument, LogLevel, LogSink},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    },
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
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
    armed: AtomicBool,
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
    fn capture<S: AuthSchema>(&self, phase: &str, data: &Value, endpoint: &EndpointContext<'_, S>) {
        let mut body = endpoint.body.clone();
        if let Some(id) = body.get_mut("organizationId") {
            *id = json!("<organization>");
        }
        self.contexts.lock().unwrap().push(json!({"phase":phase,"path":endpoint.path,"body":body,
            "request":endpoint.request.is_some(),"requestPath":endpoint.request.and_then(AuthRequest::url).map(url::Url::path),
            "email":data.get("email"),"role":data.get("role"),"inviter":data.get("inviter")}));
    }
    fn sender<S: AuthSchema>(
        self: &Arc<Self>,
        sender: &'static str,
        data: Value,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<BackgroundFuture>> {
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        self.event("sender:start");
        self.capture("start", &data, endpoint);
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
        let endpoint = endpoint.to_owned();
        Ok(Some(Box::pin(async move {
            state.gate.notified().await;
            state.capture("released", &data, &endpoint.as_endpoint());
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
            let value = argument.to_string();
            value
                .strip_prefix("Internal server error: ")
                .unwrap_or(&value)
                .to_owned()
        });
        self.event(&format!("log:{}", error.as_deref().unwrap_or("unknown")));
        self.logs
            .lock()
            .unwrap()
            .push(json!({"message":message,"error":error}));
    }
}
struct Hasher(Arc<State>);
#[async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        if self.0.armed.load(Ordering::SeqCst) {
            self.0.event("hash");
        }
        Ok("fixture".into())
    }
    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
}
struct Hooks(Arc<State>);
#[async_trait]
impl OrganizationHooks for Hooks {
    async fn after_create_invitation(&self, _: OrganizationInvitationEvent<'_>) -> AuthResult<()> {
        if self.0.armed.load(Ordering::SeqCst) {
            self.0.event("organization:after");
        }
        Ok(())
    }
}
async fn snapshot(db: &DatabaseConnection) -> Value {
    let row=db.query_one_raw(Statement::from_string(DbBackend::Sqlite,"SELECT (SELECT COUNT(*) FROM users) AS users,(SELECT COUNT(*) FROM invitation) AS invitations".to_owned())).await.unwrap().unwrap();
    json!({"users":row.try_get::<i64>("","users").unwrap(),"invitations":row.try_get::<i64>("","invitations").unwrap()})
}
async fn run(
    endpoint: &'static str,
    transport: &'static str,
    scheduling: &'static str,
    sender: &'static str,
) -> Value {
    let state = Arc::new(State::default());
    let path = std::env::temp_dir().join(format!(
        "remaining-notification-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let mut options = ConnectOptions::new(format!("sqlite:{}?mode=rwc", path.display()));
    let _ = options.max_connections(2);
    let db = Database::connect(options).await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let mut config = AuthConfig::new("remaining-background-contract-secret-longer-than-thirty-two")
        .base_url("http://localhost:3000");
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
    let duplicate = state.clone();
    let invitation = state.clone();
    let synthetic = state.clone();
    let auth=Arc::new(AuthBuilder::new(config.clone()).store(SeaOrmStore::<BundledSchema>::new(config,db.clone()))
        .rate_limit(better_auth_core::middleware::RateLimitConfig{enabled:false,..Default::default()})
        .plugin(EmailPasswordPlugin::new().auto_sign_in(endpoint!="signup").password_hasher(Arc::new(Hasher(state.clone())))
            .custom_synthetic_user(Arc::new(move|input|{synthetic.event("synthetic");let mut result=input.core_fields;result.extend(input.additional_fields);let _=result.insert("id".into(),json!(input.id));Ok(result)}))
            .callbacks(EmailPasswordCallbacks::<BundledSchema>::existing_user_sign_up(move|user,ctx|duplicate.sender(sender,json!({"email":user.email}),ctx))))
        .plugin(OrganizationPlugin::new().hooks(Arc::new(Hooks(state.clone()))).callbacks(OrganizationCallbacks::<BundledSchema>::invitation_email(move|message,ctx|invitation.sender(sender,json!({"email":message.invitation.email,"role":message.invitation.role,"inviter":message.inviter.email}),ctx))))
        .build().await.unwrap());
    let response=auth.call_endpoint(HttpMethod::Post,"/sign-up/email",EndpointInput{body:Some(json!({"name":"Owner","email":"owner@example.com","password":"fixture-password"})),..Default::default()}).await.unwrap();
    assert_eq!(response.status, 200);
    let cookie = response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let mut organization_id = None;
    if endpoint != "signup" {
        let response = auth
            .call_endpoint(
                HttpMethod::Post,
                "/organization/create",
                EndpointInput {
                    body: Some(json!({"name":"Company","slug":"company"})),
                    headers: Some([("cookie".into(), cookie.clone())].into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        organization_id = body.get("id").and_then(Value::as_str).map(str::to_owned);
        if endpoint == "resend" {
            let response=auth.call_endpoint(HttpMethod::Post,"/organization/invite-member",EndpointInput{body:Some(json!({"email":"target@example.com","role":"member","organizationId":organization_id})),headers:Some([("cookie".into(),cookie.clone())].into()),..Default::default()}).await.unwrap();
            assert_eq!(response.status, 200);
        }
    }
    let raw_body = if endpoint == "signup" {
        json!({"name":"Other","email":"owner@example.com","password":"fixture-password","unknown":"drop"})
    } else {
        json!({"email":"TARGET@example.com","role":"member","organizationId":organization_id,"resend":endpoint=="resend","unknown":"drop"})
    };
    let route = if endpoint == "signup" {
        "/sign-up/email"
    } else {
        "/organization/invite-member"
    };
    state.armed.store(true, Ordering::SeqCst);
    let worker_state = state.clone();
    let mut operation = tokio::spawn(async move {
        let headers = [
            ("cookie".into(), cookie),
            ("origin".into(), "http://localhost:3000".into()),
            ("content-type".into(), "application/json".into()),
        ]
        .into();
        let result = if transport == "http" {
            auth.handle_request(
                AuthRequest::from_parts(
                    HttpMethod::Post,
                    format!("/api/auth{route}"),
                    headers,
                    Some(serde_json::to_vec(&raw_body).unwrap()),
                    None,
                )
                .with_url(
                    format!("http://localhost:3000/api/auth{route}")
                        .parse()
                        .unwrap(),
                ),
            )
            .await
        } else {
            auth.call_endpoint(
                HttpMethod::Post,
                route,
                EndpointInput {
                    body: Some(raw_body),
                    headers: Some(headers),
                    ..Default::default()
                },
            )
            .await
        };
        worker_state.response_done.store(true, Ordering::SeqCst);
        worker_state.event("response");
        match result {
            Ok(response) => json!({"status":response.status,"thrown":null}),
            Err(AuthError::Internal(message)) => json!({"status":null,"thrown":message}),
            Err(error) => json!({"status":null,"thrown":error.to_string()}),
        }
    });
    tokio::select! {biased; _=state.entered.notified()=>{},result=&mut operation=>panic!("completed without sender: {result:?}")}
    let before = snapshot(&db).await;
    let asynchronous = sender == "resolve" || sender == "reject";
    let mut operation = Some(operation);
    let early = if !asynchronous || scheduling != "default" {
        Some(operation.take().unwrap().await.unwrap())
    } else {
        None
    };
    let responded = state.response_done.load(Ordering::SeqCst);
    state.event("gate:release");
    state.gate.notify_one();
    let outcome = match early {
        Some(result) => result,
        None => operation.take().unwrap().await.unwrap(),
    };
    state.finished.notified().await;
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    let mut task_states = Vec::new();
    for task in tasks {
        task.await.unwrap();
        task_states.push("fulfilled");
    }
    let after = snapshot(&db).await;
    db.close().await.unwrap();
    std::fs::remove_file(path).unwrap();
    json!({"endpoint":endpoint,"transport":transport,"scheduling":scheduling,"sender":sender,"respondedBeforeRelease":responded,"storedBeforeRelease":before,"storedAfterResponse":after,"outcome":outcome,"events":*state.events.lock().unwrap(),"logs":*state.logs.lock().unwrap(),"contexts":*state.contexts.lock().unwrap(),"taskStates":task_states})
}
#[tokio::test]
async fn invitation_and_duplicate_signup_scheduling_matches_pinned_upstream() {
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/remaining-notifications-upstream.json"
    ))
    .unwrap();
    for endpoint in ["invite", "resend", "signup"] {
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
                let wanted = expected
                    .iter()
                    .find(|item| {
                        item.get("endpoint") == Some(&json!(endpoint))
                            && item.get("transport") == Some(&json!(transport))
                            && item.get("scheduling") == Some(&json!(scheduling))
                            && item.get("sender") == Some(&json!(sender))
                    })
                    .unwrap();
                assert_eq!(
                    &actual, wanted,
                    "{endpoint}/{transport}/{scheduling}/{sender}"
                );
            }
        }
    }
}
