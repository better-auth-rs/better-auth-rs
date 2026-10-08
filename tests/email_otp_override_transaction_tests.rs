#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "contract fixtures fail on invalid setup and assertions"
)]

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin,
    email_otp::{EmailOtpCallbacks, EmailOtpPlugin},
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, VerificationUpdate,
};
use better_auth_core::wire::{SessionView, UserView, VerificationView};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    CreateVerification, HttpMethod, PasswordHasher,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const IDENTIFIER: &str = "email-verification-otp-override@example.com";
#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    observations: Mutex<Vec<Value>>,
    contexts: Mutex<Vec<Value>>,
}
impl State {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
    fn capture(&self, phase: &str, context: &DatabaseHookContext<'_, BundledSchema>) {
        if let Some(request) = &context.request {
            let ambient = better_auth_core::hooks::current_request_hook_context().unwrap();
            self.contexts.lock().unwrap().push(json!({"phase":phase, "supplied":{"path":request.path, "body":request.body.json().unwrap(), "request":request.is_http}, "ambient":{"path":ambient.path, "body":ambient.body.json().unwrap(), "request":ambient.is_http}}));
        }
    }
}
struct Hooks {
    state: Arc<State>,
    outcome: &'static str,
}
#[better_auth::database_hooks()]
impl DatabaseHooks<BundledSchema> for Hooks {
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.state.event("verification:create.before");
        self.state.capture("verification:create.before", context);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        _: Option<&VerificationView>,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.state.event("verification:create.after");
        self.state.capture("verification:create.after", context);
        Ok(())
    }
    async fn before_update_verification(
        &self,
        _: &VerificationUpdate,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        self.state.event("verification:update.before");
        self.state.capture("verification:update.before", context);
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_verification(
        &self,
        _: Option<&VerificationView>,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.state.event("verification:update.after");
        self.state.capture("verification:update.after", context);
        Ok(())
    }
    async fn after_create_user(
        &self,
        _: Option<&UserView>,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.state.event("user:create.after");
        self.state.capture("user:create.after", context);
        if self.outcome == "after-error" {
            return Err(AuthError::internal("after-error"));
        }
        Ok(())
    }
    async fn before_create_session(
        &self,
        _: &mut better_auth_core::FieldMap,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        self.state.event("session:create.before");
        self.state.capture("session:create.before", context);
        if self.outcome == "rollback" {
            return Err(AuthError::internal("session-rejected"));
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        _: Option<&SessionView>,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.state.event("session:create.after");
        self.state.capture("session:create.after", context);
        Ok(())
    }
}
struct InstallHooks(Arc<Hooks>);
#[async_trait]
impl AuthPlugin<BundledSchema> for InstallHooks {
    fn name(&self) -> &'static str {
        "override-transaction-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<BundledSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<BundledSchema>) -> AuthResult<()> {
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

async fn run(reuse: bool, outcome: &'static str) -> Value {
    let state = Arc::new(State::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let config = AuthConfig::new("background-override-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000");
    let sender = state.clone();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .plugin(InstallHooks(Arc::new(Hooks {
            state: state.clone(),
            outcome,
        })))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
        .plugin(EmailVerificationPlugin::new().send_on_sign_up(true))
        .plugin(
            EmailOtpPlugin::new()
                .override_default_email_verification(true)
                .reuse_otp(reuse)
                .callbacks(
                    EmailOtpCallbacks::<BundledSchema>::default()
                        .generate(|_, _, _| Ok(Some("654321".into())))
                        .send(move |message, endpoint| {
                            let message = message.clone();
                            let endpoint = endpoint.to_owned();
                            let state = sender.clone();
                            Ok(Some(Box::pin(async move {
                                let endpoint = endpoint.as_endpoint();
                                let transaction = endpoint.transaction.unwrap();
                                let user = transaction.get_user_by_email(&message.email).await?;
                                let verification = transaction
                                    .get_verification_including_expired(IDENTIFIER)
                                    .await?;
                                state.observations.lock().unwrap().push(
                                    json!({"path":endpoint.path, "body":endpoint.body.json()?,
                            "hasRequest":endpoint.request.is_some(), "userFound":user.is_some(),
                            "value":verification.map(|row| row.value), "otp":message.otp}),
                                );
                                state.event("sender");
                                Ok(())
                            })))
                        }),
                ),
        )
        .build()
        .await
        .unwrap();
    let expiry = chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
        .unwrap()
        .to_utc();
    if reuse {
        let _ = auth
            .store()
            .create_verification(CreateVerification {
                identifier: IDENTIFIER.into(),
                value: "123456:0".into(),
                expires_at: expiry.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        state.events.lock().unwrap().clear();
    }
    state.contexts.lock().unwrap().clear();
    let response = auth.call_endpoint(HttpMethod::Post, "/sign-up/email", EndpointInput {
        body: Some(json!({"name":"Override", "email":"override@example.com", "password":"fixture-password"})), ..Default::default()
    }).await;
    let result = match response {
        Ok(response) => json!({"status":response.status, "thrown":null}),
        Err(AuthError::Internal(error)) => json!({"status":null, "thrown":error}),
        Err(error) => panic!("unexpected error: {error:?}"),
    };
    let counts = db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
        "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM accounts) AS accounts, (SELECT COUNT(*) FROM sessions) AS sessions".to_owned())).await.unwrap().unwrap();
    let verification = auth
        .store()
        .get_verification_including_expired(IDENTIFIER)
        .await
        .unwrap();
    let rows: Vec<Value> = verification.into_iter().map(|row| json!({"value":row.value, "originalExpiry":row.expires_at.typed().unwrap() == &expiry.into()})).collect();
    let contexts: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-otp-context-upstream.json"
    ))
    .unwrap();
    let expected = contexts
        .iter()
        .find(|record| record["reuse"] == reuse && record["outcome"] == outcome)
        .unwrap();
    let hook_contexts: Vec<Value> = expected["contexts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|context| context["phase"] != "sender")
        .cloned()
        .collect();
    assert_eq!(*state.contexts.lock().unwrap(), hook_contexts);
    json!({"reuse":reuse, "outcome":outcome, "result":result, "events":*state.events.lock().unwrap(), "observations":*state.observations.lock().unwrap(),
        "stored":{"users":counts.try_get::<i64>("","users").unwrap(), "accounts":counts.try_get::<i64>("","accounts").unwrap(), "sessions":counts.try_get::<i64>("","sessions").unwrap(), "verification":rows}})
}

#[tokio::test]
async fn override_uses_signup_transaction_for_create_reuse_and_after_hooks() {
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-otp-override-upstream.json"
    ))
    .unwrap();
    for reuse in [false, true] {
        for outcome in ["commit", "rollback", "after-error"] {
            let actual =
                tokio::time::timeout(std::time::Duration::from_secs(30), run(reuse, outcome))
                    .await
                    .unwrap();
            assert_eq!(
                &actual,
                expected
                    .iter()
                    .find(|row| row["reuse"] == reuse && row["outcome"] == outcome)
                    .unwrap()
            );
        }
    }
}
