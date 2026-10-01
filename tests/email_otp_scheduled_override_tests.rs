#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin,
    email_otp::{EmailOtpCallbacks, EmailOtpPlugin},
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::background::{BackgroundTask, BackgroundTasks};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::wire::VerificationView;
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateSession,
    HttpMethod, PasswordHasher,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    observations: Mutex<Vec<Value>>,
    tasks: Mutex<Vec<BackgroundTask>>,
    entered: Notify,
    gate: Notify,
}
impl State {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
}
struct Hooks {
    state: Arc<State>,
    rollback: bool,
}
#[better_auth::database_hooks()]
impl DatabaseHooks<BundledSchema> for Hooks {
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.state.entered.notified().await;
        self.state.event("session:before");
        if self.rollback {
            return Err(AuthError::internal("rollback"));
        }
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        _: &VerificationView,
        context: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        self.state.event("verification:after");
        Ok(())
    }
}
struct InstallHooks(Arc<Hooks>);
#[async_trait]
impl AuthPlugin<BundledSchema> for InstallHooks {
    fn name(&self) -> &'static str {
        "scheduled-override-fixture"
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
async fn run(rollback: bool) -> Value {
    let state = Arc::new(State::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let mut config = AuthConfig::new("scheduled-override-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000");
    let handler = state.clone();
    config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
        handler.event("handler");
        handler.tasks.lock().unwrap().push(task);
        Ok(())
    }));
    let sender = state.clone();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: false,
            ..Default::default()
        })
        .plugin(InstallHooks(Arc::new(Hooks {
            state: state.clone(),
            rollback,
        })))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
        .plugin(EmailVerificationPlugin::new().send_on_sign_up(true))
        .plugin(
            EmailOtpPlugin::new()
                .override_default_email_verification(true)
                .callbacks(
                    EmailOtpCallbacks::<BundledSchema>::default()
                        .generate(|_, _, _| Ok(Some("123456".into())))
                        .send(move |_, endpoint| {
                            let endpoint = endpoint.to_owned();
                            let state = sender.clone();
                            Ok(Some(Box::pin(async move {
                                let endpoint = endpoint.as_endpoint();
                                let user = endpoint
                                    .transaction
                                    .unwrap()
                                    .get_user_by_email("scheduled@example.com")
                                    .await?;
                                state.observations.lock().unwrap().push(
                                    json!({"userFound":user.is_some(), "path":endpoint.path}),
                                );
                                state.event("sender:start");
                                state.entered.notify_one();
                                state.gate.notified().await;
                                state.event("sender:released");
                                Ok(())
                            })))
                        }),
                ),
        )
        .build()
        .await
        .unwrap();
    let response = auth.call_endpoint(HttpMethod::Post, "/sign-up/email", EndpointInput {
        body: Some(json!({"name":"Scheduled", "email":"scheduled@example.com", "password":"fixture-password"})), ..Default::default()
    }).await;
    let result = match response {
        Ok(response) => json!({"status":response.status, "thrown":null}),
        Err(AuthError::Internal(error)) => json!({"status":null, "thrown":error}),
        Err(error) => panic!("unexpected error: {error:?}"),
    };
    state.event("response");
    let count = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM verifications".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "count")
        .unwrap();
    state.event("gate:release");
    state.gate.notify_one();
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    let task_count = tasks.len();
    for task in tasks {
        task.await.unwrap();
    }
    json!({"rollback":rollback, "result":result, "events":*state.events.lock().unwrap(), "observations":*state.observations.lock().unwrap(), "count":count, "tasks":task_count})
}
#[tokio::test]
async fn scheduled_override_retains_all_three_scheduling_boundaries_and_the_active_transaction() {
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-otp-scheduled-override-upstream.json"
    ))
    .unwrap();
    for rollback in [false, true] {
        let actual = tokio::time::timeout(std::time::Duration::from_secs(30), run(rollback))
            .await
            .unwrap();
        assert_eq!(
            &actual,
            expected
                .iter()
                .find(|row| row["rollback"] == rollback)
                .unwrap()
        );
    }
}
