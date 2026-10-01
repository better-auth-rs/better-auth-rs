#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]
use async_trait::async_trait;
use better_auth::plugins::{EmailPasswordPlugin, email_password::EmailPasswordCallbacks};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    CreateVerification, HttpMethod, PasswordHasher,
    observability::{LogArgument, LogLevel, LogSink},
    store::database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
    wire::VerificationView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct Events(Mutex<Vec<&'static str>>);
impl Events {
    fn push(&self, value: &'static str) {
        self.0.lock().unwrap().push(value);
    }
}
impl LogSink for Events {
    fn log(&self, _: LogLevel, message: LogArgument<'_>, _: &[LogArgument<'_>]) {
        if message
            .to_string()
            .starts_with("Failed to run background task")
        {
            self.push("log");
        }
    }
}
#[better_auth::database_hooks()]
impl DatabaseHooks<BundledSchema> for Events {
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        _: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.push("verification:before");
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        _: &VerificationView,
        _: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.push("verification:after");
        Ok(())
    }
}
struct HookPlugin(Arc<Events>);
#[async_trait]
impl AuthPlugin<BundledSchema> for HookPlugin {
    fn name(&self) -> &'static str {
        "duplicate-notification-hooks"
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
        Ok("fixture".into())
    }
    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
}
#[tokio::test]
async fn duplicate_notification_uses_signup_transaction_and_preserves_after_commit_hooks() {
    for mode in ["resolve", "reject", "rollback"] {
        let events = Arc::new(Events::default());
        let mut config =
            AuthConfig::new("duplicate-transaction-contract-secret-longer-than-thirty-two")
                .base_url("http://localhost:3000");
        config.logger.level = LogLevel::Error;
        config.logger.log = Some(events.clone());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let sender = events.clone();
        let synthetic = events.clone();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .plugin(HookPlugin(events.clone()))
            .plugin(
                EmailPasswordPlugin::new()
                    .auto_sign_in(false)
                    .password_hasher(Arc::new(Hasher))
                    .custom_synthetic_user(Arc::new(move |input| {
                        synthetic.push("synthetic");
                        if mode == "rollback" {
                            return Err(AuthError::internal("synthetic-error"));
                        }
                        let mut fields = input.core_fields;
                        let _ = fields.insert("id".into(), json!(input.id));
                        Ok(fields)
                    }))
                    .callbacks(
                        EmailPasswordCallbacks::<BundledSchema>::existing_user_sign_up(
                            move |_, endpoint| {
                                sender.push("sender:start");
                                let sender = sender.clone();
                                let endpoint = endpoint.to_owned();
                                Ok(Some(Box::pin(async move {
                                    let _ = endpoint
                                        .as_endpoint()
                                        .transaction
                                        .unwrap()
                                        .create_verification(CreateVerification {
                                            identifier: "duplicate".into(),
                                            value: "value".into(),
                                            expires_at: (chrono::Utc::now()
                                                + chrono::Duration::seconds(60))
                                            .into(),
                                            ..Default::default()
                                        })
                                        .await?;
                                    sender.push("sender:created");
                                    if mode == "reject" {
                                        return Err(AuthError::internal("sender-async"));
                                    }
                                    Ok(())
                                })))
                            },
                        ),
                    ),
            )
            .build()
            .await
            .unwrap();
        let body =
            json!({"name":"Owner","email":"owner@example.com","password":"fixture-password"});
        let _ = auth
            .call_endpoint(
                HttpMethod::Post,
                "/sign-up/email",
                EndpointInput {
                    body: Some(body.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let result = auth
            .call_endpoint(
                HttpMethod::Post,
                "/sign-up/email",
                EndpointInput {
                    body: Some(body),
                    ..Default::default()
                },
            )
            .await;
        events.push("response");
        if mode == "rollback" {
            assert!(
                matches!(result,Err(AuthError::Internal(ref message))if message=="synthetic-error")
            );
        } else {
            assert_eq!(result.unwrap().status, 200);
        }
        let mut expected = vec!["sender:start", "verification:before", "sender:created"];
        if mode == "reject" {
            expected.push("log");
        }
        expected.push("synthetic");
        if mode != "rollback" {
            expected.push("verification:after");
        }
        expected.push("response");
        assert_eq!(*events.0.lock().unwrap(), expected);
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
        assert_eq!(count, if mode == "rollback" { 0 } else { 1 });
    }
}
