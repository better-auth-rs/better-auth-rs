#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use better_auth::store::transaction;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::CreateVerification;
use better_auth_core::wire::VerificationView;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Hooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: &'static str,
}
#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn before_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        assert!(context.tx.is_some());
        self.events.lock().unwrap().push("before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.events.lock().unwrap().push("after");
        if self.outcome == "after-error" {
            return Err(AuthError::internal("after-error"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn verification_delete_uses_the_active_transaction_and_ordered_after_hooks() {
    let upstream: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-otp-deletion-upstream.json"
    ))
    .unwrap();
    for outcome in ["commit", "rollback", "after-error"] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let config =
            AuthConfig::new("background-transaction-delete-secret-at-least-thirty-two-characters")
                .base_url("http://localhost:3000");
        let auth = AuthBuilder::new(config.clone())
            .store(
                SeaOrmStore::<BundledSchema>::new(config, db.clone()).hook(Hooks {
                    events: events.clone(),
                    outcome,
                }),
            )
            .build()
            .await
            .unwrap();
        let _ = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "transaction-delete".into(),
                value: "123456:0".into(),
                expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .to_utc()
                    .into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let found = Arc::new(Mutex::new(None));
        let captured = found.clone();
        let emitted = events.clone();
        let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                tx.delete_verification_by_identifier("transaction-delete")
                    .await?;
                *captured.lock().unwrap() = Some(
                    tx.get_verification_including_expired("transaction-delete")
                        .await?
                        .is_some(),
                );
                emitted.lock().unwrap().push("after-delete");
                if outcome == "rollback" {
                    return Err(AuthError::internal("rollback"));
                }
                Ok(())
            })
        })
        .await;
        let error = result.err().map(|error| match error {
            AuthError::Internal(message) => message,
            error => panic!("unexpected error: {error:?}"),
        });
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
        let actual = json!({"outcome":outcome, "foundInside":*found.lock().unwrap(), "error":error, "events":*events.lock().unwrap(), "count":count});
        assert_eq!(
            &actual,
            upstream
                .iter()
                .find(|record| record["outcome"] == outcome)
                .unwrap()
        );
    }
}
