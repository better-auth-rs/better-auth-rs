#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use async_trait::async_trait;
use better_auth::plugins::{endpoint_context::EndpointContext, phone_number::PhoneNumberPlugin};
use better_auth::store::{MemoryCacheAdapter, SecondaryStorage, transaction};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::wire::VerificationView;
use better_auth_core::{CreateVerification, FieldValue};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

const PHONE: &str = "+15551230001";
const KEY: &str = "verification:+15551230001";

struct Cache {
    inner: MemoryCacheAdapter,
    active: AtomicBool,
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: &'static str,
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.inner.get(key).await
    }
    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        self.inner.set_native(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        if self.active.load(Ordering::SeqCst) {
            self.events.lock().unwrap().push("cache-delete");
            if self.outcome == "cache-error" {
                return Err(AuthError::internal("cache rejected"));
            }
        }
        self.inner.delete(key).await
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.inner.get_and_delete(key).await
    }
}

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
        Ok(if self.outcome == "cancel" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.events.lock().unwrap().push("after");
        if self.outcome == "after-error" {
            return Err(AuthError::internal("after rejected"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn phone_native_consumption_preserves_transaction_cache_and_hook_failure_order() {
    let upstream: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/phone-native-transaction-upstream.json"
    ))
    .unwrap();
    for outcome in ["commit", "rollback", "cancel", "cache-error", "after-error"] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let cache = Arc::new(Cache {
            inner: MemoryCacheAdapter::new(),
            active: AtomicBool::new(false),
            events: events.clone(),
            outcome,
        });
        let mut config = AuthConfig::new("phone-consume-transaction-secret-longer-than-32")
            .base_url("http://localhost:3000");
        config.verification.store_in_database = true;
        config.verification.disable_cleanup = Some(true);
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(
                    SeaOrmStore::<BundledSchema>::new(config, db.clone()).hook(Hooks {
                        events: events.clone(),
                        outcome,
                    }),
                )
                .secondary_storage(cache.clone())
                .plugin(PhoneNumberPlugin::new())
                .build()
                .await
                .unwrap(),
        );
        let _ = auth
            .store()
            .create_verification(CreateVerification {
                identifier: PHONE.into(),
                value: "123456:0".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(cache.get(KEY).await.unwrap().is_some());
        cache.active.store(true, Ordering::SeqCst);
        let runtime = auth.clone();
        let emitted = events.clone();
        let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let mut endpoint = EndpointContext::new(
                    None,
                    better_auth_core::FieldMap::new().into(),
                    runtime.context(),
                );
                endpoint.transaction = Some(tx);
                assert!(
                    endpoint
                        .phone_number()?
                        .consume(Some(json!({"phoneNumber":PHONE,"code":"123456"})))
                        .await?
                );
                assert!(
                    tx.get_verification_including_expired(PHONE)
                        .await?
                        .is_none()
                );
                emitted.lock().unwrap().push("consumed");
                if outcome == "rollback" {
                    return Err(AuthError::internal("rollback requested"));
                }
                Ok(())
            })
        })
        .await;
        let error = result.err().map(|error| match error {
            AuthError::Internal(message) => Value::String(message),
            error => {
                serde_json::from_slice::<Value>(&error.to_auth_response().body.bytes().unwrap())
                    .unwrap()["code"]
                    .clone()
            }
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
        let actual = json!({"outcome":outcome,"error":error,"count":count,"cached":cache.get(KEY).await.unwrap().is_some(),"events":*events.lock().unwrap()});
        assert_eq!(
            &actual,
            upstream
                .iter()
                .find(|record| record["outcome"] == outcome)
                .unwrap(),
            "{outcome}"
        );
    }
}
