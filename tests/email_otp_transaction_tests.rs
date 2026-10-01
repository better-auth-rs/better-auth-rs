#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "integration fixtures fail immediately on setup or assertion errors"
)]

use better_auth::plugins::{
    email_otp::{EmailOtpPlugin, EmailOtpType},
    endpoint_context::EndpointContext,
};
use better_auth::store::transaction;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::CreateVerification;
use better_auth_seaorm::sea_orm::{Database, EntityTrait, PaginatorTrait};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore, SeaOrmVerificationModel,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type Verification = <BundledSchema as better_auth::AuthSchema>::Verification;
type VerificationEntity = <Verification as SeaOrmVerificationModel>::Entity;

#[derive(Clone, Default)]
struct Hooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_after: Arc<AtomicBool>,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        assert!(context.tx.is_some());
        self.events.lock().unwrap().push("before");
        Ok(HookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        _: &better_auth_core::wire::VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        assert_eq!(
            VerificationEntity::find().count(context.db).await.unwrap(),
            1
        );
        self.events.lock().unwrap().push("after");
        if self.fail_after.load(Ordering::SeqCst) {
            return Err(AuthError::internal("after verification failed"));
        }
        Ok(())
    }
}

async fn setup() -> (Arc<BetterAuth<BundledSchema>>, Hooks) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let hooks = Hooks::default();
    let mut config = AuthConfig::new("email-otp-transaction-secret-at-least-32-characters");
    config.verification.store_identifier.default =
        better_auth_core::config::VerificationIdentifierStorage::Hashed;
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database).hook(hooks.clone()))
        .plugin(EmailOtpPlugin::new().generate_otp(Arc::new(|_, _| Some("123456".into()))))
        .build()
        .await
        .unwrap();
    (Arc::new(auth), hooks)
}

async fn create(auth: &Arc<BetterAuth<BundledSchema>>, reject: bool) -> AuthResult<()> {
    let runtime = auth.clone();
    transaction(auth.store().as_ref(), move |tx| {
        Box::pin(async move {
            let mut endpoint = EndpointContext::new(None, serde_json::json!({}), runtime.context());
            endpoint.path = Some("/sign-up/email");
            endpoint.transaction = Some(tx);
            let api = endpoint.email_otp()?;
            assert_eq!(
                api.create("Native@Example.com", EmailOtpType::SignIn)
                    .await?,
                "123456"
            );
            assert_eq!(
                api.get("Native@Example.com", EmailOtpType::SignIn).await?,
                Some("123456".into())
            );
            if reject {
                return Err(AuthError::forbidden("admission rejected"));
            }
            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn native_otp_and_after_hooks_follow_database_commit_and_rollback() {
    let (auth, hooks) = setup().await;
    assert!(create(&auth, true).await.is_err());
    assert_eq!(*hooks.events.lock().unwrap(), ["before"]);
    assert_eq!(
        auth.email_otp()
            .unwrap()
            .get("Native@Example.com", EmailOtpType::SignIn)
            .await
            .unwrap(),
        None
    );
    create(&auth, false).await.unwrap();
    assert_eq!(*hooks.events.lock().unwrap(), ["before", "before", "after"]);
    assert_eq!(
        auth.email_otp()
            .unwrap()
            .get("Native@Example.com", EmailOtpType::SignIn)
            .await
            .unwrap(),
        Some("123456".into())
    );
}

#[tokio::test]
async fn committed_native_otp_survives_a_propagated_after_hook_error() {
    let (auth, hooks) = setup().await;
    hooks.fail_after.store(true, Ordering::SeqCst);
    let error = create(&auth, false).await.unwrap_err();
    assert!(error.to_string().contains("after verification failed"));
    assert_eq!(*hooks.events.lock().unwrap(), ["before", "after"]);
    assert_eq!(
        auth.email_otp()
            .unwrap()
            .get("Native@Example.com", EmailOtpType::SignIn)
            .await
            .unwrap(),
        Some("123456".into())
    );
}
