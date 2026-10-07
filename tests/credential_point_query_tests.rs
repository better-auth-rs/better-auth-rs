#![cfg(feature = "seaorm2")]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    FieldValue,
    store::{EphemeralStore, secondary::SecondaryStore},
    user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

const OWNER: &str = "ordinary-owner";
const PASSWORD: &str = "ordinary-fixture-password-hash";
const PROJECTION_ERROR: &str = "ordinary credential projection rejected";

fn config(limit: u8, calls: &Arc<AtomicUsize>, reject: &Arc<AtomicBool>) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.default_find_many_limit = Some(f64::from(limit));
    let calls = calls.clone();
    let reject = reject.clone();
    let _ = config.account.additional_fields.insert(
        "password".into(),
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let _ = calls.fetch_add(1, Ordering::SeqCst);
                    if reject.load(Ordering::SeqCst) {
                        return Err(AuthError::Conflict(PROJECTION_ERROR.into()));
                    }
                    Ok(match value {
                        FieldValue::String(value) => FieldValue::String(format!("{value}:output")),
                        other => other,
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    config
}

async fn check<S: AuthSchema>(
    store: &impl AuthStore<S>,
    limit: u8,
    calls: &AtomicUsize,
    reject: &AtomicBool,
) -> AuthResult<()> {
    let _ = store
        .create_user(CreateUser {
            id: Some(OWNER.into()),
            email: Some("ordinary-owner@example.test".into()),
            name: Some("Ordinary Owner".into()).into(),
            email_verified: Some(true),
            ..Default::default()
        })
        .await?;
    let _ = store
        .create_account(CreateAccount {
            user_id: OWNER.into(),
            provider_id: "ordinary-social".into(),
            account_id: "ordinary-social-owner".into(),
            access_token: Some("ordinary-social-token".into()).into(),
            ..Default::default()
        })
        .await?;
    calls.store(0, Ordering::SeqCst);
    assert!(store.get_credential_account(OWNER).await?.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let _ = store
        .create_account(CreateAccount {
            user_id: OWNER.into(),
            provider_id: "credential".into(),
            account_id: OWNER.into(),
            password: Some(PASSWORD.into()).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        store.get_user_accounts(OWNER).await?.len(),
        usize::from(limit)
    );

    calls.store(0, Ordering::SeqCst);
    let account = store
        .get_credential_account(OWNER)
        .await?
        .ok_or_else(|| AuthError::internal("ordinary credential account missing"))?;
    assert_eq!(account.user_id, OWNER);
    assert_eq!(account.provider_id, "credential");
    assert_eq!(account.account_id, OWNER);
    assert_eq!(account.password, Some(format!("{PASSWORD}:output")));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    reject.store(true, Ordering::SeqCst);
    calls.store(0, Ordering::SeqCst);
    let Err(AuthError::Conflict(message)) = store.get_credential_account(OWNER).await else {
        return Err(AuthError::internal("original projection error missing"));
    };
    assert_eq!(message, PROJECTION_ERROR);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn ephemeral_credential_point_query_preserves_projection_and_list_limits() -> AuthResult<()> {
    for limit in [0, 1] {
        let calls = Arc::new(AtomicUsize::new(0));
        let reject = Arc::new(AtomicBool::new(false));
        let store = EphemeralStore::new(Arc::new(config(limit, &calls, &reject)));
        check(&store, limit, &calls, &reject).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_credential_point_query_preserves_projection_and_list_limits() -> AuthResult<()> {
    for limit in [0, 1] {
        let calls = Arc::new(AtomicUsize::new(0));
        let reject = Arc::new(AtomicBool::new(false));
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        migrator::run_migrations(&database)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let store = SeaOrmStore::<BundledSchema>::new(config(limit, &calls, &reject), database);
        check(&store, limit, &calls, &reject).await?;
    }
    Ok(())
}

#[tokio::test]
async fn secondary_facade_forwards_credential_point_query() -> AuthResult<()> {
    for limit in [0, 1] {
        let calls = Arc::new(AtomicUsize::new(0));
        let reject = Arc::new(AtomicBool::new(false));
        let config = Arc::new(config(limit, &calls, &reject));
        let inner = Arc::new(EphemeralStore::new(config.clone()));
        let store = SecondaryStore::without_secondary(inner, config, Default::default());
        check(&store, limit, &calls, &reject).await?;
    }
    Ok(())
}
