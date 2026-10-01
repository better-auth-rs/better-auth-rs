#![cfg(feature = "seaorm2")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    store::EphemeralStore, user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

async fn check<S: AuthSchema>(
    store: &impl AuthStore<S>,
    projections: &AtomicUsize,
    fail: &AtomicUsize,
) -> AuthResult<()> {
    let provider = "provider\"quoted";
    let user = store
        .create_user(CreateUser::new().with_email("owner@example.test"))
        .await?;
    assert!(store.get_account(provider, "subject").await?.is_none());
    for (index, token) in ["first", "second", "third"].into_iter().enumerate() {
        let _ = store
            .create_account(CreateAccount {
                provider_id: provider.into(),
                account_id: "subject".into(),
                user_id: user.id.clone(),
                access_token: Some(token.to_owned()).into(),
                ..Default::default()
            })
            .await?;
        if index == 0 {
            assert!(store.get_account(provider, "subject").await?.is_some());
        }
    }
    projections.store(0, Ordering::SeqCst);
    let Err(error) = store.get_account(provider, "subject").await else {
        return Err(AuthError::internal("duplicate identity lookup must fail"));
    };
    assert_eq!(
        error.instrumentation_message(),
        "Multiple accounts match the same accountId for provider \"provider\\\"quoted\". Resolve duplicate account identities before continuing."
    );
    assert_eq!(projections.load(Ordering::SeqCst), 2);
    for (mode, message) in [
        (1, "first projection failed"),
        (2, "second projection failed"),
    ] {
        projections.store(0, Ordering::SeqCst);
        fail.store(mode, Ordering::SeqCst);
        let Err(error) = store.get_account(provider, "subject").await else {
            return Err(AuthError::internal("output projection must fail"));
        };
        assert_eq!(error.instrumentation_message(), message);
        assert_eq!(projections.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test]
async fn duplicate_identities_are_rejected_after_two_projections_independently_of_default_limits()
-> AuthResult<()> {
    for sqlite in [false, true] {
        for limit in [None, Some(0.0), Some(1.0)] {
            let projections = Arc::new(AtomicUsize::new(0));
            let fail = Arc::new(AtomicUsize::new(0));
            let (calls, should_fail) = (projections.clone(), fail.clone());
            let mut config = AuthConfig::default();
            config.advanced.database.default_find_many_limit = limit;
            let _ = config.account.additional_fields.insert(
                "accessToken".into(),
                UserFieldConfig {
                    output_transform: Some(Arc::new(move |value| {
                        let _ = calls.fetch_add(1, Ordering::SeqCst);
                        let mode = should_fail.load(Ordering::SeqCst);
                        let token = value.as_ref().and_then(serde_json::Value::as_str);
                        if mode == 1 || (mode == 2 && token == Some("second")) {
                            let token = token.ok_or_else(|| {
                                AuthError::internal("stored token must be a string")
                            })?;
                            return Err(AuthError::internal(format!("{token} projection failed")));
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                },
            );
            if sqlite {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                check(
                    &SeaOrmStore::<BundledSchema>::new(config, database),
                    &projections,
                    &fail,
                )
                .await?;
            } else {
                check(&EphemeralStore::new(Arc::new(config)), &projections, &fail).await?;
            }
        }
    }
    Ok(())
}
