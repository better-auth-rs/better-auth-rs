use better_auth::plugins::{UsernameConfig, UsernamePlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthSchema, BetterAuth};
use better_auth_core::{AuthUser, CreateUser};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct FixtureHasher;
#[async_trait::async_trait]
impl better_auth::PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> better_auth::AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> better_auth::AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

struct RejectedDelivery(AtomicUsize);
#[async_trait::async_trait]
impl better_auth_core::email::SendVerificationEmail for RejectedDelivery {
    async fn send(
        &self,
        _: &better_auth_core::wire::UserView,
        _: &str,
        _: &str,
    ) -> better_auth::AuthResult<()> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::Upstream {
            status: 409,
            code: "DELIVERY_REJECTED",
            message: "Delivery rejected",
        })
    }
}

#[tokio::test]
async fn username_login_only_sends_verification_when_required_and_propagates_delivery_errors() {
    use better_auth::plugins::{EmailPasswordPlugin, EmailVerificationPlugin};
    for required in [false, true] {
        let delivery = Arc::new(RejectedDelivery(AtomicUsize::new(0)));
        let auth = BetterAuth::stateless(AuthConfig::new(
            "username-runtime-test-secret-at-least-32-characters",
        ))
        .plugin(UsernamePlugin::default())
        .plugin(
            EmailPasswordPlugin::new()
                .password_hasher(Arc::new(FixtureHasher))
                .require_email_verification(required),
        )
        .plugin(
            EmailVerificationPlugin::new()
                .send_on_sign_in(true)
                .custom_send_verification_email(delivery.clone()),
        )
        .build()
        .await
        .unwrap();
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("unverified@example.com")
                    .with_username("Unverified"),
            )
            .await
            .unwrap();
        let _ = auth
            .store()
            .create_account(better_auth_core::CreateAccount {
                user_id: user.id().into_owned(),
                account_id: user.id().into_owned(),
                provider_id: "credential".into(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some("fixture:Password123!".into()),
            })
            .await
            .unwrap();
        let result = auth
            .call_endpoint(
                better_auth_core::HttpMethod::Post,
                "/sign-in/username",
                better_auth::server_api::EndpointInput {
                    body: Some(
                        serde_json::json!({"username":"Unverified","password":"Password123!"}),
                    ),
                    ..Default::default()
                },
            )
            .await;
        if required {
            let response = result.unwrap_err().to_auth_response();
            assert_eq!(response.status, 409);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                serde_json::json!({"code":"DELIVERY_REJECTED","message":"Delivery rejected"})
            );
            assert_eq!(delivery.0.load(Ordering::SeqCst), 1);
            assert!(
                auth.store()
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .is_empty()
            );
        } else {
            assert_eq!(result.unwrap().status, 200);
            assert_eq!(delivery.0.load(Ordering::SeqCst), 0);
        }
    }
}

async fn duplicate_in_transaction<S: AuthSchema>(auth: &BetterAuth<S>) {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        better_auth_core::store::transaction(auth.store().as_ref(), |transaction| {
            Box::pin(async move {
                let first = transaction
                    .create_user(
                        CreateUser::new()
                            .with_email("first@example.com")
                            .with_username("Mixed_User"),
                    )
                    .await?;
                assert_eq!(first.username(), Some("mixed_user"));
                transaction
                    .create_user(
                        CreateUser::new()
                            .with_email("duplicate@example.com")
                            .with_username("MIXED_USER"),
                    )
                    .await
            })
        }),
    )
    .await
    .expect("username lookup must use the active transaction connection");
    assert!(matches!(
        result,
        Err(AuthError::Upstream {
            code: "USERNAME_IS_ALREADY_TAKEN",
            ..
        })
    ));
    assert!(
        auth.store()
            .get_user_by_email("first@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .get_user_by_username("mixed_user")
            .await
            .unwrap()
            .is_none()
    );
    let created = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("after@example.com")
                .with_username("Mixed_User"),
        )
        .await
        .unwrap();
    assert_eq!(created.username(), Some("mixed_user"));
}

#[tokio::test]
async fn username_uniqueness_observes_uncommitted_sqlite_rows_and_rolls_back() {
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let config = AuthConfig::new("username-runtime-test-secret-at-least-32-characters");
    let database = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(better_auth_seaorm::SeaOrmStore::<Schema>::new(
            config, database,
        ))
        .plugin(UsernamePlugin::default())
        .build()
        .await
        .unwrap();
    duplicate_in_transaction(&auth).await;
}

#[tokio::test]
async fn username_uniqueness_observes_uncommitted_ephemeral_rows_and_rolls_back() {
    let auth = BetterAuth::stateless(AuthConfig::new(
        "username-runtime-test-secret-at-least-32-characters",
    ))
    .plugin(UsernamePlugin::new(UsernameConfig::default()))
    .build()
    .await
    .unwrap();
    duplicate_in_transaction(&auth).await;
}
