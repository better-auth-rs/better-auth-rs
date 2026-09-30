#![cfg(feature = "axum")]
#![allow(
    clippy::unwrap_used,
    reason = "Tests use panic-on-failure setup and assert concrete extractor responses"
)]

use axum::{
    extract::FromRequestParts,
    http::{Request, StatusCode, request::Parts},
};
use better_auth::integrations::axum::{CurrentSession, OptionalSession};
use better_auth::prelude::CreateUser;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_seaorm::sea_orm::ConnectionTrait;
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use chrono::{Duration, Utc};
use std::sync::Arc;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn setup() -> (DatabaseConnection, Arc<BetterAuth<Schema>>, String) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let mut config = AuthConfig::new("session-extractor-test-secret-at-least-32-characters")
        .session_update_age(Duration::zero());
    config.session.bearer = Some(Default::default());
    let auth = Arc::new(
        BetterAuth::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .build()
            .await
            .unwrap(),
    );
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("session@example.com"))
        .await
        .unwrap();
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    (database, auth, session.token)
}

fn request(token: &str) -> Parts {
    Request::builder()
        .header("authorization", format!("Bearer {token}"))
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[tokio::test]
async fn extractors_reject_expired_sessions() {
    for optional in [false, true] {
        let (_database, auth, token) = setup().await;
        let _ = auth
            .store()
            .update_session_expiry(&token, Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        let mut parts = request(&token);
        if optional {
            assert!(
                OptionalSession::<Schema>::from_request_parts(&mut parts, &auth)
                    .await
                    .unwrap()
                    .0
                    .is_none()
            );
        } else {
            assert_eq!(
                CurrentSession::<Schema>::from_request_parts(&mut parts, &auth)
                    .await
                    .err()
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
}

#[tokio::test]
async fn extractors_propagate_database_failure() {
    let (database, auth, token) = setup().await;
    database.close().await.unwrap();
    assert_eq!(
        CurrentSession::<Schema>::from_request_parts(&mut request(&token), &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        OptionalSession::<Schema>::from_request_parts(&mut request(&token), &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn extractor_refreshes_valid_sessions_through_session_manager() {
    let (_database, auth, token) = setup().await;
    let previous_expiry = Utc::now() + Duration::minutes(1);
    let _ = auth
        .store()
        .update_session_expiry(&token, previous_expiry)
        .await
        .unwrap();
    let session = CurrentSession::<Schema>::from_request_parts(&mut request(&token), &auth)
        .await
        .unwrap();
    assert!(session.session.expires_at > previous_expiry);
    assert_eq!(
        auth.store()
            .get_session(&token)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        session.session.expires_at
    );
}

#[tokio::test]
async fn extractors_propagate_session_refresh_write_failure() {
    let (database, auth, token) = setup().await;
    _ = database
        .execute_unprepared(
            "CREATE TRIGGER reject_session_refresh BEFORE UPDATE ON sessions
         BEGIN SELECT RAISE(ABORT, 'session refresh rejected'); END",
        )
        .await
        .unwrap();
    assert_eq!(
        CurrentSession::<Schema>::from_request_parts(&mut request(&token), &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        OptionalSession::<Schema>::from_request_parts(&mut request(&token), &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn extractors_reject_session_deleted_during_refresh() {
    for optional in [false, true] {
        let (database, auth, token) = setup().await;
        _ = database
            .execute_unprepared(
                "CREATE TRIGGER revoke_during_refresh BEFORE UPDATE ON sessions
             BEGIN DELETE FROM sessions WHERE id = OLD.id; SELECT RAISE(IGNORE); END",
            )
            .await
            .unwrap();
        let mut parts = request(&token);
        if optional {
            assert!(
                OptionalSession::<Schema>::from_request_parts(&mut parts, &auth)
                    .await
                    .unwrap()
                    .0
                    .is_none()
            );
        } else {
            assert_eq!(
                CurrentSession::<Schema>::from_request_parts(&mut parts, &auth)
                    .await
                    .err()
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert!(auth.store().get_session(&token).await.unwrap().is_none());
    }
}
