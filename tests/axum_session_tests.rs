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
    setup_with_cache(false).await
}

async fn setup_with_cache(cache: bool) -> (DatabaseConnection, Arc<BetterAuth<Schema>>, String) {
    let mut config = AuthConfig::new("session-extractor-test-secret-at-least-32-characters")
        .session_update_age(Duration::zero());
    config.session.bearer = Some(Default::default());
    if cache {
        config.session.cookie_cache = Some(better_auth::config::CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
    }
    setup_with_config(config).await
}

async fn setup_with_config(
    config: AuthConfig,
) -> (DatabaseConnection, Arc<BetterAuth<Schema>>, String) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let auth = Arc::new(
        BetterAuth::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .build()
            .await
            .unwrap(),
    );
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("session@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    (database, auth, session.token)
}

#[tokio::test]
async fn cached_extractor_preserves_cookies_and_avoids_database_reads_until_cache_rejection() {
    use axum::response::IntoResponse;
    use better_auth::integrations::axum::{CachedSession, OptionalCachedSession};

    let (database, auth, token) = setup_with_cache(true).await;
    let session = CachedSession::<Schema>::from_request_parts(&mut request(&token), &auth)
        .await
        .unwrap();
    let user_id = session.user.id.clone();
    let response = axum::http::Response::builder()
        .header("set-cookie", "application-preference=dark; Path=/")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = (session, response).into_response();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|header| {
            header
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie == "application-preference=dark")
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.session_data="))
    );
    let cookies = cookies.join("; ");
    database.close().await.unwrap();
    let mut parts = request(&token);
    let _ = parts.headers.insert("cookie", cookies.parse().unwrap());
    let session = CachedSession::<Schema>::from_request_parts(&mut parts, &auth)
        .await
        .unwrap();
    assert_eq!(session.user.id, user_id);
    assert_eq!(
        CurrentSession::<Schema>::from_request_parts(&mut parts, &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let _ = parts.headers.insert(
        "cookie",
        "better-auth.session_data=invalid".parse().unwrap(),
    );
    let rejection = CachedSession::<Schema>::from_request_parts(&mut parts, &auth)
        .await
        .err()
        .unwrap();
    assert_eq!(rejection.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        rejection
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|value| value.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        OptionalCachedSession::<Schema>::from_request_parts(&mut parts, &auth)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    assert!(
        OptionalCachedSession::<Schema>::from_request_parts(&mut request(""), &auth)
            .await
            .unwrap()
            .data
            .is_none()
    );
}

#[tokio::test]
async fn optional_cached_extractor_preserves_revoked_credential_cleanup() {
    use axum::response::IntoResponse;
    use better_auth::integrations::axum::{CachedSession, OptionalCachedSession};

    let (_, auth, token) = setup_with_cache(true).await;
    auth.store().delete_session(&token).await.unwrap();
    let optional = OptionalCachedSession::<Schema>::from_request_parts(&mut request(&token), &auth)
        .await
        .unwrap();
    assert!(optional.data.is_none());
    let response = (optional, "anonymous").into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let required = CachedSession::<Schema>::from_request_parts(&mut request(&token), &auth)
        .await
        .err()
        .unwrap();
    assert_eq!(required.status(), StatusCode::UNAUTHORIZED);
    for response in [response, required] {
        for name in ["better-auth.session_token=", "better-auth.session_data="] {
            assert!(
                response
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .any(|header| {
                        let value = header.to_str().unwrap();
                        value.starts_with(name) && value.contains("Max-Age=0")
                    })
            );
        }
    }
    let missing = OptionalCachedSession::<Schema>::from_request_parts(&mut request(""), &auth)
        .await
        .unwrap();
    assert!(missing.data.is_none());
    assert!(
        !(missing, "anonymous")
            .into_response()
            .headers()
            .contains_key("set-cookie")
    );
}

#[tokio::test]
async fn optional_cached_extractor_propagates_callback_unauthorized() {
    use better_auth::config::{CookieCacheConfig, CookieCacheVersion};
    use better_auth::integrations::axum::OptionalCachedSession;

    let mut config =
        AuthConfig::new("session-extractor-callback-test-secret-at-least-32-characters");
    config.session.bearer = Some(Default::default());
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        version: CookieCacheVersion::dynamic(|_| async {
            Err(better_auth::AuthError::Upstream {
                status: 401,
                code: "CACHE_VERSION_REJECTED",
                message: "Cache version rejected",
            })
        }),
        ..Default::default()
    });
    let (_, auth, token) = setup_with_config(config).await;
    let rejection =
        OptionalCachedSession::<Schema>::from_request_parts(&mut request(&token), &auth)
            .await
            .err()
            .unwrap();
    assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(rejection.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "CACHE_VERSION_REJECTED");
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
    assert!(session.session.expires_at.milliseconds() > previous_expiry.timestamp_millis() as f64);
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
