use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
use better_auth_core::types::{CreateSession, CreateUser, Session};
use chrono::{Duration, Utc};

use super::handlers::{link_social_core, social_sign_in_core};
use super::providers::{OAuthConfig, OAuthProvider};
use super::types::{LinkSocialRequest, SocialSignInRequest};
use crate::plugins::test_helpers;

fn test_oauth_config_with_google() -> OAuthConfig {
    let mut cfg = OAuthConfig::default();
    cfg.providers.insert(
        "google".to_string(),
        OAuthProvider::google("test-client-id", "test-client-secret"),
    );
    cfg
}

#[tokio::test]
async fn sign_in_social_rejects_untrusted_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("https://evil.example.com/cb".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn sign_in_social_rejects_relative_callback_url() {
    // OAuth `redirect_uri` must be absolute; a relative path would pass
    // any general redirect trust check but fail at token exchange.
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("/oauth/callback".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn sign_in_social_allows_trusted_origin_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context_with_trusted_origins(&["https://admin.test.com"]);

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("https://admin.test.com/oauth/cb".to_string()),
        scopes: None,
    };

    let response = social_sign_in_core(&body, &oauth, &ctx).await.unwrap();
    assert!(response.redirect);
}

#[tokio::test]
async fn sign_in_social_defaults_when_no_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: None,
        scopes: None,
    };

    let response = social_sign_in_core(&body, &oauth, &ctx).await.unwrap();
    assert!(response.redirect);
}

#[tokio::test]
async fn sign_in_social_rejects_backslash_authority_bypass() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("/\\evil.example.com".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

async fn seed_session(ctx: &better_auth_core::AuthContext<MemoryDatabaseAdapter>) -> Session {
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("link@test.com")
                .with_name("Link"),
        )
        .await
        .unwrap();
    ctx.database
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn link_social_rejects_untrusted_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();
    let session = seed_session(&ctx).await;

    let body = LinkSocialRequest {
        provider: "google".to_string(),
        callback_url: Some("https://evil.example.com/cb".to_string()),
        scopes: None,
    };

    let err = link_social_core(&body, &session, &oauth, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn link_social_allows_trusted_origin_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context_with_trusted_origins(&["https://admin.test.com"]);
    let session = seed_session(&ctx).await;

    let body = LinkSocialRequest {
        provider: "google".to_string(),
        callback_url: Some("https://admin.test.com/oauth/cb".to_string()),
        scopes: None,
    };

    let response = link_social_core(&body, &session, &oauth, &ctx)
        .await
        .unwrap();
    assert!(response.redirect);
}
