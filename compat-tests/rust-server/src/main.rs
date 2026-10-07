use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
mod oauth_proxy;
mod organization_callbacks;
mod organization_core_fields;
mod organization_dynamic_fields;
mod organization_fields;
mod organization_member_fields;
mod organization_native_json;
use better_auth::__private_core::AuthContext as InternalAuthContext;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::api_key::{
    ApiKeyConfig, ApiKeyReferences, CreateKeyRequest, UpdateKeyRequest, VerifyApiKey,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SendTwoFactorOtp, SessionManagementPlugin, TwoFactorPlugin,
    UserManagementPlugin,
    email_verification::SendVerificationEmail,
    oauth::{
        GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthIdTokenVerifier, OAuthProvider,
        OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
        OAuthUserInfoRequest, OAuthUserInfoResponse,
    },
    organization::{
        InvitationEmail, OrganizationConfig, OrganizationTeamsConfig, SendInvitationEmail,
    },
    password_management::SendResetPassword,
    user_management::SendChangeEmailConfirmation,
};
use better_auth::prelude::{AuthUser, CreateAccount, CreateVerification};
use better_auth::wire::UserView;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_seaorm::sea_orm::{DatabaseConnection, DbErr, EntityTrait};
use better_auth_seaorm::store::entities::{
    account, api_key, device_code, invitation, member, organization, passkey, session, two_factor,
    user, verification,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod account_http_output;
mod account_verification_fields;
mod admin_options;
mod api_error;
mod api_key_callbacks;
mod api_key_storage;
mod auth_lifecycle;
mod captcha;
mod cookie_version;
mod crypto;
mod custom_session;
mod database_lifecycle;
mod device_generators;
mod dispatch_errors;
mod dynamic_context;
mod dynamic_cookies;
mod dynamic_native;
mod dynamic_oauth;
mod email_otp;
mod email_otp_native;
mod email_otp_transaction;
mod http_body;
mod id_policy;
mod identity_context;
mod identity_routes;
mod jwt_adapter;
mod jwt_fixture;
mod jwt_session;
mod last_login;
mod native_dispatch;
mod oauth_link_id_token;
mod oauth_popup;
mod oidc;
mod one_tap;
mod openapi;
mod organization_metadata;
mod otp_callbacks;
mod passkey_native;
mod passkey_options;
mod password_policy;
mod password_security;
mod phone_native;
mod plugin_schema;
mod rate_limit_options;
mod request_query;
mod secondary_storage;
mod session_fields;
mod signup_enumeration;
mod stateless;
mod token_routes;
mod trailing_slashes;
mod two_factor_after;
mod two_factor_context;
mod two_factor_native;
mod two_factor_options;
mod user_admission;
mod user_fields;
mod username_options;
mod verification_date_output;

type TestSchema = user_fields::Schema;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyApiKeyBody {
    key: String,
    config_id: Option<String>,
    permissions: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct InvitationIdBody {
    id: String,
}

#[derive(Deserialize)]
struct InvitationSenderModeBody {
    fail: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResetPasswordMode {
    Capture,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthRefreshMode {
    Success,
    Error,
    Empty,
}

#[derive(Clone)]
struct CompatResetSender {
    outbox: Arc<Mutex<HashMap<String, String>>>,
    mode: Arc<Mutex<ResetPasswordMode>>,
}

struct CompatInvitationSender {
    outbox: Arc<Mutex<Vec<serde_json::Value>>>,
    fails: Arc<Mutex<bool>>,
}

#[async_trait::async_trait]
impl SendInvitationEmail for CompatInvitationSender {
    async fn send(&self, email: &InvitationEmail) -> better_auth::AuthResult<()> {
        if *self.fails.lock().await {
            return Err(better_auth::AuthError::internal(
                "compat invitation sender failure",
            ));
        }
        self.outbox.lock().await.push(serde_json::json!({
            "id": email.invitation.id,
            "email": email.invitation.email,
            "role": email.invitation.role,
        }));
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailOutboxRecord {
    url: String,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailOutboxRecord {
    new_email: String,
    url: String,
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SocialProfile {
    sub: String,
    email: String,
    name: String,
    image: Option<String>,
    #[serde(skip)]
    image_present: bool,
    email_verified: bool,
}

fn default_social_profile() -> SocialProfile {
    SocialProfile {
        sub: "google-account-id".to_string(),
        email: "google@example.com".to_string(),
        name: "Google Compat User".to_string(),
        image: None,
        image_present: false,
        email_verified: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubEmailRecord {
    email: String,
    primary: bool,
    verified: bool,
    visibility: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubProfile {
    id: String,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    emails: Vec<GitHubEmailRecord>,
}

fn default_github_profile() -> GitHubProfile {
    GitHubProfile {
        id: "github-account-id".to_string(),
        login: "github-compat-user".to_string(),
        name: None,
        email: None,
        avatar_url: Some("https://avatars.githubusercontent.com/u/1?v=4".to_string()),
        emails: vec![GitHubEmailRecord {
            email: "github@example.com".to_string(),
            primary: true,
            verified: true,
            visibility: Some("private".to_string()),
        }],
    }
}

async fn reset_database_state(database: &DatabaseConnection) -> Result<(), DbErr> {
    if organization_member_fields::enabled(&std::env::var("COMPAT_PROFILE").unwrap_or_default()) {
        organization_member_fields::reset(database).await?;
    }
    if std::env::var("COMPAT_PROFILE").as_deref() == Ok("organization-dynamic-fields") {
        organization_dynamic_fields::reset(database).await?;
    }
    organization_fields::reset(database).await?;
    if std::env::var("COMPAT_PROFILE").as_deref() == Ok("plugin-schema") {
        plugin_schema::reset(database).await?;
    }
    device_code::Entity::delete_many().exec(database).await?;
    if std::env::var("COMPAT_PROFILE").as_deref() == Ok("native-passkey") {
        passkey_native::reset(database).await?;
    } else {
        passkey::Entity::delete_many().exec(database).await?;
    }
    api_key::Entity::delete_many().exec(database).await?;
    if std::env::var("COMPAT_PROFILE").as_deref() == Ok("native-two-factor") {
        two_factor_native::reset(database).await?;
    } else {
        two_factor::Entity::delete_many().exec(database).await?;
    }
    better_auth_seaorm::store::entities::team_member::Entity::delete_many()
        .exec(database)
        .await?;
    better_auth_seaorm::store::entities::team::Entity::delete_many()
        .exec(database)
        .await?;
    better_auth_seaorm::store::entities::organization_role::Entity::delete_many()
        .exec(database)
        .await?;
    invitation::Entity::delete_many().exec(database).await?;
    member::Entity::delete_many().exec(database).await?;
    organization::Entity::delete_many().exec(database).await?;
    verification::Entity::delete_many().exec(database).await?;
    account::Entity::delete_many().exec(database).await?;
    session::Entity::delete_many().exec(database).await?;
    user::Entity::delete_many().exec(database).await?;

    Ok(())
}

#[async_trait::async_trait]
impl SendResetPassword for CompatResetSender {
    async fn send(
        &self,
        user: &serde_json::Value,
        _url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if *self.mode.lock().await == ResetPasswordMode::Fail {
            return Err(better_auth::AuthError::internal(
                "compat reset sender failure".to_string(),
            ));
        }

        if let Some(email) = user.get("email").and_then(|value| value.as_str()) {
            self.outbox
                .lock()
                .await
                .insert(email.to_string(), token.to_string());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatVerificationSender {
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
}

#[async_trait::async_trait]
impl SendVerificationEmail for CompatVerificationSender {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> better_auth::AuthResult<()> {
        if let Some(email) = user.email() {
            self.outbox.lock().await.insert(
                email.to_string(),
                EmailOutboxRecord {
                    url: url.to_string(),
                    token: token.to_string(),
                    metadata: None,
                },
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatTwoFactorOtpSender {
    outbox: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl SendTwoFactorOtp for CompatTwoFactorOtpSender {
    async fn send(&self, user: &UserView, otp: &str) -> better_auth::AuthResult<()> {
        if let Some(email) = user.email() {
            self.outbox
                .lock()
                .await
                .insert(email.to_string(), otp.to_string());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatChangeEmailSender {
    verification_outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
    outbox: Arc<Mutex<HashMap<String, ChangeEmailOutboxRecord>>>,
}

#[async_trait::async_trait]
impl SendChangeEmailConfirmation for CompatChangeEmailSender {
    async fn send(
        &self,
        user: &better_auth::plugins::user_management::UserInfo,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if user.email_verified {
            if let Some(email) = &user.email {
                self.outbox.lock().await.insert(
                    email.clone(),
                    ChangeEmailOutboxRecord {
                        new_email: new_email.to_string(),
                        url: url.to_string(),
                        token: token.to_string(),
                    },
                );
            }
        } else {
            self.verification_outbox.lock().await.insert(
                new_email.to_string(),
                EmailOutboxRecord {
                    url: url.to_string(),
                    token: token.to_string(),
                    metadata: None,
                },
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatGoogleUserInfoHandler {
    profile: Arc<Mutex<SocialProfile>>,
    preserve_image_null: bool,
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for CompatGoogleUserInfoHandler {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> better_auth::AuthResult<Option<OAuthUserInfoResponse>> {
        let profile = self.profile.lock().await.clone();
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: profile.sub.clone(),
                email: Some(profile.email.clone()).into(),
                name: Some(profile.name.clone()).into(),
                image: if self.preserve_image_null && profile.image_present {
                    Some(profile.image.clone())
                } else {
                    profile.image.clone().map(Some)
                },
                email_verified: Some(profile.email_verified).into(),
            },
            data: serde_json::json!({
                "sub": profile.sub,
                "email": profile.email,
                "name": profile.name,
                "picture": profile.image,
                "email_verified": profile.email_verified,
            }),
        }))
    }
}

#[derive(Clone)]
struct CompatGoogleIdTokenVerifier {
    valid: Arc<Mutex<bool>>,
}

#[async_trait::async_trait]
impl OAuthIdTokenVerifier for CompatGoogleIdTokenVerifier {
    async fn verify_id_token(
        &self,
        _token: &str,
        _nonce: Option<&str>,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<bool, String> {
        Ok(*self.valid.lock().await)
    }
}

#[derive(Clone)]
struct CompatGoogleRefreshHandler {
    mode: Arc<Mutex<OAuthRefreshMode>>,
}

#[async_trait::async_trait]
impl OAuthRefreshTokenHandler for CompatGoogleRefreshHandler {
    async fn refresh_access_token(
        &self,
        _refresh_token: &str,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        let mode = *self.mode.lock().await;
        if mode == OAuthRefreshMode::Error {
            return Err("invalid refresh token".to_string());
        }
        let token = |value: &str| {
            Some(if mode == OAuthRefreshMode::Empty {
                String::new()
            } else {
                value.to_owned()
            })
        };

        Ok(OAuthTokenSet {
            token_type: Some("Bearer".to_string()),
            access_token: token("google-access-token"),
            refresh_token: token("google-refresh-token"),
            access_token_expires_at: Some((Utc::now() + chrono::Duration::hours(1)).into()),
            refresh_token_expires_at: Some((Utc::now() + chrono::Duration::hours(2)).into()),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            id_token: token("google-id-token"),
            raw: None,
        })
    }
}

#[derive(Deserialize)]
struct ResetTokenQuery {
    email: String,
}

#[derive(Deserialize)]
struct EmailQuery {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserIdQuery {
    user_id: String,
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedResetPasswordRequest {
    email: String,
    token: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedDeleteUserTokenRequest {
    email: String,
    token: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveCredentialAccountRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedOAuthAccountRequest {
    email: String,
    provider_id: Option<String>,
    account_id: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<String>,
    refresh_token_expires_at: Option<String>,
    scope: Option<String>,
}

fn deserialize_social_image<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetSocialProfileRequest {
    sub: Option<String>,
    email: Option<String>,
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_social_image")]
    image: Option<Option<String>>,
    email_verified: Option<bool>,
    id_token_valid: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetGitHubProfileRequest {
    id: Option<String>,
    login: Option<String>,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    emails: Option<Vec<GitHubEmailRecord>>,
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc))
}

struct MockGenericUserInfo;

#[async_trait::async_trait]
impl GenericOAuthUserInfoHandler for MockGenericUserInfo {
    async fn get_user_info(
        &self,
        _tokens: &OAuthUserInfoRequest,
    ) -> better_auth::AuthResult<Option<serde_json::Value>> {
        Ok(Some(serde_json::json!({
            "id": "mock-account-id",
            "email": "mock@example.com",
            "name": "Mock OAuth User",
            "image": null,
            "emailVerified": true,
        })))
    }
}

fn mock_oauth_plugin(
    port: u16,
    social_profile: Arc<Mutex<SocialProfile>>,
    social_id_token_valid: Arc<Mutex<bool>>,
    oauth_refresh_mode: Arc<Mutex<OAuthRefreshMode>>,
    preserve_image_null: bool,
) -> OAuthPlugin {
    OAuthPlugin::new()
        .add_generic_provider(
            "mock",
            GenericOAuthConfig {
                client_id: "mock-client-id".to_string(),
                client_secret: Some("mock-client-secret".to_string()),
                end_session_endpoint: Some("https://idp.example.test/logout".to_string()),
                authorization_url: Some(format!("http://localhost:{port}/__test/oauth/authorize")),
                token_url: Some(format!("http://127.0.0.1:{port}/__test/oauth/token")),
                user_info_url: Some(format!("http://127.0.0.1:{port}/__test/oauth/userinfo")),
                scopes: vec!["openid".into(), "email".into(), "profile".into()],
                get_user_info: Some(Arc::new(MockGenericUserInfo)),
                ..Default::default()
            },
        )
        .add_provider(
            "github",
            OAuthProvider::github_with_endpoints(
                "github-client-id",
                "github-client-secret",
                &format!("http://localhost:{port}/__test/oauth/authorize"),
                &format!("http://127.0.0.1:{port}/__test/github/oauth/token"),
                &format!("http://127.0.0.1:{port}/__test/github/user"),
                &format!("http://127.0.0.1:{port}/__test/github/user/emails"),
            ),
        )
        .add_provider("google", {
            let mut provider = OAuthProvider::custom(
                "google-client-id",
                "google-client-secret",
                &format!("http://localhost:{port}/__test/oauth/authorize"),
                &format!("http://127.0.0.1:{port}/__test/oauth/token"),
            );
            provider.scopes = Some(vec![
                "email".to_string(),
                "profile".to_string(),
                "openid".to_string(),
            ]);
            provider.authorization_params = {
                let mut params = vec![("include_granted_scopes".to_string(), "true".to_string())];
                if std::env::var("COMPAT_PROFILE").as_deref() == Ok("one-tap-options") {
                    params.push(("hd".to_string(), "example.com".to_string()));
                }
                params
            };
            provider.get_user_info = Some(Arc::new(CompatGoogleUserInfoHandler {
                profile: social_profile,
                preserve_image_null,
            }));
            provider.refresh_access_token = Some(Arc::new(CompatGoogleRefreshHandler {
                mode: oauth_refresh_mode,
            }));
            provider.verify_id_token = Some(Arc::new(CompatGoogleIdTokenVerifier {
                valid: social_id_token_valid,
            }));
            provider.disable_implicit_sign_up = Some(false);
            provider.disable_sign_up = Some(false);
            provider
        })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3200);
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    let port = listener.local_addr()?.port();
    println!("COMPAT_SERVER_PORT={port}");
    if let Ok(case) = std::env::var("COMPAT_PROXY_CASE") {
        let case: serde_json::Value = serde_json::from_str(&case)?;
        let mut environment = case["env"].as_object().expect("case environment").clone();
        environment.insert(
            "COMPAT_PROXY_OPTIONS".into(),
            case["options"].to_string().into(),
        );
        for (key, value) in environment {
            let value = value
                .as_str()
                .expect("environment string")
                .replace("{base}", &format!("http://localhost:{port}"));
            // SAFETY: startup is single-threaded; the Tokio runtime is created below.
            unsafe { std::env::set_var(key, value) };
        }
    }
    listener.set_nonblocking(true)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            tracing_subscriber::fmt::init();
            run(TcpListener::from_std(listener)?, port).await
        })
}

async fn run(listener: TcpListener, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let secret = "compat-test-only-key-not-real-minimum-32chars";
    let device_profile = std::env::var("COMPAT_PROFILE").unwrap_or_default();
    if device_profile == "account-verification-fields" {
        let app = verification_date_output::router()
            .merge(account_verification_fields::router())
            .merge(account_http_output::router())
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route("/__health", axum::routing::get(|| async { "ok" }))
            .route(
                "/__test/reset-state",
                axum::routing::post(|| async { axum::Json(serde_json::json!({"success": true})) }),
            );
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("database-lifecycle") {
        let app = database_lifecycle::router(&device_profile, &format!("http://localhost:{port}"))
            .await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("two-factor-after-") {
        let app =
            two_factor_after::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("phone-native-") {
        let app =
            phone_native::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile == "native-dispatch" {
        let app = native_dispatch::router(&format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("request-oauth-")
        || device_profile.starts_with("request-otp-")
        || device_profile.starts_with("request-two-factor-")
        || device_profile.starts_with("request-security-")
        || device_profile.starts_with("request-admin-")
        || device_profile.starts_with("request-api-key-")
        || device_profile.starts_with("request-organization-")
        || device_profile.starts_with("request-query-")
        || device_profile.starts_with("request-record-")
        || device_profile.starts_with("request-plugin-")
        || device_profile.starts_with("request-change-email")
    {
        let app =
            request_query::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if matches!(
        device_profile.as_str(),
        "api-error" | "api-error-production"
    ) {
        let app = api_error::router(&format!("http://localhost:{port}"));
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("trailing-slashes-") {
        let app =
            trailing_slashes::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("username-") {
        let app =
            username_options::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile == "openapi" {
        axum::serve(listener, openapi::router()).await?;
        return Ok(());
    }
    if device_profile == "jwt-adapter" {
        axum::serve(
            listener,
            jwt_adapter::router(&format!("http://localhost:{port}")),
        )
        .await?;
        return Ok(());
    }
    if device_profile == "identity-context" {
        axum::serve(
            listener,
            identity_context::router(&format!("http://localhost:{port}")),
        )
        .await?;
        return Ok(());
    }
    if matches!(
        device_profile.as_str(),
        "dynamic-context"
            | "dynamic-native"
            | "dynamic-oauth"
            | "id-policy"
            | "organization-metadata"
    ) || device_profile.starts_with("dynamic-environment:")
    {
        axum::serve(listener, dynamic_context::router()).await?;
        return Ok(());
    }
    if device_profile == "dispatch-errors" {
        axum::serve(
            listener,
            dispatch_errors::router(&format!("http://localhost:{port}")),
        )
        .await?;
        return Ok(());
    }
    if device_profile == "rate-limit-options" {
        let app = rate_limit_options::router(&format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("last-login-") {
        let app = last_login::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    if device_profile.starts_with("stateless-") {
        let app = stateless::router(&device_profile, &format!("http://localhost:{port}")).await?;
        axum::serve(listener, app).await?;
        return Ok(());
    }
    let mut config = AuthConfig::new(secret)
        .base_url(format!("http://localhost:{port}"))
        .password_min_length(8);
    if let Ok(case) = std::env::var("COMPAT_PROXY_CASE") {
        let case: serde_json::Value = serde_json::from_str(&case)?;
        if let Some(base_url) = case["baseURL"].as_str() {
            config.base_url = base_url.into();
        }
        if let Some(origins) = case.get("trustedOrigins") {
            config.trusted_origins =
                Some(serde_json::from_value::<Vec<String>>(origins.clone())?.into());
        }
    }
    if device_profile == "organization-cache" {
        config.session.cookie_cache = Some(better_auth::config::CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
    }
    if device_profile == "device-bearer" {
        config.session.bearer = Some(Default::default());
    }
    if device_profile == "jwt-cache" {
        config.session.cookie_cache = Some(better_auth::config::CookieCacheConfig {
            enabled: Some(true),
            strategy: Some(better_auth::config::CookieCacheStrategy::Jwt),
            ..Default::default()
        });
    }
    let jwt_fixture = jwt_fixture::JwtFixture::new(&config, &device_profile).await?;
    if device_profile.starts_with("oauth-proxy") {
        config.account.account_linking.update_user_info_on_link = Some(true);
        if device_profile == "oauth-proxy-cookie" {
            config.account.store_state_strategy =
                Some(better_auth::config::OAuthStateStrategy::Cookie);
        }
    }

    if matches!(device_profile.as_str(), "user-fields" | "organization-jwt") {
        user_fields::configure(&mut config);
    }
    if matches!(
        device_profile.as_str(),
        "organization-callbacks" | "organization-custom-team" | "two-factor-context"
    ) {
        config.user.fields_mut().insert(
            "secretNote".into(),
            better_auth::config::UserFieldConfig {
                returned: Some(false),
                default_value: Some("hidden".into()),
                ..Default::default()
            },
        );
    }
    if device_profile == "organization-jwt" {
        config.session.cookie_cache.as_mut().unwrap().strategy =
            Some(better_auth::config::CookieCacheStrategy::Jwt);
        config
            .session
            .fields_mut()
            .insert("deviceLabel".into(), Default::default());
        config.session.fields_mut().insert(
            "internalNote".into(),
            better_auth::config::SessionFieldConfig {
                input: Some(false),
                returned: Some(false),
                ..Default::default()
            },
        );
    }
    secondary_storage::SecondaryFixture::configure(&device_profile, &mut config);
    session_fields::configure(&device_profile, &mut config);
    signup_enumeration::configure(&device_profile, &mut config);
    auth_lifecycle::AuthLifecycleFixture::configure(&device_profile, &mut config);
    crypto::configure(&device_profile, &mut config);
    http_body::configure(&device_profile, &mut config);
    email_otp_transaction::EmailOtpTransactionFixture::configure(&device_profile, &mut config);
    oauth_link_id_token::OAuthLinkIdTokenFixture::configure(&device_profile, &mut config);
    let oauth_popup_fixture = oauth_popup::OAuthPopupFixture::new(
        &device_profile,
        config.base_url.as_static().unwrap_or(""),
    );
    oauth_popup_fixture.configure(&device_profile, &mut config);
    let admin_options_fixture = admin_options::AdminOptionsFixture::default();
    admin_options_fixture.configure(&device_profile, &mut config);
    let captcha_fixture = captcha::CaptchaFixture::default();
    captcha_fixture.configure(&device_profile, &mut config);
    let captcha_plugin =
        captcha_fixture.plugin(&device_profile, config.base_url.as_static().unwrap_or(""));
    let cookie_version_fixture = cookie_version::CookieVersionFixture::default();
    cookie_version_fixture.configure(&device_profile, &mut config);
    let cookie_version_router = cookie_version_fixture.router();
    let passkey_options = passkey_options::PasskeyOptions::new(&device_profile);
    passkey_options.configure(&mut config);
    let custom_session = custom_session::CustomSessionFixture::new(&device_profile);
    custom_session.configure(&mut config);
    let custom_session_router = custom_session.router();
    let database = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    user_fields::add_columns(&database).await?;
    organization_fields::create_tables(&database).await?;
    if organization_member_fields::enabled(&device_profile) {
        organization_member_fields::create_tables(&database).await?;
    }
    if device_profile == "organization-dynamic-fields" {
        organization_dynamic_fields::create_tables(&database).await?;
    }
    if device_profile == "plugin-schema" {
        plugin_schema::create_tables(&database).await?;
    }
    if device_profile == "native-passkey" {
        passkey_native::create_tables(&database).await?;
    }
    if device_profile == "native-two-factor" {
        two_factor_native::create_tables(&database).await?;
    }
    let disabled_user_router = if device_profile == "user-fields" {
        user_fields::disabled_router(config.clone(), database.clone()).await?
    } else {
        Router::new()
    };
    let reset_database = database.clone();

    let reset_outbox = Arc::new(Mutex::new(HashMap::new()));
    let verification_outbox = Arc::new(Mutex::new(HashMap::new()));
    let change_email_outbox = Arc::new(Mutex::new(HashMap::new()));
    let two_factor_otp_outbox = Arc::new(Mutex::new(HashMap::new()));
    let two_factor_context = two_factor_context::TwoFactorContextFixture::default();
    let two_factor_context_router = two_factor_context.router();
    let invitation_email_outbox = Arc::new(Mutex::new(Vec::new()));
    let invitation_sender_fails = Arc::new(Mutex::new(false));
    let reset_password_mode = Arc::new(Mutex::new(ResetPasswordMode::Capture));
    let oauth_refresh_mode = Arc::new(Mutex::new(OAuthRefreshMode::Success));
    let social_profile = Arc::new(Mutex::new(default_social_profile()));
    let github_profile = Arc::new(Mutex::new(default_github_profile()));
    let social_id_token_valid = Arc::new(Mutex::new(true));

    let secondary_fixture =
        secondary_storage::SecondaryFixture::new(&device_profile, database.clone());
    let oauth_link_id_token_fixture = oauth_link_id_token::OAuthLinkIdTokenFixture::default();
    let mut hooks = if passkey_options.enabled() {
        vec![passkey_options.hooks()]
    } else {
        secondary_fixture.hooks()
    };
    if oauth_link_id_token::OAuthLinkIdTokenFixture::enabled(&device_profile) {
        hooks.push(oauth_link_id_token_fixture.hooks());
    }
    if [
        "admin-default-options",
        "admin-empty-roles",
        "admin-options",
    ]
    .contains(&device_profile.as_str())
    {
        hooks.push(admin_options_fixture.hooks());
    }
    if device_profile.starts_with("oauth-popup-") {
        hooks.push(oauth_popup_fixture.hooks());
    }
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), database).with_hooks(hooks);
    let store: Arc<dyn better_auth::store::AuthStore<TestSchema>> =
        if device_profile == "organization-fields" {
            Arc::new(store.with_organization_schema::<organization_fields::models::Models>())
        } else if organization_member_fields::enabled(&device_profile) {
            Arc::new(store.with_organization_schema::<organization_member_fields::Models>())
        } else if device_profile == "organization-dynamic-fields" {
            Arc::new(store.with_organization_schema::<organization_dynamic_fields::Models>())
        } else if device_profile == "plugin-schema" {
            Arc::new(store.with_plugin_schema::<plugin_schema::Models>())
        } else if device_profile == "native-passkey" {
            Arc::new(store.with_plugin_schema::<passkey_native::Models>())
        } else if device_profile == "native-two-factor" {
            Arc::new(store.with_plugin_schema::<two_factor_native::Models>())
        } else {
            Arc::new(store)
        };
    if device_profile == "native-passkey" {
        assert_eq!(
            store.passkey_storage(),
            better_auth_core::PasskeyStorage::Native
        );
    }
    let passkey_options_router = passkey_options.router(store.clone());
    let organization_callbacks =
        organization_callbacks::OrganizationCallbacks::new(&device_profile);
    let organization_callbacks_router = organization_callbacks.router();
    let identity_fixture = identity_routes::IdentityFixture::default();
    let identity_router = identity_fixture.router(Arc::new(SeaOrmStore::<TestSchema>::new(
        config.clone(),
        reset_database.clone(),
    )));
    let email_otp_fixture = email_otp::EmailOtpFixture::default();
    let email_otp_native_fixture = email_otp_native::EmailOtpNativeFixture::default();
    let email_otp_transaction_fixture =
        email_otp_transaction::EmailOtpTransactionFixture::default();
    let otp_callbacks = otp_callbacks::OtpCallbacksFixture::default();
    let password_security_fixture = password_security::PasswordSecurityFixture::new().await;
    let auth_lifecycle_fixture = auth_lifecycle::AuthLifecycleFixture::default();
    let user_admission_fixture = user_admission::UserAdmissionFixture::default();
    let device_generators_fixture = device_generators::DeviceGenerators::default();
    let otp_callbacks_router = otp_callbacks.router();
    let api_key_storage_fixture = api_key_storage::ApiKeyStorageFixture::default();
    let api_key_callbacks = api_key_callbacks::ApiKeyCallbacks::default();
    let one_tap_fixture = one_tap::OneTapFixture::default();
    let one_tap_router = one_tap_fixture.router();
    let email_otp_router = email_otp_fixture.router(Arc::new(SeaOrmStore::<TestSchema>::new(
        config.clone(),
        reset_database.clone(),
    )));
    let two_factor_plugin =
        TwoFactorPlugin::with_config(two_factor_options::configure(&device_profile));
    let two_factor_plugin = if device_profile == "two-factor-context" {
        two_factor_plugin
    } else {
        two_factor_plugin.custom_send_otp(Arc::new(CompatTwoFactorOtpSender {
            outbox: two_factor_otp_outbox.clone(),
        }))
    };
    let two_factor_options_router =
        two_factor_options::router(reset_database.clone(), two_factor_plugin.clone());
    let api_key_plugin = ApiKeyPlugin::builder()
        .enable_metadata(true)
        .key_length(
            if std::env::var("COMPAT_PROFILE").as_deref() == Ok("api-key-zero") {
                0
            } else {
                64
            },
        )
        .build()
        .configuration(ApiKeyConfig {
            config_id: "secondary".to_string(),
            enable_metadata: true,
            ..ApiKeyConfig::default()
        })
        .configuration(ApiKeyConfig {
            config_id: "organization".to_string(),
            references: ApiKeyReferences::Organization,
            enable_metadata: true,
            ..ApiKeyConfig::default()
        });
    let api_key_plugin = api_key_plugin.configuration(ApiKeyConfig {
        config_id: "session".to_string(),
        enable_session_for_api_keys: true,
        api_key_headers: vec!["x-api-key".to_string(), "x-machine-key".to_string()],
        ..ApiKeyConfig::default()
    });
    let api_key_plugin =
        ["shared-first", "shared-second"]
            .into_iter()
            .fold(api_key_plugin, |plugin, id| {
                plugin.configuration(ApiKeyConfig {
                    config_id: id.to_string(),
                    enable_session_for_api_keys: true,
                    api_key_headers: vec!["x-shared-key".to_string()],
                    ..ApiKeyConfig::default()
                })
            });
    let device_plugin = match device_profile.as_str() {
        "device-rate-window" => {
            DeviceAuthorizationPlugin::new().expires_in(chrono::Duration::seconds(2))
        }
        "device-custom" => DeviceAuthorizationPlugin::new()
            .generate_user_code_with(|| async { Ok("custom-code".to_string()) }),
        "device-collision" => {
            let issued = std::sync::atomic::AtomicUsize::new(0);
            DeviceAuthorizationPlugin::new().generate_user_code_with(move || {
                let value = match issued.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
                    0..2 => "same-code".to_string(),
                    2..6 => "next-code".to_string(),
                    _ => "after-code".to_string(),
                };
                async move { Ok(value) }
            })
        }
        _ => DeviceAuthorizationPlugin::new(),
    };
    let device_plugin = device_generators_fixture.apply(&device_profile, device_plugin);
    let mut organization_config = OrganizationConfig {
        cancel_pending_invitations_on_re_invite: device_profile
            .starts_with("organization-invitation-"),
        require_email_verification_on_invitation: device_profile
            == "organization-invitation-options",
        invitation_limit: if device_profile.starts_with("organization-invitation-") {
            Some(1)
        } else {
            Some(100)
        },
        teams: OrganizationTeamsConfig {
            enabled: device_profile.starts_with("organization-"),
            default_team: device_profile != "organization-limits",
            allow_removing_all_teams: device_profile == "organization-limits",
            maximum_teams: (device_profile == "organization-limits").then_some(2),
            maximum_members_per_team: (device_profile == "organization-limits").then_some(1),
            ..Default::default()
        },
        dynamic_access_control: device_profile.starts_with("organization-"),
        maximum_roles_per_organization: (device_profile == "organization-limits").then_some(1),
        ac: (device_profile.starts_with("organization-") && device_profile != "organization-no-ac")
            .then(|| {
                HashMap::from([
                    (
                        "organization".to_string(),
                        vec!["update".to_string(), "delete".to_string()],
                    ),
                    (
                        "member".to_string(),
                        vec![
                            "create".to_string(),
                            "update".to_string(),
                            "delete".to_string(),
                        ],
                    ),
                    (
                        "invitation".to_string(),
                        vec!["create".to_string(), "cancel".to_string()],
                    ),
                    (
                        "team".to_string(),
                        vec![
                            "create".to_string(),
                            "update".to_string(),
                            "delete".to_string(),
                        ],
                    ),
                    (
                        "ac".to_string(),
                        vec![
                            "create".to_string(),
                            "read".to_string(),
                            "update".to_string(),
                            "delete".to_string(),
                        ],
                    ),
                ])
            }),
        ..Default::default()
    };
    if device_profile == "organization-fields" {
        organization_fields::configure(&mut organization_config);
    }
    if device_profile == "organization-empty-roles" {
        organization_config.roles = Some(HashMap::new());
    }
    if device_profile == "organization-core-fields" {
        organization_core_fields::configure(&mut organization_config);
    }
    if organization_member_fields::enabled(&device_profile) {
        organization_member_fields::configure(&mut organization_config, &device_profile);
    }
    if device_profile == "organization-dynamic-fields" {
        organization_dynamic_fields::configure(&mut organization_config);
    }
    if device_profile.starts_with("organization-native-json") {
        organization_native_json::configure(&mut organization_config, &device_profile);
    }
    let organization_plugin = organization_callbacks.apply(
        OrganizationPlugin::with_config(organization_config).custom_send_invitation_email(
            Arc::new(CompatInvitationSender {
                outbox: invitation_email_outbox.clone(),
                fails: invitation_sender_fails.clone(),
            }),
        ),
    );
    let api_key_plugin = if device_profile == "api-key-storage" {
        api_key_storage_fixture.plugin(api_key_plugin)
    } else {
        api_key_plugin
    };
    let api_key_plugin = api_key_callbacks.apply(&device_profile, api_key_plugin);
    if device_profile == "api-key-storage" {
        config.session.store_session_in_database = Some(true);
        config.verification.store_in_database = true;
    }
    let builder = AuthBuilder::<TestSchema>::new(config)
        .store_arc(store)
        .rate_limit(captcha::CaptchaFixture::rate_limit(
            &device_profile,
            RateLimitConfig::new().enabled(matches!(
                device_profile.as_str(),
                "device-rate-limit" | "device-rate-window"
            )),
        ));
    let builder = if device_profile.starts_with("captcha-") {
        builder
            .plugin(captcha_plugin)
            .plugin(captcha_fixture.clone())
    } else {
        builder
    };
    let builder = if device_profile.starts_with("password-security")
        && device_profile != "password-security-after"
    {
        builder.plugin(password_security_fixture.plugin(&device_profile))
    } else {
        builder
    };
    let builder = builder
        .plugin(email_otp_transaction::EmailOtpTransactionFixture::password(
            &device_profile,
            user_admission_fixture.password(
                &device_profile,
                signup_enumeration::plugin(
                    &device_profile,
                    password_policy::configure(
                        &device_profile,
                        password_security_fixture.configure(
                            &device_profile,
                            EmailPasswordPlugin::new()
                                .enable_signup(true)
                                .username(true),
                        ),
                    ),
                ),
            ),
        ))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(device_plugin)
        .plugin(api_key_plugin.clone())
        .plugin(organization_plugin.clone())
        .plugin(admin_options_fixture.plugin(&device_profile, AdminPlugin::new()))
        .plugin(passkey_options.apply(PasskeyPlugin::new()))
        .plugin(auth_lifecycle_fixture.password(
            &device_profile,
            PasswordManagementPlugin::new().send_reset_password(Arc::new(CompatResetSender {
                outbox: reset_outbox.clone(),
                mode: reset_password_mode.clone(),
            })),
        ))
        .plugin({
            let plugin = EmailVerificationPlugin::new()
                .auto_sign_in_after_verification(device_profile == "email-otp-options");
            let plugin = if device_profile == "otp-callbacks-override" {
                plugin.send_on_sign_up(true)
            } else {
                plugin
            };
            if matches!(
                device_profile.as_str(),
                "email-otp-reuse" | "otp-callbacks-override"
            ) {
                plugin
            } else {
                plugin.custom_send_verification_email(Arc::new(CompatVerificationSender {
                    outbox: verification_outbox.clone(),
                }))
            }
        })
        .plugin(
            auth_lifecycle_fixture.users(
                &device_profile,
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .send_change_email_confirmation(Arc::new(CompatChangeEmailSender {
                        verification_outbox: verification_outbox.clone(),
                        outbox: change_email_outbox.clone(),
                    }))
                    .delete_user_enabled(true),
            ),
        )
        .plugin(two_factor_context.plugin::<TestSchema>(
            &device_profile,
            two_factor_plugin.clone(),
            two_factor_otp_outbox.clone(),
        ))
        .plugin(oauth_popup_fixture.oauth(oauth_link_id_token_fixture.oauth(
            &device_profile,
            oidc::configure(mock_oauth_plugin(
                port,
                social_profile.clone(),
                social_id_token_valid.clone(),
                oauth_refresh_mode.clone(),
                device_profile.starts_with("oauth-proxy"),
            )),
        )));
    let builder = if device_profile.starts_with("oauth-popup-") {
        builder
            .plugin(oauth_popup_fixture.clone())
            .plugin(better_auth::plugins::oauth::OAuthPopupPlugin::new())
    } else {
        builder
    };
    let builder = if device_profile == "password-security-after" {
        builder.plugin(password_security_fixture.plugin(&device_profile))
    } else {
        builder
    };
    let builder = if (device_profile.starts_with("email-otp")
        && !device_profile.starts_with("email-otp-native")
        && device_profile != "email-otp-transaction")
        || device_profile == "user-fields"
    {
        builder.plugin(email_otp_fixture.plugin(&device_profile))
    } else {
        builder
    };
    let builder = if device_profile == "plugin-schema" {
        builder.plugin(better_auth::plugins::JwtPlugin::new())
    } else {
        builder
    };
    let builder = token_routes::add_plugins(builder, &device_profile, verification_outbox.clone());
    let builder = if matches!(
        device_profile.as_str(),
        "otp-callbacks" | "otp-callbacks-override"
    ) {
        builder
            .plugin(otp_callbacks.email(&device_profile))
            .plugin(otp_callbacks.phone())
    } else {
        builder
    };
    let builder = if custom_session.enabled() {
        builder
            .plugin(better_auth::plugins::MultiSessionPlugin::new())
            .plugin(custom_session.plugin())
    } else {
        builder
    };
    let builder = if [
        "jwt-ps256",
        "jwt-es512",
        "jwt-advanced",
        "jwt-remote",
        "jwt-cache",
        "organization-jwt",
        "cookie-version-plugin-jwt",
        "jwt-claims",
        "jwt-date",
        "jwt-relative",
    ]
    .contains(&device_profile.as_str())
    {
        builder.plugin(jwt_fixture.plugin())
    } else {
        builder
    };
    let builder = if device_profile.starts_with("one-tap") {
        builder.plugin(one_tap_fixture.plugin(port, &device_profile))
    } else {
        builder
    };
    let builder = identity_fixture.add_plugins(builder, &device_profile);
    let builder = user_admission_fixture.builder(&device_profile, builder);
    let builder = email_otp_native_fixture.builder(&device_profile, builder);
    let builder = email_otp_transaction_fixture.builder(&device_profile, builder);
    let builder = oauth_link_id_token_fixture.builder(&device_profile, builder);
    let builder = if device_profile.starts_with("oauth-proxy") {
        builder.plugin(oauth_proxy::plugin(port))
    } else {
        builder
    };
    let builder = if device_profile == "api-key-storage" {
        builder.secondary_storage(api_key_storage_fixture.secondary_storage())
    } else {
        builder
    };
    let builder = if let Some(storage) = secondary_fixture.storage() {
        builder.secondary_storage(storage)
    } else {
        builder
    };
    let auth = Arc::new(builder.build().await?);
    let captcha_router = captcha_fixture.router(auth.clone());
    let email_otp_native_router = email_otp_native_fixture.router(auth.clone());
    let email_otp_transaction_router = email_otp_transaction_fixture.router(auth.clone());
    let oauth_link_id_token_router = oauth_link_id_token_fixture.router(auth.clone());
    let oauth_popup_router = oauth_popup_fixture.router(auth.clone());
    let admin_options_router = admin_options_fixture.router(auth.clone());
    let crypto_router = crypto::router(auth.clone());
    let user_admission_router = user_admission_fixture.router(auth.clone());
    let device_generators_router = device_generators_fixture.router(reset_database.clone());
    let password_security_router = password_security_fixture.router(auth.store().clone());
    let auth_lifecycle_router = auth_lifecycle_fixture.router(auth.clone(), reset_database.clone());
    let secondary_router = secondary_fixture.router(auth.clone());
    let api_key_storage_router = api_key_storage_fixture.router(auth.clone());
    let api_key_callbacks_router = api_key_callbacks.router(auth.clone(), api_key_plugin.clone());

    let auth_router = auth.clone().axum_router();
    let jwt_router = jwt_fixture.router(auth.clone());

    let reset_outbox_for_token = reset_outbox.clone();
    let reset_outbox_for_reset = reset_outbox.clone();
    let verification_outbox_for_get = verification_outbox.clone();
    let verification_outbox_for_reset = verification_outbox.clone();
    let change_email_outbox_for_get = change_email_outbox.clone();
    let change_email_outbox_for_reset = change_email_outbox.clone();
    let two_factor_otp_outbox_for_get = two_factor_otp_outbox.clone();
    let two_factor_otp_outbox_for_reset = two_factor_otp_outbox.clone();
    let invitation_email_outbox_for_get = invitation_email_outbox.clone();
    let invitation_email_outbox_for_reset = invitation_email_outbox.clone();
    let invitation_sender_fails_for_set = invitation_sender_fails.clone();
    let invitation_sender_fails_for_reset = invitation_sender_fails.clone();
    let reset_mode_for_reset = reset_password_mode.clone();
    let reset_mode_for_set = reset_password_mode.clone();
    let oauth_mode_for_reset = oauth_refresh_mode.clone();
    let oauth_mode_for_set = oauth_refresh_mode.clone();
    let oauth_mode_for_token = oauth_refresh_mode.clone();
    let oauth_mode_for_github_token = oauth_refresh_mode.clone();
    let social_profile_for_reset = social_profile.clone();
    let social_profile_for_set = social_profile.clone();
    let github_profile_for_reset = github_profile.clone();
    let github_profile_for_set = github_profile.clone();
    let github_profile_for_user = github_profile.clone();
    let github_profile_for_emails = github_profile.clone();
    let social_id_token_valid_for_reset = social_id_token_valid.clone();
    let social_id_token_valid_for_set = social_id_token_valid.clone();
    let database_for_reset = reset_database.clone();
    let auth_for_reset_seed = auth.clone();
    let auth_for_delete_seed = auth.clone();
    let auth_for_remove_credential = auth.clone();
    let auth_for_oauth_seed = auth.clone();
    let auth_for_promote_admin = auth.clone();
    let auth_for_view_backup_codes = auth.clone();
    let auth_for_invitation_expiry = auth.clone();
    let two_factor_plugin_for_view_backup_codes = two_factor_plugin.clone();

    let auth_for_organization_member = auth.clone();
    let auth_for_api_key_create = auth.clone();
    let auth_for_api_key_update = auth.clone();
    let auth_for_api_key_verify = auth.clone();
    let api_key_for_create = api_key_plugin.clone();
    let api_key_for_update = api_key_plugin.clone();

    let app = Router::new()
        .route("/__test/organization-add-member", post(move |headers: axum::http::HeaderMap, Json(body): Json<better_auth::plugins::organization::AddMemberInput>| {
            let auth = auth_for_organization_member.clone();
            let plugin = organization_plugin.clone();
            async move {
                let mut request = better_auth_core::AuthRequest::new(better_auth_core::HttpMethod::Post, "/__test/organization-add-member");
                for (name, value) in headers { if let Some(name) = name { request.headers.insert(name.as_str().to_owned(), value.to_str().unwrap_or_default().to_owned()); } }
                match plugin.add_member(body, Some(&request), auth.context()).await {
                    Ok(member) => Json(serde_json::to_value(member).unwrap()).into_response(),
                    Err(better_auth::AuthError::Unauthenticated) => (axum::http::StatusCode::UNAUTHORIZED, [(axum::http::header::CONTENT_TYPE, "application/json")]).into_response(),
                    Err(error) => { let response = error.to_auth_response(); (axum::http::StatusCode::from_u16(response.status).unwrap(), [(axum::http::header::CONTENT_TYPE, "application/json")], response.body).into_response() }
                }
            }
        }))
        .route("/__health", get(health_check))
        .route(
            "/__test/api-key/create",
            post(move |Json(body): Json<CreateKeyRequest>| {
                let auth = auth_for_api_key_create.clone();
                let plugin = api_key_for_create.clone();
                async move {
                    let ctx = auth.context();
                    match plugin.create_key(ctx, &body).await {
                        Ok(key) => Json(key).into_response(),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.status_code()).unwrap(),
                            Json(serde_json::json!({ "message": error.to_string() })),
                        )
                            .into_response(),
                    }
                }
            }),
        )
        .route(
            "/__test/api-key/update",
            post(move |Json(body): Json<UpdateKeyRequest>| {
                let auth = auth_for_api_key_update.clone();
                let plugin = api_key_for_update.clone();
                async move {
                    let ctx = auth.context();
                    match plugin.update_key(ctx, &body).await {
                        Ok(key) => Json(key).into_response(),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.status_code()).unwrap(),
                            Json(serde_json::json!({ "message": error.to_string() })),
                        )
                            .into_response(),
                    }
                }
            }),
        )
        .route(
            "/__test/api-key/verify",
            post(move |Json(body): Json<VerifyApiKeyBody>| {
                let auth = auth_for_api_key_verify.clone();
                let plugin = api_key_plugin.clone();
                async move {
                    let ctx = auth.context();
                    let input = VerifyApiKey {
                        key: &body.key,
                        config_id: body.config_id.as_deref(),
                        permissions: body.permissions.as_ref(),
                    };
                    match plugin.verify_api_key(&input, ctx).await {
                        Ok(key) => {
                            #[derive(serde::Serialize)]
                            struct VerifiedKey<T> {
                                valid: bool,
                                error: Option<()>,
                                key: T,
                            }
                            Json(VerifiedKey {
                                valid: true,
                                error: None,
                                key,
                            })
                            .into_response()
                        }
                        Err(error) => {
                            let response = error.into_response().unwrap();
                            (axum::http::StatusCode::from_u16(response.status).unwrap(),
                                [(axum::http::header::CONTENT_TYPE, "application/json")], response.body).into_response()
                        }
                    }
                }
            }),
        )
        .route(
            "/__test/invitation-sender-mode",
            post(move |Json(body): Json<InvitationSenderModeBody>| {
                let fails = invitation_sender_fails_for_set.clone();
                async move {
                    *fails.lock().await = body.fail;
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/invitation-emails",
            get(move |Query(query): Query<EmailQuery>| {
                let outbox = invitation_email_outbox_for_get.clone();
                async move {
                    Json(
                        outbox
                            .lock()
                            .await
                            .iter()
                            .filter(|record| record["email"] == query.email)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                }
            }),
        )
        .route(
            "/__test/shorten-invitation-expiry",
            post(move |Json(body): Json<InvitationIdBody>| {
                let auth = auth_for_invitation_expiry.clone();
                async move {
                    let expires_at = Utc::now() + chrono::Duration::hours(1);
                    match auth
                        .store()
                        .update_invitation_expiry(&body.id, expires_at)
                        .await
                    {
                        Ok(invitation) => {
                            Json(serde_json::json!({ "expiresAt": invitation.expires_at }))
                                .into_response()
                        }
                        Err(error) => (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        )
                            .into_response(),
                    }
                }
            }),
        )
        .route(
            "/__test/verification-email",
            get(move |Query(query): Query<EmailQuery>| {
                let verification_outbox = verification_outbox_for_get.clone();
                async move {
                    let record = verification_outbox.lock().await.get(&query.email).cloned();
                    match record {
                        Some(record) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::to_value(record).unwrap()),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/change-email-confirmation",
            get(move |Query(query): Query<EmailQuery>| {
                let change_email_outbox = change_email_outbox_for_get.clone();
                async move {
                    let record = change_email_outbox.lock().await.get(&query.email).cloned();
                    match record {
                        Some(record) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::to_value(record).unwrap()),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/reset-password-token",
            get(move |Query(query): Query<ResetTokenQuery>| {
                let reset_outbox = reset_outbox_for_token.clone();
                async move {
                    let token = reset_outbox.lock().await.remove(&query.email);
                    match token {
                        Some(token) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({ "token": token })),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/two-factor-otp",
            get(move |Query(query): Query<EmailQuery>| {
                let two_factor_otp_outbox = two_factor_otp_outbox_for_get.clone();
                async move {
                    let record = two_factor_otp_outbox
                        .lock()
                        .await
                        .get(&query.email)
                        .cloned();
                    match record {
                        Some(otp) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({ "otp": otp })),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/view-backup-codes",
            get(move |Query(query): Query<UserIdQuery>| {
                let auth = auth_for_view_backup_codes.clone();
                let two_factor_plugin = two_factor_plugin_for_view_backup_codes.clone();
                async move {
                    let ctx = InternalAuthContext::new(
                        Arc::new(auth.config().clone()),
                        auth.store().clone(),
                    );
                    match two_factor_plugin
                        .view_backup_codes(&query.user_id, &ctx)
                        .await
                    {
                        Ok(backup_codes) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({
                                "status": true,
                                "backupCodes": backup_codes,
                            })),
                        ),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.status_code())
                                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
                            Json(serde_json::json!({
                                "message": error.to_string(),
                            })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/reset-state",
            post(move || {
                let identity_fixture = identity_fixture.clone();
                let email_otp_fixture = email_otp_fixture.clone();
                let email_otp_native_fixture = email_otp_native_fixture.clone();
                let email_otp_transaction_fixture = email_otp_transaction_fixture.clone();
                let oauth_link_id_token_fixture = oauth_link_id_token_fixture.clone();
                let oauth_popup_fixture = oauth_popup_fixture.clone();
                let admin_options_fixture = admin_options_fixture.clone();
                let otp_callbacks = otp_callbacks.clone();
                let password_security_fixture = password_security_fixture.clone();
                let auth_lifecycle_fixture = auth_lifecycle_fixture.clone();
                let captcha_fixture = captcha_fixture.clone();
                let user_admission_fixture = user_admission_fixture.clone();
                let device_generators_fixture = device_generators_fixture.clone();
                let api_key_storage_fixture = api_key_storage_fixture.clone();
                let secondary_fixture = secondary_fixture.clone();
                let cookie_version_fixture = cookie_version_fixture.clone();
                let passkey_options = passkey_options.clone();
                let custom_session = custom_session.clone();
                let api_key_callbacks = api_key_callbacks.clone();
                let one_tap_fixture = one_tap_fixture.clone();
                let organization_callbacks = organization_callbacks.clone();
                let reset_outbox = reset_outbox_for_reset.clone();
                let verification_outbox = verification_outbox_for_reset.clone();
                let change_email_outbox = change_email_outbox_for_reset.clone();
                let two_factor_otp_outbox = two_factor_otp_outbox_for_reset.clone();
                let two_factor_context = two_factor_context.clone();
                let invitation_email_outbox = invitation_email_outbox_for_reset.clone();
                let invitation_sender_fails = invitation_sender_fails_for_reset.clone();
                let reset_mode = reset_mode_for_reset.clone();
                let oauth_mode = oauth_mode_for_reset.clone();
                let social_profile = social_profile_for_reset.clone();
                let github_profile = github_profile_for_reset.clone();
                let social_id_token_valid = social_id_token_valid_for_reset.clone();
                let database = database_for_reset.clone();
                async move {
                    if let Err(error) = reset_database_state(&database).await {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }
                    reset_outbox.lock().await.clear();
                    identity_fixture.reset().await;
                    email_otp_fixture.reset().await;
                    email_otp_native_fixture.reset();
                    email_otp_transaction_fixture.reset();
                    oauth_link_id_token_fixture.reset();
                    admin_options_fixture.reset();
                    oauth_popup_fixture.reset();
                    otp_callbacks.reset().await;
                    password_security_fixture.reset();
                    auth_lifecycle_fixture.reset().await;
                    captcha_fixture.reset().await;
                    user_admission_fixture.reset();
                    device_generators_fixture.reset();
                    api_key_storage_fixture.reset();
                    secondary_fixture.reset();
                    cookie_version_fixture.reset();
                    passkey_options.reset();
                    custom_session.reset();
                    two_factor_context.reset();
                    api_key_callbacks.reset().await;
                    one_tap_fixture.reset().await;
                    organization_callbacks.reset().await;
                    verification_outbox.lock().await.clear();
                    change_email_outbox.lock().await.clear();
                    two_factor_otp_outbox.lock().await.clear();
                    invitation_email_outbox.lock().await.clear();
                    *invitation_sender_fails.lock().await = false;
                    *reset_mode.lock().await = ResetPasswordMode::Capture;
                    *oauth_mode.lock().await = OAuthRefreshMode::Success;
                    *social_profile.lock().await = default_social_profile();
                    *github_profile.lock().await = default_github_profile();
                    *social_id_token_valid.lock().await = true;
                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/set-reset-password-mode",
            post(move |Json(body): Json<ModeRequest>| {
                let reset_mode = reset_mode_for_set.clone();
                async move {
                    *reset_mode.lock().await = if body.mode == "throw" {
                        ResetPasswordMode::Fail
                    } else {
                        ResetPasswordMode::Capture
                    };
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/seed-reset-password-token",
            post(move |Json(body): Json<SeedResetPasswordRequest>| {
                let auth = auth_for_reset_seed.clone();
                async move {
                    let user = match auth.store().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let expires_at = match parse_rfc3339(&body.expires_at) {
                        Ok(expires_at) => expires_at,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    if let Err(error) = auth
                        .store()
                        .create_verification(CreateVerification {
identifier: (format!("reset-password:{}", body.token)).into(),
value: (user.id.typed().unwrap().to_string()).into(),
expires_at: (expires_at).into(),
..Default::default()
})
                        .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/seed-delete-user-token",
            post(move |Json(body): Json<SeedDeleteUserTokenRequest>| {
                let auth = auth_for_delete_seed.clone();
                async move {
                    let user = match auth.store().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let expires_at = match parse_rfc3339(&body.expires_at) {
                        Ok(expires_at) => expires_at,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    if let Err(error) = auth
                        .store()
                        .create_verification(CreateVerification {
identifier: (format!("delete-account-{}", body.token)).into(),
value: (user.id.typed().unwrap().to_string()).into(),
expires_at: (expires_at).into(),
..Default::default()
})
                        .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/remove-credential-account",
            post(move |Json(body): Json<RemoveCredentialAccountRequest>| {
                let auth = auth_for_remove_credential.clone();
                async move {
                    let user = match auth.store().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let accounts = match auth.store().get_user_accounts(&user.id.typed().unwrap().to_string()).await
                    {
                        Ok(accounts) => accounts,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    for account in accounts {
                        if account.provider_id == "credential" {
                            if let Err(error) = async { auth.store().delete_account(account.id.typed()?).await }.await {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({ "message": error.to_string() })),
                                );
                            }
                        }
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/promote-admin",
            post(move |Json(body): Json<RemoveCredentialAccountRequest>| {
                let auth = auth_for_promote_admin.clone();
                async move {
                    let user = match auth.store().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    if let Err(error) = auth
                        .store()
                        .update_user(
                            user.id().typed().unwrap(),
                            better_auth::prelude::UpdateUser {
                                role: Some("admin".to_string()),
                                ..Default::default()
                            },
                        )
                        .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/set-oauth-refresh-mode",
            post(move |Json(body): Json<ModeRequest>| {
                let oauth_mode = oauth_mode_for_set.clone();
                async move {
                    *oauth_mode.lock().await = match body.mode.as_str() {
                        "error" => OAuthRefreshMode::Error,
                        "empty" => OAuthRefreshMode::Empty,
                        _ => OAuthRefreshMode::Success,
                    };
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/set-social-profile",
            post(move |Json(body): Json<SetSocialProfileRequest>| {
                let social_profile = social_profile_for_set.clone();
                let social_id_token_valid = social_id_token_valid_for_set.clone();
                async move {
                    let mut profile = social_profile.lock().await;
                    if let Some(sub) = body.sub {
                        profile.sub = sub;
                    }
                    if let Some(email) = body.email {
                        profile.email = email;
                    }
                    if let Some(name) = body.name {
                        profile.name = name;
                    }
                    if let Some(image) = body.image {
                        profile.image = image;
                        profile.image_present = true;
                    }
                    if let Some(email_verified) = body.email_verified {
                        profile.email_verified = email_verified;
                    }
                    if let Some(id_token_valid) = body.id_token_valid {
                        *social_id_token_valid.lock().await = id_token_valid;
                    }
                    Json(serde_json::json!({
                        "status": true,
                        "profile": &*profile,
                        "idTokenValid": *social_id_token_valid.lock().await,
                    }))
                }
            }),
        )
        .route(
            "/__test/set-github-profile",
            post(move |Json(body): Json<SetGitHubProfileRequest>| {
                let github_profile = github_profile_for_set.clone();
                async move {
                    let mut profile = github_profile.lock().await;
                    if let Some(id) = body.id {
                        profile.id = id;
                    }
                    if let Some(login) = body.login {
                        profile.login = login;
                    }
                    if let Some(name) = body.name {
                        profile.name = Some(name);
                    }
                    if let Some(email) = body.email {
                        profile.email = Some(email);
                    }
                    if let Some(avatar_url) = body.avatar_url {
                        profile.avatar_url = Some(avatar_url);
                    }
                    if let Some(emails) = body.emails {
                        profile.emails = emails;
                    }
                    Json(serde_json::json!({
                        "status": true,
                        "profile": &*profile,
                    }))
                }
            }),
        )
        .route(
            "/__test/seed-oauth-account",
            post(move |Json(body): Json<SeedOAuthAccountRequest>| {
                let auth = auth_for_oauth_seed.clone();
                async move {
                    let user = match auth.store().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let provider_id = body.provider_id.unwrap_or_else(|| "mock".to_string());
                    let account_id = body
                        .account_id
                        .unwrap_or_else(|| "mock-account-id".to_string());
                    let access_token_expires_at = match body
                        .access_token_expires_at
                        .as_deref()
                        .map(parse_rfc3339)
                        .transpose()
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };
                    let refresh_token_expires_at = match body
                        .refresh_token_expires_at
                        .as_deref()
                        .map(parse_rfc3339)
                        .transpose()
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let accounts = match auth.store().get_user_accounts(&user.id.typed().unwrap().to_string()).await
                    {
                        Ok(accounts) => accounts,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };
                    for account in accounts {
                        if account.provider_id == provider_id
                            && account.account_id == account_id
                        {
                            if let Err(error) = async { auth.store().delete_account(account.id.typed()?).await }.await {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({ "message": error.to_string() })),
                                );
                            }
                        }
                    }

                    let account = match auth
                        .store()
                        .create_account(CreateAccount {
user_id: (user.id.typed().unwrap().to_string()).into(),
account_id: (account_id).into(),
provider_id: (provider_id).into(),
access_token: (body.access_token).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
refresh_token: (body.refresh_token).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
id_token: (body.id_token).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
access_token_expires_at: (access_token_expires_at).map(|value| better_auth_core::SchemaValue::Typed(Some(value.into()))).unwrap_or_default(),
refresh_token_expires_at: (refresh_token_expires_at).map(|value| better_auth_core::SchemaValue::Typed(Some(value.into()))).unwrap_or_default(),
scope: (body.scope).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
password: Default::default(),
..Default::default()
})
                        .await
                    {
                        Ok(account) => account,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true, "accountId": account.id })),
                    )
                }
            }),
        )
        .route(
            "/__test/github/oauth/token",
            post(move || {
                let oauth_mode = oauth_mode_for_github_token.clone();
                async move {
                    if *oauth_mode.lock().await == OAuthRefreshMode::Error {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": "invalid_grant",
                                "error_description": "invalid refresh token",
                            })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": "github-access-token",
                            "refresh_token": "github-refresh-token",
                            "expires_in": 3600,
                            "refresh_token_expires_in": 7200,
                            "scope": "read:user user:email",
                            "token_type": "bearer",
                        })),
                    )
                }
            }),
        )
        .route(
            "/__test/github/user",
            get(move || {
                let github_profile = github_profile_for_user.clone();
                async move {
                    let profile = github_profile.lock().await.clone();
                    Json(serde_json::json!({
                        "id": profile.id,
                        "login": profile.login,
                        "name": profile.name,
                        "email": profile.email,
                        "avatar_url": profile.avatar_url,
                    }))
                }
            }),
        )
        .route(
            "/__test/github/user/emails",
            get(move || {
                let github_profile = github_profile_for_emails.clone();
                async move {
                    let emails = github_profile.lock().await.emails.clone();
                    Json(serde_json::json!(emails))
                }
            }),
        )
        .route(
            "/__test/oauth/authorize",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let Some(redirect_uri) = query.get("redirect_uri") else {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "message": "redirect_uri is required" })),
                    )
                        .into_response();
                };
                let Some(state) = query.get("state") else {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "message": "state is required" })),
                    )
                        .into_response();
                };
                let mut url = match url::Url::parse(redirect_uri) {
                    Ok(url) => url,
                    Err(error) => {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        )
                            .into_response();
                    }
                };
                url.query_pairs_mut()
                    .append_pair("code", "compat-code")
                    .append_pair("state", state);
                axum::response::Redirect::to(url.as_ref()).into_response()
            }),
        )
        .route(
            "/__test/oauth/token",
            post(move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
                let oauth_mode = oauth_mode_for_token.clone();
                async move {
                    if *oauth_mode.lock().await == OAuthRefreshMode::Error {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": "invalid_grant",
                                "error_description": "invalid refresh token",
                            })),
                        );
                    }

                    let google = form.get("client_id").is_some_and(|client| client == "google-client-id");
                    let scope = match form.get("code").map(String::as_str) {
                        Some("compat-scope-missing") => None,
                        Some("compat-scope-empty") => Some(serde_json::json!("")),
                        Some("compat-scope-array") => Some(serde_json::json!([" \u{feff}audit\u{feff} ", " email ", "", 42, "\u{85}legacy"])),
                        _ => Some(serde_json::json!(if google { "openid email profile" } else { "openid,email,profile" })),
                    };
                    let mut tokens = serde_json::json!({
                        "access_token": if google { "google-access-token" } else { "new-access-token" },
                        "refresh_token": if google { "google-refresh-token" } else { "new-refresh-token" },
                        "id_token": if google { "google-id-token" } else { "mock-id-token" },
                        "expires_in": 3600,
                        "refresh_token_expires_in": 7200,
                    });
                    if let Some(scope) = scope {
                        tokens["scope"] = scope;
                    }
                    (
                        axum::http::StatusCode::OK,
                        Json(tokens),
                    )
                }
            }),
        )
        .route(
            "/__test/oauth/userinfo",
            get(|| async {
                Json(serde_json::json!({
                    "id": "mock-account-id",
                    "email": "mock@example.com",
                    "name": "Mock OAuth User",
                    "image": serde_json::Value::Null,
                    "emailVerified": true,
                }))
            }),
        )
        .nest("/api/auth", auth_router)
        .with_state(auth)
        .merge(oauth_proxy::router(reset_database.clone()))
        .merge(email_otp_router)
        .merge(email_otp_native_router)
        .merge(email_otp_transaction_router)
        .merge(oauth_link_id_token_router)
        .merge(admin_options_router)
        .merge(oauth_popup_router)
        .merge(otp_callbacks_router)
        .merge(password_security_router)
        .merge(auth_lifecycle_router)
        .merge(captcha_router)
        .merge(crypto_router)
        .merge(user_admission_router)
        .merge(device_generators_router)
        .merge(api_key_storage_router)
        .merge(secondary_router)
        .merge(cookie_version_router)
        .merge(passkey_options_router)
        .merge(custom_session_router)
        .merge(two_factor_options_router)
        .merge(two_factor_context_router)
        .merge(api_key_callbacks_router)
        .merge(jwt_router)
        .merge(one_tap_router)
        .merge(organization_callbacks_router)
        .merge(identity_router)
        .merge(disabled_user_router);

    println!("[rust-server] Listening on http://localhost:{port}");
    println!("READY");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}
