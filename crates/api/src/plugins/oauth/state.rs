use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use better_auth_core::entity::AuthAccount;
use better_auth_core::{AuthConfig, AuthRequest, AuthResult, OAuthStateStrategy};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OAuthStateLink {
    pub email: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OAuthStatePayload {
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "codeVerifier")]
    pub code_verifier: String,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<OAuthStateLink>,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "requestSignUp", skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    #[serde(flatten)]
    pub additional_data: Map<String, Value>,
}

impl OAuthStatePayload {
    pub(crate) fn new(
        callback_url: String,
        code_verifier: String,
        error_url: Option<String>,
        new_user_url: Option<String>,
        link: Option<OAuthStateLink>,
        request_sign_up: Option<bool>,
        additional_data: Map<String, Value>,
    ) -> Self {
        Self {
            callback_url,
            code_verifier,
            error_url,
            new_user_url,
            link,
            expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis(),
            request_sign_up,
            additional_data,
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.expires_at < Utc::now().timestamp_millis()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountCookiePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "accessToken", skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(
        rename = "accessTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub access_token_expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(
        rename = "refreshTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl AccountCookiePayload {
    pub(crate) fn from_account(account: &impl AuthAccount) -> Self {
        Self {
            id: Some(account.id().to_string()),
            user_id: account.user_id().to_string(),
            provider_id: account.provider_id().to_string(),
            account_id: account.account_id().to_string(),
            access_token: account.access_token().map(str::to_string),
            refresh_token: account.refresh_token().map(str::to_string),
            id_token: account.id_token().map(str::to_string),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateCookieClaims {
    state: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatePayloadClaims {
    #[serde(flatten)]
    payload: OAuthStatePayload,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountCookieClaims {
    #[serde(flatten)]
    payload: AccountCookiePayload,
    exp: usize,
    iat: usize,
}

pub(crate) fn state_cookie_name(config: &AuthConfig) -> String {
    match config.account.store_state_strategy {
        OAuthStateStrategy::Cookie => related_cookie_name(config, "oauth_state"),
        OAuthStateStrategy::Database => related_cookie_name(config, "state"),
    }
}

pub(crate) fn account_cookie_name(config: &AuthConfig) -> String {
    related_cookie_name(config, "account_data")
}

pub(crate) fn create_database_state_cookie_value(secret: &str, state: &str) -> AuthResult<String> {
    let now = Utc::now();
    let claims = StateCookieClaims {
        state: state.to_string(),
        exp: (now + Duration::minutes(10)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_database_state_cookie_value(secret: &str, token: &str) -> AuthResult<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<StateCookieClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims
    .state)
}

pub(crate) fn create_cookie_state_value(
    secret: &str,
    payload: &OAuthStatePayload,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = StatePayloadClaims {
        payload: payload.clone(),
        exp: (now + Duration::minutes(10)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_cookie_state_value(
    secret: &str,
    token: &str,
) -> AuthResult<OAuthStatePayload> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<StatePayloadClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims
    .payload)
}

pub(crate) fn create_account_cookie_value(
    secret: &str,
    payload: &AccountCookiePayload,
    max_age: Duration,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = AccountCookieClaims {
        payload: payload.clone(),
        exp: (now + max_age).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_account_cookie_value(
    secret: &str,
    token: &str,
) -> AuthResult<AccountCookiePayload> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<AccountCookieClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims
    .payload)
}

pub(crate) fn get_cookie(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            let (cookie_name, cookie_value) = trimmed.split_once('=')?;
            (cookie_name == name).then_some(cookie_value.to_string())
        })
        .next()
}

pub(crate) fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{}{}", prefix, suffix))
        .unwrap_or_else(|| format!("better-auth.{}", suffix))
}

pub(crate) fn filter_additional_state_data(
    additional_data: Option<Map<String, Value>>,
) -> Map<String, Value> {
    additional_data
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| !reserved_state_key(key))
        .collect()
}

fn reserved_state_key(key: &str) -> bool {
    matches!(
        key,
        "callbackURL"
            | "codeVerifier"
            | "errorURL"
            | "newUserURL"
            | "link"
            | "expiresAt"
            | "requestSignUp"
    )
}
