use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use better_auth_core::entity::AuthAccount;
use better_auth_core::{
    AuthConfig, AuthError, AuthRequest, AuthResult, OAuthStateStrategy, SecretKey,
};

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
    pub expires_at: f64,
    #[serde(rename = "requestSignUp", skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    #[serde(
        rename = "serverContext",
        default,
        skip_serializing_if = "Map::is_empty"
    )]
    pub server_context: Map<String, Value>,
    #[serde(rename = "idTokenNonce", skip_serializing_if = "Option::is_none")]
    pub id_token_nonce: Option<String>,
    #[serde(flatten)]
    pub additional_data: Map<String, Value>,
}

impl OAuthStatePayload {
    pub(crate) fn parse(value: &str) -> AuthResult<Self> {
        let mut value: Value = serde_json::from_str(value)?;
        for field in [
            "errorURL",
            "newUserURL",
            "link",
            "requestSignUp",
            "idTokenNonce",
            "serverContext",
        ] {
            if value.get(field).is_some_and(Value::is_null) {
                return Err(AuthError::bad_request("Invalid OAuth state payload"));
            }
        }
        if let Some(link) = value.get_mut("link").and_then(Value::as_object_mut) {
            let user_id = better_auth_core::SchemaValue::<String>::from_json(link.remove("userId"))
                .display_string()?;
            let _ = link.insert("userId".into(), user_id.into());
        }
        let payload: Self = serde_json::from_value(value)?;
        if payload
            .additional_data
            .get("oauthState")
            .is_some_and(|value| !value.is_string())
        {
            return Err(AuthError::bad_request("Invalid OAuth state nonce"));
        }
        Ok(payload)
    }

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
            expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis() as f64,
            request_sign_up,
            server_context: Map::new(),
            id_token_nonce: None,
            additional_data,
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.expires_at < Utc::now().timestamp_millis() as f64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountCookiePayload {
    #[serde(skip)]
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
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
    pub(crate) fn optional<T>(
        &self,
        name: &str,
        value: Option<T>,
    ) -> better_auth_core::SchemaValue<Option<T>> {
        if value.is_some()
            || self
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
        {
            better_auth_core::SchemaValue::Typed(value)
        } else {
            better_auth_core::SchemaValue::Undefined
        }
    }

    pub(crate) fn from_account(account: &impl AuthAccount) -> Self {
        Self {
            visible_fields: account.field_presence().cloned(),
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

pub(crate) fn state_cookie_name(config: &AuthConfig) -> String {
    match config.account.store_state_strategy() {
        OAuthStateStrategy::Cookie => related_cookie_name(config, "oauth_state"),
        OAuthStateStrategy::Database => related_cookie_name(config, "state"),
    }
}

pub(crate) fn account_cookie_name(config: &AuthConfig) -> String {
    related_cookie_name(config, "account_data")
}

pub(crate) fn create_database_state_cookie_value(secret: &str, state: &str) -> AuthResult<String> {
    Ok(better_auth_core::utils::cookie_utils::sign_cookie_value(
        state, secret,
    ))
}

pub(crate) fn decode_database_state_cookie_value(secret: &str, token: &str) -> AuthResult<String> {
    better_auth_core::utils::cookie_utils::verify_cookie_value(token, secret)
        .ok_or_else(|| AuthError::bad_request("Invalid OAuth state cookie"))
}

pub(crate) fn create_cookie_state_value<'a>(
    secret: impl Into<SecretKey<'a>>,
    payload: &OAuthStatePayload,
) -> AuthResult<String> {
    let encrypted = crate::plugins::symmetric::encrypt(secret, &serde_json::to_string(payload)?)?;
    Ok(urlencoding::encode(&encrypted).into_owned())
}

pub(crate) fn decode_cookie_state_value<'a>(
    secret: impl Into<SecretKey<'a>>,
    token: &str,
) -> AuthResult<OAuthStatePayload> {
    let token = urlencoding::decode(token)
        .map_err(|error| AuthError::bad_request(format!("Invalid OAuth state cookie: {error}")))?;
    OAuthStatePayload::parse(&crate::plugins::symmetric::decrypt(secret, &token)?)
}

pub(crate) fn create_account_cookie_value<'a>(
    secret: impl Into<SecretKey<'a>>,
    payload: &AccountCookiePayload,
    max_age: Duration,
) -> AuthResult<String> {
    let mut fields: serde_json::Map<String, Value> =
        serde_json::from_value(serde_json::to_value(payload)?)?;
    for name in [
        "accessToken",
        "refreshToken",
        "idToken",
        "accessTokenExpiresAt",
        "refreshTokenExpiresAt",
        "scope",
    ] {
        if !fields.contains_key(name)
            && payload
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
        {
            let _ = fields.insert(name.into(), Value::Null);
        }
    }
    better_auth_core::utils::jwe::encode(
        fields,
        secret,
        "better-auth-account",
        max_age.num_seconds(),
    )
}

pub(crate) fn decode_account_cookie_value<'a>(
    secret: impl Into<SecretKey<'a>>,
    token: &str,
) -> Option<AccountCookiePayload> {
    let payload = better_auth_core::utils::jwe::decode(token, secret, "better-auth-account")?;
    let visible_fields = Some(payload.keys().cloned().collect());
    let mut account: AccountCookiePayload = serde_json::from_value(Value::Object(payload)).ok()?;
    account.visible_fields = visible_fields;
    Some(account)
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
        "oauthState"
            | "idTokenNonce"
            | "serverContext"
            | "callbackURL"
            | "codeVerifier"
            | "errorURL"
            | "newUserURL"
            | "link"
            | "expiresAt"
            | "requestSignUp"
    )
}
