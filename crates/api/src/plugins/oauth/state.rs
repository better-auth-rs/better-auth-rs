use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use serde_json::{Map, Value};

use super::state_json::StateExtras;

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

#[derive(Debug, Clone, Default)]
pub(crate) struct OAuthStatePayload {
    pub callback_url: String,
    pub code_verifier: String,
    pub error_url: Option<String>,
    pub new_user_url: Option<String>,
    pub link: Option<OAuthStateLink>,
    pub expires_at: f64,
    pub request_sign_up: Option<bool>,
    pub server_context: Map<String, Value>,
    pub id_token_nonce: Option<String>,
    pub oauth_state: Option<String>,
    pub additional_data: StateExtras,
}

impl OAuthStatePayload {
    pub(crate) fn parse(value: &str) -> AuthResult<Self> {
        let mut fields: StateExtras = serde_json::from_str(value)?;
        let callback_url = required(&mut fields, "callbackURL")?;
        let code_verifier = required(&mut fields, "codeVerifier")?;
        let error_url = optional(&mut fields, "errorURL")?;
        let new_user_url = optional(&mut fields, "newUserURL")?;
        let expires_at = required(&mut fields, "expiresAt")?;
        let oauth_state = optional(&mut fields, "oauthState")?;
        let link = match fields.remove("link") {
            None => None,
            Some(raw) => {
                let mut value: Value = serde_json::from_str(raw.get())?;
                if let Some(link) = value.as_object_mut() {
                    let user_id =
                        better_auth_core::SchemaValue::<String>::from_json(link.remove("userId"))
                            .display_string()?;
                    let _ = link.insert("userId".into(), user_id.into());
                }
                Some(serde_json::from_value(value)?)
            }
        };
        let request_sign_up = optional(&mut fields, "requestSignUp")?;
        let id_token_nonce = optional(&mut fields, "idTokenNonce")?;
        let server_context = optional(&mut fields, "serverContext")?.unwrap_or_default();
        // Zod's loose object drops this top-level key; nested extras remain raw.
        fields.retain(|key| key != "__proto__");
        Ok(Self {
            callback_url,
            code_verifier,
            error_url,
            new_user_url,
            link,
            expires_at,
            request_sign_up,
            server_context,
            id_token_nonce,
            oauth_state,
            additional_data: fields,
        })
    }

    pub(crate) fn new(
        callback_url: String,
        code_verifier: String,
        error_url: Option<String>,
        new_user_url: Option<String>,
        link: Option<OAuthStateLink>,
        request_sign_up: Option<bool>,
        additional_data: StateExtras,
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
            oauth_state: None,
            additional_data,
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.expires_at < Utc::now().timestamp_millis() as f64
    }

    fn raw_fields(&self) -> serde_json::Result<StateExtras> {
        let mut fields = self.additional_data.clone();
        fields.insert("callbackURL", &self.callback_url)?;
        fields.insert("codeVerifier", &self.code_verifier)?;
        fields.insert("expiresAt", &self.expires_at)?;
        if let Some(value) = &self.error_url {
            fields.insert("errorURL", value)?;
        }
        if let Some(value) = &self.new_user_url {
            fields.insert("newUserURL", value)?;
        }
        if let Some(value) = &self.link {
            fields.insert("link", value)?;
        }
        if let Some(value) = &self.request_sign_up {
            fields.insert("requestSignUp", value)?;
        }
        if let Some(value) = &self.id_token_nonce {
            fields.insert("idTokenNonce", value)?;
        }
        if let Some(value) = &self.oauth_state {
            fields.insert("oauthState", value)?;
        }
        if !self.server_context.is_empty() {
            fields.insert("serverContext", &self.server_context)?;
        }
        Ok(fields)
    }
}

impl Serialize for OAuthStatePayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw_fields()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

fn required<T: DeserializeOwned>(fields: &mut StateExtras, name: &str) -> AuthResult<T> {
    let value = fields
        .remove(name)
        .ok_or_else(|| AuthError::bad_request(format!("Missing OAuth state field: {name}")))?;
    Ok(serde_json::from_str(value.get())?)
}

fn optional<T: DeserializeOwned>(fields: &mut StateExtras, name: &str) -> AuthResult<Option<T>> {
    fields
        .remove(name)
        .map(|value| serde_json::from_str(value.get()).map_err(Into::into))
        .transpose()
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
    better_auth_core::utils::cookie_utils::related_cookie_name(config, suffix)
}

pub(crate) fn filter_additional_state_data(
    additional_data: Option<Map<String, Value>>,
) -> AuthResult<StateExtras> {
    let mut fields = StateExtras::from_values(additional_data.unwrap_or_default())?;
    fields.retain(|key| !reserved_state_key(key));
    Ok(fields)
}

pub(super) fn reserved_state_key(key: &str) -> bool {
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

#[cfg(test)]
mod raw_state_tests {
    use super::*;

    #[test]
    fn payload_keeps_raw_extras_and_validates_reserved_values() {
        let input = r#"{"callbackURL":"/done","codeVerifier":"verifier","expiresAt":123.5,"oauthState":"bound","\ud800":{"v":"\udc00","day":"2026-02-30T00:00:00Z","__proto__":"nested"},"__proto__":"top"}"#;
        let payload = OAuthStatePayload::parse(input).unwrap();
        assert_eq!(payload.oauth_state.as_deref(), Some("bound"));
        let output = serde_json::to_string(&payload).unwrap();
        assert!(output.contains(
            r#""\ud800":{"v":"\udc00","day":"2026-02-30T00:00:00Z","__proto__":"nested"}"#
        ));
        assert!(!output.contains(r#""top""#));
        assert!(
            OAuthStatePayload::parse(
                &input.replace(r#""oauthState":"bound""#, r#""oauthState":null"#)
            )
            .is_err()
        );
        assert!(
            OAuthStatePayload::parse(
                &input.replace(r#""codeVerifier":"verifier""#, r#""codeVerifier":null"#)
            )
            .is_err()
        );
        let output = serde_json::to_string(&OAuthStatePayload::parse(&output).unwrap()).unwrap();
        assert!(output.contains("2026-02-30T00:00:00Z"));
    }
}
