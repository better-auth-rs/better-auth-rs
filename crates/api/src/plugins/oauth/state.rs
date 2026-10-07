use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use serde_json::{Map, Value};

use super::state_json::StateExtras;

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
                        better_auth_core::SchemaValue::<String>::from_json(link.remove("userId"))?
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

pub(crate) use better_auth_core::wire::AccountView as AccountCookiePayload;

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
    max_age: f64,
) -> AuthResult<String> {
    let fields = serde_json::from_value(serde_json::to_value(payload)?)?;
    better_auth_core::utils::jwe::encode(fields, secret, "better-auth-account", max_age)
}

pub(crate) fn decode_account_cookie_value<'a>(
    secret: impl Into<SecretKey<'a>>,
    token: &str,
) -> Option<AccountCookiePayload> {
    let payload = better_auth_core::utils::jwe::decode(token, secret, "better-auth-account")?;
    serde_json::from_value(Value::Object(payload)).ok()
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

#[cfg(test)]
mod cookie_lifetime_tests {
    use super::*;

    #[test]
    fn account_cookie_lifetime_uses_the_resolved_fractional_override() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/cookie-cache-lifetime-1.7.6.json"
        ))
        .unwrap();
        for fixture in fixtures["account"].as_object().unwrap().values() {
            let age = fixture["maxAge"].as_f64().unwrap();
            let mut config =
                AuthConfig::new("ordinary-cookie-lifetime-fixture-secret-more-than-32-characters");
            config.advanced.cookies.get_or_insert_default().insert(
                "account_data".into(),
                better_auth_core::CookieOverride {
                    name: None,
                    attributes: better_auth_core::CookieAttributes {
                        max_age: Some(age),
                        ..Default::default()
                    },
                },
            );
            let account = AccountCookiePayload {
                provider_id: "ordinary".to_owned().into(),
                access_token: Some("fixture-access-token".into()).into(),
                ..Default::default()
            };
            let before = Utc::now().timestamp() as f64;
            let headers = crate::plugins::oauth::handlers::create_account_cookie_headers(
                &AuthRequest::new(better_auth_core::HttpMethod::Get, "/"),
                &config,
                &account,
            )
            .unwrap();
            let after = Utc::now().timestamp() as f64;
            let token = headers[0]
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap()
                .1;
            let claims = better_auth_core::utils::jwe::decode(
                token,
                config.encryption_secret(),
                "better-auth-account",
            )
            .unwrap();
            let expiry_base =
                claims["exp"].as_f64().unwrap() - fixture["expiresIn"].as_f64().unwrap();
            assert_eq!(expiry_base.fract(), 0.0);
            assert!(before <= expiry_base && expiry_base <= after);
            assert_eq!(claims["providerId"], fixture["providerId"]);
            assert_eq!(
                decode_account_cookie_value(config.encryption_secret(), token)
                    .unwrap()
                    .provider_id,
                account.provider_id
            );
        }
    }
}
