use std::{error::Error, fmt::Write, sync::Arc};

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult};
use serde_json::{Map, Value};

use super::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthUserInfoRequest,
};

const VERIFY_URL: &str = "https://api.line.me/oauth2/v2.1/verify";

impl GenericOAuthConfig {
    /// Configure LINE code login with profile claims from its ID-token verification endpoint.
    /// Register each channel with its own name through `OAuthPlugin::add_generic_provider`.
    pub fn line(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            authorization_url: Some("https://access.line.me/oauth2/v2.1/authorize".into()),
            token_url: Some("https://api.line.me/oauth2/v2.1/token".into()),
            user_info_url: Some("https://api.line.me/oauth2/v2.1/userinfo".into()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            get_user_info: Some(Arc::new(LineProfile {
                verify_url: VERIFY_URL.into(),
            })),
            account_subject: Some(Arc::new(LineSubject)),
            ..Default::default()
        }
    }
}

struct LineProfile {
    verify_url: String,
}

#[async_trait]
impl GenericOAuthUserInfoHandler for LineProfile {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "LINE requires resolved profile context",
        ))
    }

    async fn get_user_info_with_context(
        &self,
        tokens: &OAuthUserInfoRequest,
        context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Option<Value>> {
        if let Some(claims) = context.verified_claims() {
            return profile(claims.as_value()).map(Some);
        }
        let client = reqwest::Client::new();
        let request =
            if let Some(token) = tokens.id_token.as_deref().filter(|token| !token.is_empty()) {
                let mut form = vec![("id_token", token), ("client_id", context.client_id())];
                if let Some(nonce) = context.expected_nonce() {
                    form.push(("nonce", nonce));
                }
                client.post(&self.verify_url).form(&form)
            } else {
                let endpoint = context
                    .user_info_url()
                    .ok_or_else(|| AuthError::internal("Missing LINE userinfo endpoint"))?;
                client
                    .get(endpoint)
                    .bearer_auth(tokens.access_token.as_deref().unwrap_or("undefined"))
            };
        let response = request
            .send()
            .await
            .map_err(|error| request_error("request failed", error))?;
        let success = response.status().is_success();
        let body = response
            .text()
            .await
            .map_err(|error| request_error("response failed", error))?;
        if !success || body.is_empty() {
            return Ok(None);
        }
        let Some(claims) = serde_json::from_str::<Option<Value>>(&body)
            .map_err(|error| AuthError::internal(format!("Invalid LINE response: {error}")))?
        else {
            return Ok(None);
        };
        profile(&claims).map(Some)
    }
}

fn profile(claims: &Value) -> AuthResult<Value> {
    let claims = claims
        .as_object()
        .ok_or_else(|| AuthError::internal("LINE profile must be an object"))?;
    let mut profile = Map::new();
    for (from, to) in [
        ("sub", "sub"),
        ("name", "name"),
        ("email", "email"),
        ("picture", "image"),
    ] {
        if let Some(value) = claims.get(from) {
            let _ = profile.insert(to.into(), value.clone());
        }
    }
    let _ = profile.insert("emailVerified".into(), Value::Bool(false));
    Ok(Value::Object(profile))
}

fn request_error(context: &str, error: reqwest::Error) -> AuthError {
    let error = error.without_url();
    let mut message = format!("LINE {context}: {error}");
    let mut cause = error.source();
    while let Some(error) = cause {
        let _ = write!(message, ": {error}");
        cause = error.source();
    }
    AuthError::internal(message)
}

struct LineSubject;

#[async_trait]
impl OAuthAccountSubject for LineSubject {
    async fn resolve_subject(
        &self,
        _: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        Ok(profile
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into())
    }
}

#[cfg(test)]
#[path = "line_tests.rs"]
mod tests;
