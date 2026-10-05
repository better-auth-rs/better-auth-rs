use better_auth_core::{AuthError, AuthResult};
use serde_json::Value;

use super::{OAuthProvider, OAuthUserInfoRequest, defaults::ProviderKind};
use crate::plugins::json_body::is_truthy;
use crate::plugins::oauth::{
    generic_profile::decode_claims, id_token, social_profile::fetch_http_profile,
};

impl OAuthProvider {
    pub(in crate::plugins::oauth) fn line_verify_url(&self) -> Option<&str> {
        match &self.kind {
            ProviderKind::Line { verify_url } => Some(verify_url),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(in crate::plugins::oauth) fn set_line_verify_url(&mut self, endpoint: String) {
        self.kind = ProviderKind::Line {
            verify_url: endpoint,
        };
    }
}

pub(in crate::plugins::oauth) async fn verify(
    endpoint: &str,
    client_id: &str,
    token: &str,
    nonce: Option<&str>,
) -> AuthResult<()> {
    let mut form = vec![("id_token", token), ("client_id", client_id)];
    if let Some(nonce) = nonce.filter(|value| !value.is_empty()) {
        form.push(("nonce", nonce));
    }
    let profile = fetch_http_profile(reqwest::Client::new().post(endpoint).form(&form))
        .await
        .map_err(|_| id_token::invalid())?
        .ok_or_else(id_token::invalid)?;
    if profile.get("aud").and_then(Value::as_str) != Some(client_id)
        || profile
            .get("nonce")
            .filter(|value| is_truthy(value))
            .is_some_and(|value| value.as_str() != nonce)
    {
        return Err(id_token::invalid());
    }
    Ok(())
}

pub(in crate::plugins::oauth) async fn fetch_profile(
    provider: &OAuthProvider,
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<Value>> {
    if let Some(claims) = request.id_token.as_deref().and_then(decode_claims) {
        return Ok(Some(claims));
    }
    let endpoint = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let profile = fetch_http_profile(provider.user_info_request(
        endpoint,
        request.access_token.as_deref().unwrap_or("undefined"),
    ))
    .await?;
    Ok(profile.filter(is_truthy))
}
