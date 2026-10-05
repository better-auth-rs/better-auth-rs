use std::time::Duration;

use better_auth_core::{AuthError, AuthResult};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    OAuthCallbackUserPayload, OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest,
    defaults::ProviderKind,
};
use crate::plugins::oauth::{generic_profile::decode_claims, id_token, oidc::OidcVerifier};

const ISSUER: &str = "https://appleid.apple.com";
const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Audience selection for Sign in with Apple.
#[derive(Clone, Default)]
pub struct AppleOptions {
    /// Explicit accepted audiences. An omitted or empty list uses the bundle or client identifiers.
    pub audience: Option<Vec<String>>,
    /// Accepted bundle identifier when an explicit audience list is absent or empty.
    pub app_bundle_identifier: Option<String>,
    /// Additional accepted client identifiers after the primary `OAuthProvider::client_id`.
    pub additional_client_ids: Vec<String>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) jwks_url: Option<String>,
}

impl AppleOptions {
    pub(in crate::plugins::oauth) fn audiences(&self, client_id: &str) -> Vec<String> {
        if let Some(audience) = self.audience.as_ref().filter(|values| !values.is_empty()) {
            audience.clone()
        } else if let Some(bundle) = self
            .app_bundle_identifier
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            vec![bundle.clone()]
        } else {
            std::iter::once(client_id.to_owned())
                .chain(self.additional_client_ids.iter().cloned())
                .collect()
        }
    }

    pub(in crate::plugins::oauth) async fn verify(
        &self,
        client_id: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> AuthResult<Value> {
        let jwks_url = JWKS_URL;
        #[cfg(test)]
        let jwks_url = self.jwks_url.as_deref().unwrap_or(jwks_url);
        let verifier = OidcVerifier::with_policy(
            jwks_url
                .parse()
                .map_err(|error: url::ParseError| AuthError::internal(error.to_string()))?,
            ISSUER.into(),
            self.audiences(client_id),
            None,
            Some(Duration::from_secs(3600)),
        )
        .map_err(|error| AuthError::internal(error.to_string()))?;
        let claims = verifier
            .verify(token, None)
            .await
            .map_err(|_| id_token::invalid())?;
        if let Some(nonce) = nonce.filter(|value| !value.is_empty()) {
            let claim = claims.get("nonce").and_then(Value::as_str);
            let hashed = hex::encode(Sha256::digest(nonce.as_bytes()));
            if claim != Some(nonce) && claim != Some(hashed.as_str()) {
                return Err(id_token::invalid());
            }
        }
        Ok(claims)
    }
}

impl OAuthProvider {
    /// Configure Apple authorization, token grants, and direct ID-token verification.
    /// `client_secret` is the configured Apple secret; this constructor does not generate one.
    pub fn apple(client_id: &str, client_secret: &str, options: AppleOptions) -> Self {
        Self {
            kind: ProviderKind::Apple(options),
            ..Self::custom(
                client_id,
                client_secret,
                "https://appleid.apple.com/auth/authorize",
                "https://appleid.apple.com/auth/token",
            )
        }
    }

    pub(in crate::plugins::oauth) fn apple_options(&self) -> Option<&AppleOptions> {
        match &self.kind {
            ProviderKind::Apple(options) => Some(options),
            _ => None,
        }
    }
}

pub(in crate::plugins::oauth) fn profile(
    request: &OAuthUserInfoRequest,
    verified: Option<Value>,
) -> AuthResult<Option<Value>> {
    let claims = match verified {
        Some(claims) => claims,
        None => {
            let Some(token) = request
                .id_token
                .as_deref()
                .filter(|token| !token.is_empty())
            else {
                return Ok(None);
            };
            decode_claims(token)
                .ok_or_else(|| AuthError::internal("Invalid Apple ID-token claims"))?
        }
    };
    enrich_profile(claims, request.user.as_ref()).map(Some)
}

fn enrich_profile(mut claims: Value, user: Option<&OAuthCallbackUserPayload>) -> AuthResult<Value> {
    let name = if let Some(name) = user.and_then(|user| user.name.as_ref()) {
        format!(
            "{} {}",
            name.first_name.as_deref().unwrap_or_default(),
            name.last_name.as_deref().unwrap_or_default()
        )
        .trim_matches(crate::plugins::helpers::oauth_scope_whitespace)
        .to_owned()
    } else {
        claims
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let _ = claims
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Apple claims must be an object"))?
        .insert("name".into(), name.into());
    Ok(claims)
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let verified = match profile.get("email_verified") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value == "true",
        _ => false,
    };
    Ok(OAuthUserInfo {
        id: profile
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing Apple subject")?
            .into(),
        name: Some(
            profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )
        .into(),
        email: super::defaults::profile_email(&profile)?,
        image: None,
        email_verified: Some(verified).into(),
        additional_fields: Default::default(),
    })
}
