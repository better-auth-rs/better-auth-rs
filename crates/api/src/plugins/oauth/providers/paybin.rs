use better_auth_core::{AuthError, AuthResult};
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use url::Url;

use super::{OAuthProvider, OAuthUserInfo, defaults::ProviderKind};
use crate::plugins::oauth::oidc::{OidcVerifier, fetch_discovery};

const DEFAULT_ISSUER: &str = "https://idp.paybin.io";

impl OAuthProvider {
    /// Configure Paybin with its default issuer and verified ID-token profiles.
    pub fn paybin(client_id: &str, client_secret: &str) -> Self {
        Self::paybin_with_issuer(client_id, client_secret, DEFAULT_ISSUER)
    }

    /// Configure a Paybin issuer while retaining the Social provider protocol.
    /// Custom issuers declare their JWKS through OpenID discovery.
    pub fn paybin_with_issuer(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        let issuer = if issuer.is_empty() {
            DEFAULT_ISSUER
        } else {
            issuer
        };
        Self {
            kind: ProviderKind::Paybin {
                issuer: issuer.into(),
            },
            ..Self::custom(
                client_id,
                client_secret,
                &format!("{issuer}/oauth2/authorize"),
                &format!("{issuer}/oauth2/token"),
            )
        }
    }

    pub(in crate::plugins::oauth) fn paybin_issuer(&self) -> Option<&str> {
        match &self.kind {
            ProviderKind::Paybin { issuer } => Some(issuer),
            _ => None,
        }
    }
}

pub(in crate::plugins::oauth) async fn verify(
    issuer: &str,
    client_id: &str,
    token: &str,
    nonce: Option<&str>,
) -> AuthResult<Value> {
    let jwks_url = if issuer == DEFAULT_ISSUER {
        Url::parse("https://idp.paybin.io/.well-known/jwks.json")
            .map_err(|error| AuthError::config(error.to_string()))?
    } else {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let document = fetch_discovery(&discovery_url, &HeaderMap::new())
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if document.issuer.as_deref() != Some(issuer) {
            return Err(AuthError::config(
                "Paybin discovery must describe the configured issuer",
            ));
        }
        let jwks = document
            .jwks_uri
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::config("Paybin discovery must declare its JWKS URI"))?;
        Url::parse(&discovery_url)
            .and_then(|url| url.join(&jwks))
            .map_err(|error| AuthError::config(error.to_string()))?
    };
    // Discovery locates keys; application configuration still fixes issuer and audience.
    let verifier = OidcVerifier::new(
        jwks_url,
        issuer.into(),
        client_id.into(),
        Some(vec![json!("RS256")]),
    )
    .map_err(|error| AuthError::internal(error.to_string()))?;
    verifier
        .verify(token, nonce)
        .await
        .map_err(|_| crate::plugins::oauth::id_token::invalid())
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let name = ["name", "preferred_username"]
        .into_iter()
        .find_map(|key| {
            profile
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default()
        .to_owned();
    let verified = super::profile_email_verified(&better_auth_core::SchemaValue::from_json(
        profile.get("email_verified").cloned(),
    ))
    .map_err(|error| error.to_string())?;
    Ok(OAuthUserInfo {
        id: profile
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing sub")?
            .into(),
        email: super::defaults::profile_email(&profile)?,
        name: Some(name),
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Paybin picture: {error}"))?,
        email_verified: Some(verified).into(),
        additional_fields: Default::default(),
    })
}
