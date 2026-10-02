use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use jsonwebtoken::{Algorithm, DecodingKey, crypto};
use serde_json::Value;

use super::OAuthIdTokenVerifier;
use crate::plugins::json_body;

pub(super) const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub(crate) struct VerifiedGoogleClaims(Value);

impl VerifiedGoogleClaims {
    pub(crate) fn into_value(self) -> Value {
        self.0
    }

    pub(super) fn matches_hosted_domain(&self, domain: Option<&str>) -> bool {
        hosted_domain_allowed(domain, &self.0)
    }
}

pub(super) struct AcceptedIdToken(String);

impl AcceptedIdToken {
    pub(super) async fn verify(
        verifier: &dyn OAuthIdTokenVerifier,
        token: &str,
        nonce: Option<&str>,
    ) -> Option<Self> {
        // The configured verifier owns this application's token trust policy.
        verifier
            .verify_id_token(token, nonce)
            .await
            .unwrap_or(false)
            .then(|| Self(token.to_owned()))
    }

    pub(super) fn claims(self) -> AuthResult<VerifiedGoogleClaims> {
        self.value().map(VerifiedGoogleClaims)
    }

    pub(super) fn value(self) -> AuthResult<Value> {
        let payload = self
            .0
            .split('.')
            .nth(1)
            .ok_or_else(|| AuthError::internal("Verified ID token has no claims"))?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|error| {
            AuthError::internal(format!("Invalid verified ID claims encoding: {error}"))
        })?;
        let claims = serde_json::from_slice(&bytes)?;
        Ok(claims)
    }
}

pub(crate) fn hosted_domain_allowed(domain: Option<&str>, claims: &Value) -> bool {
    domain
        .filter(|domain| !domain.is_empty())
        .is_none_or(|domain| {
            claims
                .get("hd")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .is_some_and(|value| domain == "*" || domain == value)
        })
}

pub(crate) async fn verify(
    token: &str,
    audience: &[String],
    nonce: Option<&str>,
    jwks_url: &str,
) -> Option<VerifiedGoogleClaims> {
    let (signed, signature) = token.rsplit_once('.')?;
    let (protected, payload) = signed.split_once('.')?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).ok()?).ok()?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return None;
    }
    if let Some(critical) = header.get("crit") {
        let extensions = critical.as_array()?;
        if extensions.is_empty()
            || extensions.iter().any(|value| value.as_str() != Some("b64"))
            || header.get("b64").and_then(Value::as_bool) != Some(true)
        {
            return None;
        }
    }
    let kid = header
        .get("kid")
        .filter(|value| json_body::is_truthy(value));
    let keys: Value = reqwest::Client::new()
        .get(jwks_url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    let keys = keys.get("keys")?.as_array()?;
    let keys = keys
        .iter()
        .filter(|key| kid.is_none_or(|kid| key.get("kid") == Some(kid)))
        .map(import_google_key)
        .collect::<Option<Vec<_>>>()?;
    for (key, modulus_bits) in keys {
        if modulus_bits < 2048 {
            continue;
        }
        if crypto::verify(signature, signed.as_bytes(), &key, Algorithm::RS256).ok() != Some(true) {
            continue;
        }
        let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        return valid_claims(&claims, audience, nonce).then_some(VerifiedGoogleClaims(claims));
    }
    None
}

fn import_google_key(key: &Value) -> Option<(DecodingKey, usize)> {
    if key.get("kty").and_then(Value::as_str) != Some("RSA")
        || key.get("ext").is_some_and(|value| !value.is_boolean())
        || key.get("d").is_some()
    {
        return None;
    }
    if let Some(operations) = key.get("key_ops") {
        let operations = operations.as_array()?;
        if operations.len() != 1 || operations.first().and_then(Value::as_str) != Some("verify") {
            return None;
        }
    }
    // Google's importJWK(jwk, "RS256") ignores alg/use, but WebCrypto enforces key_ops and ext.
    let modulus = key.get("n")?.as_str()?;
    let exponent = key.get("e")?.as_str()?;
    let bytes = URL_SAFE_NO_PAD.decode(modulus).ok()?;
    let (first, byte) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0)?;
    let modulus_bits = (bytes.len() - first) * 8 - byte.leading_zeros() as usize;
    Some((
        DecodingKey::from_rsa_components(modulus, exponent).ok()?,
        modulus_bits,
    ))
}

// jose accepts fractional NumericDates; jsonwebtoken's JWT decoder rounds these to integers.
fn valid_claims(claims: &Value, audience: &[String], nonce: Option<&str>) -> bool {
    if !matches!(
        claims.get("iss").and_then(Value::as_str),
        Some("https://accounts.google.com" | "accounts.google.com")
    ) {
        return false;
    }
    let audience_matches = match claims.get("aud") {
        Some(Value::String(value)) => audience.contains(value),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| audience.iter().any(|expected| expected == value)),
        _ => false,
    };
    if nonce
        .filter(|nonce| !nonce.is_empty())
        .is_some_and(|nonce| claims.get("nonce").and_then(Value::as_str) != Some(nonce))
    {
        return false;
    }
    if !audience_matches {
        return false;
    }
    let now = chrono::Utc::now().timestamp() as f64;
    let Some(issued) = claims.get("iat").and_then(Value::as_f64) else {
        return false;
    };
    issued <= now
        && now - issued <= 3600.0
        && claims
            .get("exp")
            .is_none_or(|value| value.as_f64().is_some_and(|expiry| expiry > now))
        && claims
            .get("nbf")
            .is_none_or(|value| value.as_f64().is_some_and(|start| start <= now))
}
