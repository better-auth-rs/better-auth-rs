use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jws::JwsVerifier;

impl JwtPlugin {
    /// Verify a token with adapter keys. Invalid tokens return `None`; store failures propagate.
    ///
    /// The optional issuer overrides the configured issuer. Like upstream `verifyJWT`,
    /// this reads local adapter keys even when `remote_url` is configured.
    pub async fn verify<S: AuthSchema>(
        &self,
        token: &str,
        issuer: Option<&str>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let keys = ctx.database.list_jwks().await?;
        let issuer = issuer
            .or(self.config.issuer.as_deref())
            .unwrap_or(&ctx.config.base_url);
        let audience = self
            .config
            .audience
            .as_deref()
            .unwrap_or(&ctx.config.base_url);
        let verified = verify_local(token, &keys, self.config.algorithm, issuer, audience, 0);
        Ok(verified.filter(|payload| {
            payload
                .get("sub")
                .and_then(Value::as_str)
                .is_some_and(|sub| !sub.is_empty())
        }))
    }
}

pub(super) fn protected_header(token: &str) -> Option<JwsHeader> {
    let bytes = URL_SAFE_NO_PAD.decode(token.split('.').next()?).ok()?;
    JwsHeader::from_bytes(&bytes).ok()
}

pub(super) fn verify_local(
    token: &str,
    keys: &[better_auth_core::Jwk],
    default_algorithm: JwtAlgorithm,
    issuer: &str,
    audience: &str,
    tolerance: i64,
) -> Option<Map<String, Value>> {
    let header = protected_header(token)?;
    let key = keys
        .iter()
        .find(|key| Some(key.id.as_str()) == header.key_id())?;
    let algorithm = key.alg.as_deref().unwrap_or(default_algorithm.name());
    if header.algorithm() != Some(algorithm) {
        return None;
    }
    let public = Jwk::from_bytes(&key.public_key).ok()?;
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        "EdDSA" => Box::new(jws::EdDSA.verifier_from_jwk(&public).ok()?),
        "RS256" => Box::new(jws::RS256.verifier_from_jwk(&public).ok()?),
        "ES256" => Box::new(jws::ES256.verifier_from_jwk(&public).ok()?),
        "ES512" => Box::new(jws::ES512.verifier_from_jwk(&public).ok()?),
        "PS256" => Box::new(jws::PS256.verifier_from_jwk(&public).ok()?),
        _ => return None,
    };
    let (payload, _) = josekit::jwt::decode_with_verifier(token, verifier.as_ref()).ok()?;
    let claims = payload.claims_set();
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return None;
    }
    let aud = claims.get("aud")?;
    if aud.as_str() != Some(audience)
        && !aud.as_array().is_some_and(|values| {
            values.iter().all(Value::is_string)
                && values.iter().any(|value| value.as_str() == Some(audience))
        })
    {
        return None;
    }
    let now = Utc::now().timestamp() as f64;
    for field in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(field) {
            let value = value.as_f64()?;
            if (field == "exp" && value <= now - tolerance as f64)
                || (field == "nbf" && value > now + tolerance as f64)
            {
                return None;
            }
        }
    }
    Some(claims.clone())
}
