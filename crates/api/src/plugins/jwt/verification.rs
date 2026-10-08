use super::*;
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use josekit::jws::JwsVerifier;

impl JwtPlugin {
    /// Verify a token with adapter keys. Invalid tokens and verification adapter errors return `None`.
    ///
    /// The optional issuer overrides the configured issuer. Like upstream `verifyJWT`,
    /// this reads local adapter keys even when `remote_url` is configured.
    pub async fn verify<S: AuthSchema>(
        &self,
        token: &str,
        issuer: Option<&str>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let body = verification_body(token, issuer);
            let mut endpoint = EndpointContext::new(
                None,
                better_auth_core::FieldValue::from_json(body)?,
                &resolved,
            );
            endpoint.path = Some("virtual:");
            self.verify_in_endpoint(token, issuer, &endpoint).await
        })
        .await
    }

    /// Verify with the supplied endpoint context and its key-adapter callbacks.
    pub async fn verify_in_endpoint<S: AuthSchema>(
        &self,
        token: &str,
        issuer: Option<&str>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        if !has_key_id(token) {
            return Ok(None);
        }
        let keys = match self.read_keys(endpoint).await {
            Ok(Some(keys)) => keys,
            Ok(None) => return Ok(None),
            Err(error) => {
                better_auth_core::observability::logger::current().debug(
                    "JWT verification failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                return Ok(None);
            }
        };
        let ctx = endpoint.auth;
        let issuer = issuer
            .filter(|issuer| !issuer.is_empty())
            .or(self.config.issuer.as_deref())
            .or(ctx.config.base_url.as_static());
        let audience = self
            .config
            .audience
            .as_ref()
            .map(JwtAudience::recipients)
            .or_else(|| ctx.config.base_url.as_static().map(|base| vec![base]));
        let verified = verify_local(
            token,
            &keys,
            Some(self.config.primary_algorithm()),
            issuer,
            audience.as_deref(),
            0,
        );
        Ok(verified.filter(|payload| {
            ["sub", "aud"].iter().all(|claim| {
                payload
                    .get(*claim)
                    .is_some_and(crate::plugins::json_body::is_truthy)
            })
        }))
    }
}

pub(super) fn verification_body(token: &str, issuer: Option<&str>) -> Value {
    let mut body = Map::from_iter([("token".into(), token.into())]);
    if let Some(issuer) = issuer {
        let _ = body.insert("issuer".into(), issuer.into());
    }
    body.into()
}

pub(super) fn has_key_id(token: &str) -> bool {
    raw_header(token).is_some_and(|header| header.has_key_id())
}

#[serde_with::serde_as]
#[derive(serde::Deserialize)]
#[serde(transparent)]
pub(super) struct Header(
    // Unknown JSON property names can contain unpaired surrogates and must not reject key lookup.
    #[serde_as(as = "std::collections::HashMap<serde_with::Bytes, _>")]
    std::collections::HashMap<Vec<u8>, Box<serde_json::value::RawValue>>,
);

impl Header {
    pub(super) fn has_key_id(&self) -> bool {
        self.0
            .get(b"kid".as_slice())
            .is_some_and(|kid| match kid.get().as_bytes().first() {
                Some(b'"') => kid.get() != "\"\"",
                Some(b'[' | b'{') => true,
                _ => serde_json::from_str::<Value>(kid.get())
                    .is_ok_and(|value| crate::plugins::json_body::is_truthy(&value)),
            })
    }

    pub(super) fn has_type(&self, expected: &str) -> bool {
        self.0.get(b"typ".as_slice()).is_some_and(|typ| {
            serde_json::from_str::<String>(typ.get()).is_ok_and(|typ| typ == expected)
        })
    }

    pub(super) fn field(&self, name: &str) -> AuthResult<FieldValue> {
        self.0
            .get(name.as_bytes())
            .map_or(Ok(FieldValue::Undefined), |value| {
                FieldValue::parse_json(value.get())
            })
    }
}

pub(super) fn raw_header(token: &str) -> Option<Header> {
    if token.split('.').count() != 3 {
        return None;
    }
    let encoded = token.split('.').next()?;
    let alphabet = if encoded.contains(['-', '_']) {
        &alphabet::URL_SAFE
    } else {
        &alphabet::STANDARD
    };
    let engine = GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let encoded = encoded.split('=').next()?;
    // The upstream decoder validates incomplete sextets, discards their bits, and stops at padding.
    let encoded = if encoded.len() % 4 == 1 {
        let _ = engine
            .decode([*encoded.as_bytes().last()?, b'A', b'A', b'A'])
            .ok()?;
        encoded.get(..encoded.len() - 1)?
    } else {
        encoded
    };
    let bytes = engine.decode(encoded).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

pub(super) fn verify_local(
    token: &str,
    keys: &[better_auth_core::Jwk],
    default_algorithm: Option<JwtAlgorithm>,
    issuer: Option<&str>,
    audience: Option<&[&str]>,
    tolerance: i64,
) -> Option<Map<String, Value>> {
    let header = raw_header(token)?;
    let kid = header.field("kid").ok()?;
    let key = keys
        .iter()
        .find(|key| key.id.field_value().strict_equals(&kid))?;
    let fallback = match default_algorithm {
        Some(algorithm) => algorithm.name().into(),
        None => header.field("alg").ok()?,
    };
    let algorithm = keys::algorithm(key, fallback);
    let (algorithm, public) = keys::import(
        keys::parse_json(&key.public_key.field_value()).ok()?,
        &algorithm,
    )
    .ok()?;
    let verifier: Box<dyn JwsVerifier> = match algorithm.as_str() {
        "EdDSA" => Box::new(jws::EdDSA.verifier_from_jwk(&public).ok()?),
        "RS256" => Box::new(jws::RS256.verifier_from_jwk(&public).ok()?),
        "ES256" => Box::new(jws::ES256.verifier_from_jwk(&public).ok()?),
        "ES512" => Box::new(jws::ES512.verifier_from_jwk(&public).ok()?),
        "PS256" => Box::new(jws::PS256.verifier_from_jwk(&public).ok()?),
        _ => return None,
    };
    let protected = jose::header(token)?;
    let payload = jose::verify(token, &protected, verifier.as_ref())?;
    let claims: Map<String, Value> = serde_json::from_slice(&payload).ok()?;
    if issuer.is_some_and(|issuer| claims.get("iss").and_then(Value::as_str) != Some(issuer)) {
        return None;
    }
    if let Some(audience) = audience {
        let aud = claims.get("aud")?;
        if !aud.as_str().is_some_and(|value| audience.contains(&value))
            && !aud.as_array().is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| audience.contains(&value))
                })
            })
        {
            return None;
        }
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
    Some(claims)
}
