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
        let options = self.options.clone();
        let options = match issuer.filter(|issuer| !issuer.is_empty()) {
            Some(issuer) => options.with_issuer(issuer)?,
            None => options,
        };
        let Some(header) = raw_header(token).filter(Header::has_key_id) else {
            return Ok(None);
        };
        let verified = async {
            let keys = adapter::Keyring::new(adapter::store(endpoint), &options, endpoint)
                .all()
                .await?;
            if !keys.is_truthy() || keys.model_property("length")?.strict_equals(&0.into()) {
                return Ok(None);
            }
            let key = keys::find(&keys, header.field("kid")?)?;
            if !key.is_truthy() {
                return Ok(None);
            }
            let public = keys::parse_json(&key.model_property("publicKey")?)?;
            let algorithm = options.key_algorithm(&key)?;
            let (algorithm, public) = keys::import(public, &algorithm)?;
            let base = endpoint
                .auth
                .config
                .base_url
                .as_static()
                .map(|base| base.into())
                .unwrap_or_default();
            let issuer = overrides::nullish(options.property("jwt", "issuer")?, || base.clone());
            let audience = overrides::nullish(options.property("jwt", "audience")?, || base);
            verify_imported(token, &public, &algorithm, &issuer, &audience, 0)
        }
        .await;
        let verified = match verified {
            Ok(verified) => verified,
            Err(error) => {
                better_auth_core::observability::logger::current().debug(
                    "JWT verification failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                )?;
                return Ok(None);
            }
        };
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
                _ => FieldValue::parse_json(kid.get()).is_ok_and(|value| value.is_truthy()),
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
    public: FieldValue,
    algorithm: &FieldValue,
    issuer: Option<&str>,
    audience: Option<&[&str]>,
    tolerance: i64,
) -> AuthResult<Option<Map<String, Value>>> {
    let (algorithm, public) = keys::import(public, algorithm)?;
    let issuer = issuer.map(FieldValue::from).unwrap_or_default();
    let audience = audience
        .map(|values| {
            values
                .iter()
                .map(|value| FieldValue::from(*value))
                .collect::<Vec<_>>()
                .into()
        })
        .unwrap_or_default();
    verify_imported(token, &public, &algorithm, &issuer, &audience, tolerance)
}

fn verify_signed_claims(token: &str, public: &Jwk, algorithm: &str) -> Option<Map<String, Value>> {
    // WebCrypto requires a public key for verification; josekit also accepts private JWK material.
    if public.parameter("d").is_some() {
        return None;
    }
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        "EdDSA" => Box::new(jws::EdDSA.verifier_from_jwk(public).ok()?),
        "RS256" => Box::new(jws::RS256.verifier_from_jwk(public).ok()?),
        "ES256" => Box::new(jws::ES256.verifier_from_jwk(public).ok()?),
        "ES512" => Box::new(jws::ES512.verifier_from_jwk(public).ok()?),
        "PS256" => Box::new(jws::PS256.verifier_from_jwk(public).ok()?),
        _ => return None,
    };
    let protected = jose::header(token)?;
    let payload = jose::verify(
        token,
        &protected,
        verifier.algorithm().name(),
        |input, signature| verifier.verify(input, signature).is_ok(),
    )
    .ok()?;
    serde_json::from_slice(&payload).ok()
}

fn verify_imported(
    token: &str,
    public: &Jwk,
    algorithm: &str,
    issuer: &FieldValue,
    audience: &FieldValue,
    tolerance: i64,
) -> AuthResult<Option<Map<String, Value>>> {
    let Some(claims) = verify_signed_claims(token, public, algorithm) else {
        return Ok(None);
    };
    let issuer_claim = claims.get("iss");
    let audience_claim = claims.get("aud");
    if (!issuer.is_undefined() && issuer_claim.is_none())
        || (!audience.is_undefined() && audience_claim.is_none())
    {
        return Ok(None);
    }
    if let Some(value) = issuer_claim.filter(|_| !issuer.is_undefined()) {
        let accepted = if matches!(issuer, FieldValue::Array(_)) {
            issuer.clone()
        } else {
            vec![issuer.clone()].into()
        };
        if !accepted
            .includes_method(&FieldValue::from_json(value.clone())?, "issuer")?
            .is_truthy()
        {
            return Ok(None);
        }
    }
    if let Some(value) = audience_claim.filter(|_| !audience.is_undefined()) {
        let payload_audience = FieldValue::from_json(value.clone())?;
        let accepted = if audience.is_string() {
            vec![audience.clone()].into()
        } else {
            audience.clone()
        };
        let matches = if payload_audience.is_string() {
            accepted
                .includes_method(&payload_audience, "audOption")?
                .is_truthy()
        } else if matches!(payload_audience, FieldValue::Array(_)) {
            accepted
                .some_method(
                    &better_auth_core::FieldFunction::contextual(move |_, arguments| {
                        payload_audience.includes_method(
                            arguments.first().unwrap_or(&FieldValue::Undefined),
                            "audPayload",
                        )
                    }),
                    "audOption",
                )?
                .is_truthy()
        } else {
            false
        };
        if !matches {
            return Ok(None);
        }
    }
    let now = Utc::now().timestamp() as f64;
    for field in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(field) {
            let Some(value) = value.as_f64() else {
                return Ok(None);
            };
            if (field == "exp" && value <= now - tolerance as f64)
                || (field == "nbf" && value > now + tolerance as f64)
            {
                return Ok(None);
            }
        }
    }
    Ok(Some(claims))
}

#[cfg(test)]
#[path = "verification_native_tests.rs"]
mod native_tests;
