use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use reqwest::{Client, StatusCode, header::HeaderMap};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use url::Url;

const CACHE_MAX_AGE: Duration = Duration::from_secs(600);
const RELOAD_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(super) enum OidcError {
    #[error("OIDC HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWKS endpoint returned {0}, expected 200 OK")]
    Status(StatusCode),
    #[error("OIDC JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OIDC URL is invalid: {0}")]
    Url(#[from] url::ParseError),
    #[error("ID token encoding is invalid: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ID token signature verification failed: {0}")]
    Signature(#[from] jsonwebtoken::errors::Error),
    #[error("ID token signature verification failed: {0}")]
    Jose(#[from] josekit::JoseError),
    #[error("ID token signature verification failed: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("No matching JWKS key")]
    NoMatchingKey,
    #[error("{0}")]
    Invalid(&'static str),
}

#[derive(Debug, Deserialize)]
pub(super) struct DiscoveryDocument {
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub issuer: Option<String>,
    pub jwks_uri: Option<String>,
    #[serde(default, deserialize_with = "deserialize_signing_algorithms")]
    pub id_token_signing_alg_values_supported: Option<Vec<Value>>,
}

fn deserialize_signing_algorithms<'de, D>(deserializer: D) -> Result<Option<Vec<Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::Array(values) => Some(values),
        _ => None,
    })
}

pub(super) async fn fetch_discovery(
    url: &str,
    headers: &HeaderMap,
) -> Result<DiscoveryDocument, OidcError> {
    let document: DiscoveryDocument = Client::builder()
        .build()?
        .get(url)
        .headers(headers.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(issuer) = document
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())
    {
        let _ = Url::parse(issuer)?;
    }
    Ok(document)
}

#[derive(Debug)]
struct CachedJwks {
    keys: Vec<Value>,
    fetched_at: Instant,
}

#[derive(Debug)]
pub(super) struct OidcVerifier {
    client: Client,
    jwks_url: Url,
    issuer: String,
    audiences: Vec<String>,
    max_token_age: Option<Duration>,
    algorithms: Option<Vec<Value>>,
    cache: RwLock<Option<Arc<CachedJwks>>>,
    reload: Semaphore,
    #[cfg(test)]
    pub(super) verification_calls: std::sync::atomic::AtomicUsize,
}

impl OidcVerifier {
    pub(super) fn new(
        jwks_url: Url,
        issuer: String,
        audience: String,
        algorithms: Option<Vec<Value>>,
    ) -> Result<Self, OidcError> {
        Self::with_policy(jwks_url, issuer, vec![audience], algorithms, None)
    }

    pub(super) fn with_policy(
        jwks_url: Url,
        issuer: String,
        audiences: Vec<String>,
        algorithms: Option<Vec<Value>>,
        max_token_age: Option<Duration>,
    ) -> Result<Self, OidcError> {
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            jwks_url,
            issuer,
            audiences,
            max_token_age,
            algorithms,
            cache: RwLock::new(None),
            reload: Semaphore::new(1),
            #[cfg(test)]
            verification_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub(super) async fn verify(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<Value, OidcError> {
        #[cfg(test)]
        let _ = self
            .verification_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OidcError::Invalid("ID token must be a compact JWT"));
        };
        let header: Map<String, Value> = serde_json::from_slice(&decode_base64(header)?)?;
        let algorithm = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(OidcError::Invalid("ID token algorithm is missing"))?;
        if self.algorithms.as_ref().is_some_and(|allowed| {
            !allowed.iter().all(Value::is_string)
                || !allowed.iter().any(|alg| alg.as_str() == Some(algorithm))
        }) {
            return Err(OidcError::Invalid("ID token algorithm is not allowed"));
        }
        validate_critical_headers(&header)?;
        let cached = self.keys(false).await?;
        let key = match select_key(&cached.keys, &header, algorithm) {
            Err(OidcError::NoMatchingKey) => {
                let refreshed = self.keys(true).await?;
                select_key(&refreshed.keys, &header, algorithm)?.clone()
            }
            result => result?.clone(),
        };
        let (message, _) = token
            .rsplit_once('.')
            .ok_or(OidcError::Invalid("ID token must be a compact JWT"))?;
        verify_signature(algorithm, &key, signature, message.as_bytes())?;
        let claims: Map<String, Value> = serde_json::from_slice(&decode_base64(payload)?)?;
        validate_claims(
            &claims,
            &self.issuer,
            &self.audiences,
            nonce,
            self.max_token_age,
        )?;
        Ok(Value::Object(claims))
    }

    fn cached(&self, refresh: bool) -> Result<Option<Arc<CachedJwks>>, OidcError> {
        let cache = self
            .cache
            .read()
            .map_err(|_| OidcError::Invalid("OIDC cache lock is poisoned"))?;
        let maximum = if refresh {
            RELOAD_COOLDOWN
        } else {
            CACHE_MAX_AGE
        };
        Ok(cache
            .as_ref()
            .filter(|keys| keys.fetched_at.elapsed() < maximum)
            .cloned())
    }

    async fn keys(&self, refresh: bool) -> Result<Arc<CachedJwks>, OidcError> {
        if let Some(cached) = self.cached(refresh)? {
            return Ok(cached);
        }
        // Serialize remote reloads without holding the cache lock across network I/O.
        let _permit = self
            .reload
            .acquire()
            .await
            .map_err(|_| OidcError::Invalid("OIDC reload semaphore is closed"))?;
        if let Some(cached) = self.cached(refresh)? {
            return Ok(cached);
        }
        let response = self
            .client
            .get(self.jwks_url.clone())
            .header("Accept", "application/json, application/jwk-set+json")
            .header("User-Agent", "jose/v6.2.12")
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(OidcError::Status(response.status()));
        }
        let document: Value = response.json().await?;
        let keys = document
            .get("keys")
            .and_then(Value::as_array)
            .filter(|keys| keys.iter().all(Value::is_object))
            .ok_or(OidcError::Invalid(
                "JWKS must contain an array of key objects",
            ))?;
        let cached = Arc::new(CachedJwks {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
        *self
            .cache
            .write()
            .map_err(|_| OidcError::Invalid("OIDC cache lock is poisoned"))? = Some(cached.clone());
        Ok(cached)
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>, OidcError> {
    Ok(URL_SAFE_NO_PAD.decode(value.trim_end_matches('='))?)
}

fn validate_critical_headers(header: &Map<String, Value>) -> Result<(), OidcError> {
    if let Some(critical) = header.get("crit") {
        let fields = critical
            .as_array()
            .filter(|fields| !fields.is_empty())
            .ok_or(OidcError::Invalid("Invalid critical JWT headers"))?;
        if fields.iter().any(|field| field.as_str() != Some("b64"))
            || header.get("b64") != Some(&Value::Bool(true))
        {
            return Err(OidcError::Invalid("Unsupported critical JWT header"));
        }
    }
    Ok(())
}

fn select_key<'a>(
    keys: &'a [Value],
    header: &Map<String, Value>,
    algorithm: &str,
) -> Result<&'a Value, OidcError> {
    let (key_type, curve) = match algorithm {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => ("RSA", None),
        "ES256" => ("EC", Some("P-256")),
        "ES384" => ("EC", Some("P-384")),
        "ES512" => ("EC", Some("P-521")),
        "EdDSA" | "Ed25519" => ("OKP", Some("Ed25519")),
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => ("AKP", None),
        _ => return Err(OidcError::Invalid("Unsupported JWKS algorithm")),
    };
    let mut matching = keys.iter().filter(|key| {
        key.get("kty").and_then(Value::as_str) == Some(key_type)
            && curve.is_none_or(|curve| key.get("crv").and_then(Value::as_str) == Some(curve))
            && header
                .get("kid")
                .is_none_or(|kid| kid.is_string() && key.get("kid") == Some(kid))
            && key
                .get("alg")
                .map_or(key_type != "AKP", |alg| alg.as_str() == Some(algorithm))
            && key
                .get("use")
                .is_none_or(|usage| usage.as_str() == Some("sig"))
            && key.get("ext").is_none_or(Value::is_boolean)
            && key.get("key_ops").is_none_or(|operations| {
                operations.as_array().is_some_and(|operations| {
                    operations
                        .iter()
                        .any(|operation| operation.as_str() == Some("verify"))
                        && operations.iter().enumerate().all(|(index, operation)| {
                            operation.is_string()
                                && !operations
                                    .iter()
                                    .take(index)
                                    .any(|other| other == operation)
                        })
                })
            })
    });
    let key = matching.next().ok_or(OidcError::NoMatchingKey)?;
    if matching.next().is_some() {
        return Err(OidcError::Invalid("Multiple matching JWKS keys"));
    }
    Ok(key)
}

fn verify_signature(
    algorithm: &str,
    key: &Value,
    signature: &str,
    message: &[u8],
) -> Result<(), OidcError> {
    if key.get("d").is_some() || key.get("priv").is_some() {
        return Err(OidcError::Invalid("JWKS members must be public keys"));
    }
    if key
        .get("key_ops")
        .and_then(Value::as_array)
        .is_some_and(|operations| {
            operations
                .iter()
                .any(|operation| operation.as_str() != Some("verify"))
        })
    {
        return Err(OidcError::Invalid(
            "Invalid public verification key operations",
        ));
    }
    if key.get("kty").and_then(Value::as_str) == Some("RSA") {
        let modulus = decode_base64(
            key.get("n")
                .and_then(Value::as_str)
                .ok_or(OidcError::Invalid("RSA modulus is missing"))?,
        )?;
        let first = modulus
            .iter()
            .position(|byte| *byte != 0)
            .ok_or(OidcError::Invalid("RSA modulus is empty"))?;
        let leading = modulus
            .get(first)
            .ok_or(OidcError::Invalid("RSA modulus is empty"))?
            .leading_zeros() as usize;
        if (modulus.len() - first) * 8 - leading < 2048 {
            return Err(OidcError::Invalid(
                "RSA keys must contain at least 2048 bits",
            ));
        }
    }
    if matches!(algorithm, "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87") {
        use openssl::{
            pkey::{KeyType, PKey},
            sign::Verifier,
        };
        let key_type = match algorithm {
            "ML-DSA-44" => KeyType::ML_DSA_44,
            "ML-DSA-65" => KeyType::ML_DSA_65,
            _ => KeyType::ML_DSA_87,
        };
        let public = key
            .get("pub")
            .and_then(Value::as_str)
            .ok_or(OidcError::Invalid("ML-DSA public key is missing"))?;
        let key =
            PKey::public_key_from_raw_bytes_ex(None, key_type, None, &decode_base64(public)?)?;
        if !Verifier::new_without_digest(&key)?
            .verify_oneshot(&decode_base64(signature)?, message)?
        {
            return Err(OidcError::Invalid("ID token signature is invalid"));
        }
    } else if algorithm == "ES512" {
        use josekit::jws::JwsVerifier;
        let key = josekit::jwk::Jwk::from_map(
            key.as_object()
                .ok_or(OidcError::Invalid("JWK must be an object"))?
                .iter()
                .filter(|(name, _)| matches!(name.as_str(), "kty" | "crv" | "x" | "y"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Map<String, Value>>(),
        )?;
        josekit::jws::ES512
            .verifier_from_jwk(&key)?
            .verify(message, &decode_base64(signature)?)?;
    } else {
        let algorithm = if algorithm == "Ed25519" {
            Algorithm::EdDSA
        } else {
            algorithm.parse()?
        };
        let component = |name| {
            key.get(name)
                .and_then(Value::as_str)
                .ok_or(OidcError::Invalid("JWK public key component is missing"))
        };
        let key = match algorithm {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                DecodingKey::from_rsa_components(component("n")?, component("e")?)?
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_components(component("x")?, component("y")?)?
            }
            Algorithm::EdDSA => DecodingKey::from_ed_components(component("x")?)?,
            _ => return Err(OidcError::Invalid("Unsupported JWKS algorithm")),
        };
        let signature = URL_SAFE_NO_PAD.encode(decode_base64(signature)?);
        if !jsonwebtoken::crypto::verify(&signature, message, &key, algorithm)? {
            return Err(OidcError::Invalid("ID token signature is invalid"));
        }
    }
    Ok(())
}

fn validate_claims(
    claims: &Map<String, Value>,
    issuer: &str,
    audiences: &[String],
    nonce: Option<&str>,
    max_token_age: Option<Duration>,
) -> Result<(), OidcError> {
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(OidcError::Invalid("ID token issuer does not match"));
    }
    let matches_audience = claims.get("aud").is_some_and(|claim| {
        audiences.iter().any(|audience| {
            claim.as_str() == Some(audience.as_str())
                || claim.as_array().is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some(audience.as_str()))
                })
        })
    });
    if !matches_audience {
        return Err(OidcError::Invalid("ID token audience does not match"));
    }
    let now = chrono::Utc::now().timestamp() as f64;
    if let Some(max_age) = max_token_age {
        let issued = claims
            .get("iat")
            .and_then(Value::as_f64)
            .ok_or(OidcError::Invalid(
                "ID token issued-at timestamp is required",
            ))?;
        let age = now - issued;
        if age < 0.0 || age > max_age.as_secs_f64() {
            return Err(OidcError::Invalid("ID token exceeds its maximum age"));
        }
    }
    for claim in ["iat", "nbf", "exp"] {
        if let Some(value) = claims.get(claim) {
            let value = value
                .as_f64()
                .ok_or(OidcError::Invalid("ID token timestamps must be numbers"))?;
            if (claim == "exp" && value <= now) || (claim == "nbf" && value > now) {
                return Err(OidcError::Invalid(
                    "ID token timestamp is outside its validity period",
                ));
            }
        }
    }
    if nonce
        .filter(|nonce| !nonce.is_empty())
        .is_some_and(|nonce| claims.get("nonce").and_then(Value::as_str) != Some(nonce))
    {
        return Err(OidcError::Invalid("ID token nonce does not match"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
