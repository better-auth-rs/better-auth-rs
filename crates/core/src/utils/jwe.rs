//! Shared encrypted JWTs for session and OAuth account cookies.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hkdf::Hkdf;
use josekit::jwe::{self, Dir, JweHeader};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{AuthError, AuthResult, config::SecretKey};

fn encryption_key(secret: &str, salt: &str) -> AuthResult<[u8; 64]> {
    let mut key = [0; 64];
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_bytes())
        .expand(b"BetterAuth.js Generated Encryption Key", &mut key)
        .map_err(|error| AuthError::internal(format!("Derive cookie encryption key: {error}")))?;
    Ok(key)
}

fn key_id(key: &[u8]) -> String {
    let thumbprint = format!(r#"{{"k":"{}","kty":"oct"}}"#, URL_SAFE_NO_PAD.encode(key));
    URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint))
}

/// Encrypt a JWT with the current secret and the specified cookie purpose.
pub fn encode<'a>(
    mut payload: Map<String, Value>,
    secret: impl Into<SecretKey<'a>>,
    salt: &str,
    expires_in: f64,
) -> AuthResult<String> {
    let key = encryption_key(secret.into().current()?, salt)?;
    let now = Utc::now().timestamp();
    let _ = payload.insert("iat".into(), now.into());
    let _ = payload.insert(
        "exp".into(),
        crate::wire::serialize_optional_number(
            &Some(now as f64 + expires_in),
            serde_json::value::Serializer,
        )?,
    );
    let _ = payload.insert("jti".into(), uuid::Uuid::new_v4().to_string().into());
    let mut header = JweHeader::new();
    header.set_algorithm("dir");
    header.set_content_encryption("A256CBC-HS512");
    header.set_key_id(key_id(&key));
    let encrypter = Dir
        .encrypter_from_bytes(key)
        .map_err(|error| AuthError::internal(format!("Create cookie encrypter: {error}")))?;
    jwe::serialize_compact(&serde_json::to_vec(&payload)?, &header, &encrypter)
        .map_err(|error| AuthError::internal(format!("Encrypt cookie: {error}")))
}

/// Read retained encryption keys. An explicit unknown key ID never falls back.
pub fn decode<'a>(
    token: &str,
    secret: impl Into<SecretKey<'a>>,
    salt: &str,
) -> Option<Map<String, Value>> {
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next()?).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "dir"
        || !matches!(header.get("enc")?.as_str()?, "A256CBC-HS512" | "A256GCM")
    {
        return None;
    }
    let secrets: Vec<_> = match secret.into() {
        SecretKey::Single(secret) => vec![secret],
        SecretKey::Versioned {
            keys,
            legacy_secret,
        } => {
            let mut secrets: Vec<_> = keys.iter().map(|key| key.value.as_str()).collect();
            if let Some(legacy) = legacy_secret.filter(|legacy| !secrets.contains(legacy)) {
                secrets.push(legacy);
            }
            secrets
        }
    };
    for secret in secrets {
        let key = encryption_key(secret, salt).ok()?;
        if header
            .get("kid")
            .is_some_and(|kid| kid.as_str() != Some(key_id(&key).as_str()))
        {
            continue;
        }
        let decrypter = Dir.decrypter_from_bytes(key).ok()?;
        let Ok((plaintext, _)) = jwe::deserialize_compact(token, &decrypter) else {
            continue;
        };
        let payload: Map<String, Value> = serde_json::from_slice(&plaintext).ok()?;
        let now = Utc::now().timestamp() as f64;
        if let Some(expiration) = payload.get("exp")
            && expiration.as_f64()? <= now - 15.0
        {
            return None;
        }
        if let Some(not_before) = payload.get("nbf")
            && not_before.as_f64()? > now + 15.0
        {
            return None;
        }
        if let Some(issued) = payload.get("iat") {
            let _ = issued.as_f64()?;
        }
        return Some(payload);
    }
    None
}
