use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use josekit::jwe::{self, Dir, JweHeader};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::config::{AuthConfig, CookieCacheConfig, CookieCacheStrategy};
use crate::utils::cookie_utils::{
    create_clear_cookie, create_session_like_cookie, get_cookie, related_cookie_name,
};
use crate::{AuthError, AuthRequest, AuthResult};

use super::SessionData;

#[derive(Debug, Deserialize)]
pub(super) struct CachedSession {
    #[serde(flatten)]
    pub data: SessionData,
    #[serde(rename = "updatedAt")]
    pub _updated_at: i64,
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "1".to_string()
}

// Upstream revives UTC dates before checking the Compact HMAC. Use the same
// millisecond representation so JSON.stringify(Date) preserves the signed bytes.
fn normalize_dates(value: &mut Value) {
    match value {
        Value::String(text) if text.ends_with('Z') && text.contains('T') => {
            if let Ok(date) = chrono::DateTime::parse_from_rfc3339(text) {
                *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_dates),
        Value::Object(values) => values.values_mut().for_each(normalize_dates),
        _ => {}
    }
}

fn encryption_key(secret: &str) -> AuthResult<[u8; 64]> {
    let mut key = [0; 64];
    Hkdf::<Sha256>::new(Some(b"better-auth-session"), secret.as_bytes())
        .expand(b"BetterAuth.js Generated Encryption Key", &mut key)
        .map_err(|error| {
            AuthError::internal(format!("Deriving session encryption key: {error}"))
        })?;
    Ok(key)
}

fn key_id(key: &[u8]) -> String {
    let thumbprint = format!(r#"{{"k":"{}","kty":"oct"}}"#, URL_SAFE_NO_PAD.encode(key));
    URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint))
}

pub(super) async fn payload(
    data: &SessionData,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    dont_remember: bool,
) -> AuthResult<(serde_json::Map<String, Value>, i64)> {
    let now = Utc::now();
    let version = cache.version.resolve(data).await?;
    let mut public = data.clone();
    public.user.filter_cached_fields(&config.user);
    public.session.filter_returned_fields(&config.session);
    let mut payload = serde_json::Map::new();
    let _ = payload.insert("session".into(), serde_json::to_value(&public.session)?);
    let _ = payload.insert("user".into(), serde_json::to_value(&public.user)?);
    let _ = payload.insert("updatedAt".into(), now.timestamp_millis().into());
    let _ = payload.insert("version".into(), version.into());
    for value in payload.values_mut() {
        normalize_dates(value);
    }
    let max_age = if dont_remember {
        300
    } else {
        cache.max_age.num_seconds()
    };
    Ok((payload, max_age))
}

pub(super) async fn encode(
    data: &SessionData,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    dont_remember: bool,
) -> AuthResult<String> {
    let now = Utc::now();
    let (payload, max_age) = payload(data, config, cache, dont_remember).await?;
    match cache.strategy {
        CookieCacheStrategy::Compact => {
            let expires_at = now.timestamp_millis()
                + if dont_remember {
                    60_000
                } else {
                    max_age * 1000
                };
            let mut signed = payload.clone();
            let _ = signed.insert("expiresAt".into(), expires_at.into());
            let mut mac = Hmac::<Sha256>::new_from_slice(config.secret.as_bytes())
                .map_err(|error| AuthError::internal(format!("Signing session cache: {error}")))?;
            mac.update(&serde_json::to_vec(&signed)?);
            Ok(
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
                    "session": payload, "expiresAt": expires_at,
                    "signature": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
                }))?),
            )
        }
        CookieCacheStrategy::Jwt => {
            let mut claims = payload;
            let _ = claims.insert("iat".into(), now.timestamp().into());
            let _ = claims.insert("exp".into(), (now.timestamp() + max_age).into());
            let mut header = Header::new(Algorithm::HS256);
            header.typ = None;
            Ok(jsonwebtoken::encode(
                &header,
                &claims,
                &EncodingKey::from_secret(config.secret.as_bytes()),
            )?)
        }
        CookieCacheStrategy::Jwe => {
            let key = encryption_key(&config.secret)?;
            let mut claims = payload;
            let _ = claims.insert("iat".into(), now.timestamp().into());
            let _ = claims.insert("exp".into(), (now.timestamp() + max_age).into());
            let _ = claims.insert("jti".into(), uuid::Uuid::new_v4().to_string().into());
            let mut header = JweHeader::new();
            header.set_algorithm("dir");
            header.set_content_encryption("A256CBC-HS512");
            header.set_key_id(key_id(&key));
            let encrypter = Dir.encrypter_from_bytes(key).map_err(|error| {
                AuthError::internal(format!("Creating session cache encrypter: {error}"))
            })?;
            jwe::serialize_compact(&serde_json::to_vec(&claims)?, &header, &encrypter)
                .map_err(|error| AuthError::internal(format!("Encrypting session cache: {error}")))
        }
    }
}

pub(super) fn parse_jwt(payload: serde_json::Map<String, Value>) -> Option<(CachedSession, i64)> {
    let expires = payload.get("exp")?.as_i64()?.checked_mul(1000)?;
    let mut parsed: CachedSession = serde_json::from_value(Value::Object(payload)).ok()?;
    parsed.data.session.active = true;
    Some((parsed, expires))
}

pub(super) fn decode(
    value: &str,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
) -> Option<(CachedSession, i64)> {
    let (payload, expires_at) = match cache.strategy {
        CookieCacheStrategy::Compact => {
            let raw: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).ok()?).ok()?;
            let payload = raw.get("session")?.as_object()?;
            let expires = raw.get("expiresAt")?.as_i64()?;
            let signature = URL_SAFE_NO_PAD
                .decode(raw.get("signature")?.as_str()?)
                .ok()?;
            let mut signed = payload.clone();
            let _ = signed.insert("expiresAt".into(), expires.into());
            let mut mac = Hmac::<Sha256>::new_from_slice(config.secret.as_bytes()).ok()?;
            mac.update(&serde_json::to_vec(&signed).ok()?);
            mac.verify_slice(&signature).ok()?;
            (Value::Object(payload.clone()), expires)
        }
        CookieCacheStrategy::Jwt => {
            let mut validation = Validation::new(Algorithm::HS256);
            validation.leeway = 0;
            validation.validate_aud = false;
            let payload = jsonwebtoken::decode::<Value>(
                value,
                &DecodingKey::from_secret(config.secret.as_bytes()),
                &validation,
            )
            .ok()?
            .claims;
            let expires = payload.get("exp")?.as_i64()?.checked_mul(1000)?;
            (payload, expires)
        }
        CookieCacheStrategy::Jwe => {
            let key = encryption_key(&config.secret).ok()?;
            let decrypter = Dir.decrypter_from_bytes(key).ok()?;
            let (plaintext, header) = jwe::deserialize_compact(value, &decrypter).ok()?;
            if header.algorithm() != Some("dir")
                || header.content_encryption() != Some("A256CBC-HS512")
                || header.key_id().is_some_and(|kid| kid != key_id(&key))
            {
                return None;
            }
            let payload: Value = serde_json::from_slice(&plaintext).ok()?;
            let expires = payload.get("exp")?.as_i64()?.checked_mul(1000)?;
            (payload, expires)
        }
    };
    let mut payload: CachedSession = serde_json::from_value(payload).ok()?;
    // `active` is internal state and is intentionally absent from wire payloads.
    payload.data.session.active = true;
    Some((payload, expires_at))
}

fn chunk_index(name: &str, cookie_name: &str) -> Option<usize> {
    let suffix = name.strip_prefix(cookie_name)?.strip_prefix('.')?;
    let index: usize = suffix.parse().ok()?;
    (index.to_string() == suffix).then_some(index)
}

pub(super) fn existing_names(req: &AuthRequest, name: &str) -> Vec<String> {
    req.headers
        .get("cookie")
        .map(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .filter(|cookie| {
                    cookie.name() == name || chunk_index(cookie.name(), name).is_some()
                })
                .map(|cookie| cookie.name().to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn read(req: &AuthRequest, name: &str) -> Option<String> {
    if let Some(value) = get_cookie(req, name).filter(|value| !value.is_empty()) {
        return Some(value);
    }
    let mut chunks = BTreeMap::new();
    for cookie in cookie::Cookie::split_parse(req.headers.get("cookie")?).flatten() {
        if let Some(index) = chunk_index(cookie.name(), name) {
            let _ = chunks.insert(index, cookie.value().to_string());
        }
    }
    (!chunks.is_empty()).then(|| chunks.into_values().collect())
}

pub(super) fn clear(req: &AuthRequest, config: &AuthConfig) -> AuthResult<()> {
    let name = related_cookie_name(config, "session_data");
    req.append_response_header("Set-Cookie", create_clear_cookie(&name, config))?;
    for chunk in existing_names(req, &name)
        .into_iter()
        .filter(|chunk| chunk != &name)
    {
        req.append_response_header("Set-Cookie", create_clear_cookie(&chunk, config))?;
    }
    Ok(())
}

pub(super) async fn write(
    req: &AuthRequest,
    data: &SessionData,
    config: &AuthConfig,
    dont_remember: bool,
    signed: Option<String>,
) -> AuthResult<()> {
    let Some(cache) = config
        .session
        .cookie_cache
        .as_ref()
        .filter(|cache| cache.enabled)
    else {
        return Ok(());
    };
    let value = match signed {
        Some(value) => value,
        None => encode(data, config, cache, dont_remember).await?,
    };
    let name = related_cookie_name(config, "session_data");
    let max_age = (!dont_remember).then_some(cache.max_age.num_seconds());
    let overhead = create_session_like_cookie(&format!("{name}.99"), "", max_age, config).len();
    let Some(chunk_size) = 4050_usize.checked_sub(overhead).filter(|size| *size > 0) else {
        return Ok(());
    };
    let count = value.len().div_ceil(chunk_size);
    let mut cookies: BTreeMap<String, String> = existing_names(req, &name)
        .into_iter()
        .map(|name| {
            let cookie = create_clear_cookie(&name, config);
            (name, cookie)
        })
        .collect();
    if count <= 100 {
        if count <= 1 {
            let _ = cookies.insert(
                name.clone(),
                create_session_like_cookie(&name, &value, max_age, config),
            );
        } else {
            for (index, chunk) in value.as_bytes().chunks(chunk_size).enumerate() {
                let chunk_name = format!("{name}.{index}");
                // All supported cache encodings use ASCII.
                let value = std::str::from_utf8(chunk).map_err(|error| {
                    AuthError::internal(format!("Encoding session cache chunk: {error}"))
                })?;
                let _ = cookies.insert(
                    chunk_name.clone(),
                    create_session_like_cookie(&chunk_name, value, max_age, config),
                );
            }
        }
    } else {
        tracing::warn!("Session cookie cache exceeds the 100 chunk limit; cache not stored");
    }
    for cookie in cookies.into_values() {
        req.append_response_header("Set-Cookie", cookie)?;
    }
    Ok(())
}
