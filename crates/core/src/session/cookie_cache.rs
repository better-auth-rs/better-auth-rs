use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::Value;
use sha2::Sha256;

use crate::config::{AuthConfig, CookieCacheConfig, CookieCacheStrategy};
use crate::utils::cookie_utils::{
    clear_existing_cookies, create_chunked_cookies, expire_cookie, related_cookie_name,
};
use crate::{
    AuthError, AuthRequest, AuthResult, CookieAttributes, FieldMap, FieldValue, FromFieldMap,
};

pub(super) use crate::utils::cookie_utils::get_chunked_cookie as read;

use super::{NativeSessionData, SessionData};

#[derive(Debug)]
pub(super) struct CachedSession {
    pub data: SessionData,
    pub version: String,
}

fn cache_cookie(
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    dont_remember: bool,
) -> crate::request_runtime::ResolvedCookie {
    let mut cookie = config.auth_cookie(
        "session_data",
        CookieAttributes {
            max_age: Some(cache.max_age().as_seconds_f64()),
            ..Default::default()
        },
    );
    if dont_remember {
        cookie.attributes.max_age = None;
    }
    cookie
}

// Upstream revives UTC dates before checking the Compact HMAC. Use the same
// millisecond representation so JSON.stringify(Date) preserves the signed bytes.
fn normalize_dates(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(date) = crate::utils::json::parse_json_date(text) {
                *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_dates),
        Value::Object(values) => values.values_mut().for_each(normalize_dates),
        _ => {}
    }
}

pub(super) async fn payload(
    data: &NativeSessionData,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    dont_remember: bool,
) -> AuthResult<(serde_json::Map<String, Value>, f64)> {
    let now = Utc::now();
    let mut session = data.session.clone();
    session.filter_returned_fields(&config.session);
    let user = data.public_user(&config.user)?;
    let version = cache.version.resolve(data).await?;
    let mut payload = serde_json::Map::new();
    let _ = payload.insert("session".into(), serde_json::to_value(&session)?);
    let _ = payload.insert(
        "user".into(),
        serde_json::to_value(crate::field_value::serde::Json(&user))?,
    );
    let _ = payload.insert("updatedAt".into(), now.timestamp_millis().into());
    let _ = payload.insert("version".into(), version.into());
    let max_age = cache_cookie(config, cache, dont_remember)
        .attributes
        .max_age
        .filter(|age| *age != 0.0 && !age.is_nan())
        .unwrap_or(300.0);
    Ok((payload, max_age))
}

pub(super) async fn encode(
    data: &NativeSessionData,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    dont_remember: bool,
) -> AuthResult<String> {
    let now = Utc::now();
    let (payload, max_age) = payload(data, config, cache, dont_remember).await?;
    match cache.strategy() {
        CookieCacheStrategy::Compact => {
            let expires_at = crate::utils::date::from_milliseconds(
                now.timestamp_millis() as f64
                    + cache_cookie(config, cache, dont_remember)
                        .attributes
                        .max_age
                        .filter(|age| *age != 0.0 && !age.is_nan())
                        .unwrap_or(60.0)
                        * 1000.0,
            )
            .ok_or_else(|| AuthError::config("Invalid cookie cache lifetime"))?
            .timestamp_millis();
            let mut signed = payload.clone();
            let _ = signed.insert("expiresAt".into(), expires_at.into());
            let mut mac = Hmac::<Sha256>::new_from_slice(config.signing_secret().as_bytes())
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
            let _ = claims.insert(
                "exp".into(),
                crate::wire::serialize_optional_number(
                    &Some(now.timestamp() as f64 + max_age),
                    serde_json::value::Serializer,
                )?,
            );
            let mut header = Header::new(Algorithm::HS256);
            header.typ = None;
            Ok(jsonwebtoken::encode(
                &header,
                &claims,
                &EncodingKey::from_secret(config.signing_secret().as_bytes()),
            )?)
        }
        CookieCacheStrategy::Jwe => crate::utils::jwe::encode(
            payload,
            config.encryption_secret(),
            "better-auth-session",
            max_age,
        ),
    }
}

fn parse_payload(payload: Value) -> Option<CachedSession> {
    fn core_fields(fields: &mut FieldMap) -> Option<()> {
        fields.get("id")?.as_str()?;
        for name in ["createdAt", "updatedAt"] {
            if fields.get(name).is_none_or(FieldValue::is_undefined) {
                let _ = fields.insert(name.into(), Utc::now().into());
            }
            if !fields.get(name)?.as_date()?.milliseconds().is_finite() {
                return None;
            }
        }
        Some(())
    }

    fn optional_string(fields: &FieldMap, name: &str) -> bool {
        fields
            .get(name)
            .is_none_or(|value| value.is_undefined() || value.is_null() || value.as_str().is_some())
    }

    // All signed cache strategies validate the upstream schemas after reviving ISO dates.
    // Adapter views remain permissive; cookie validity is a separate trust boundary.
    let payload = crate::utils::json::safe_parse_field(&FieldValue::from_json(payload).ok()?);
    let fields = payload.as_object()?;
    let _ = fields.get("updatedAt")?.as_f64()?;
    let version = match fields.get("version") {
        None | Some(FieldValue::Undefined) => "1".to_owned(),
        Some(value) => value.as_str()?.to_owned(),
    };
    let mut user = fields.get("user")?.as_object()?.clone();
    core_fields(&mut user)?;
    let email = user.get("email")?.as_str()?.to_lowercase();
    user.get("name")?.as_str()?;
    if !optional_string(&user, "image") {
        return None;
    }
    match user.get("emailVerified") {
        None | Some(FieldValue::Undefined) => {
            let _ = user.insert("emailVerified".into(), false.into());
        }
        Some(FieldValue::Bool(_)) => {}
        _ => return None,
    }
    let _ = user.insert("email".into(), email.into());
    let user = user.in_field_order(&[
        "id".into(),
        "createdAt".into(),
        "updatedAt".into(),
        "email".into(),
        "emailVerified".into(),
        "name".into(),
        "image".into(),
    ]);
    let mut session = fields.get("session")?.as_object()?.clone();
    core_fields(&mut session)?;
    let user_id = session
        .get("userId")
        .unwrap_or(&FieldValue::Undefined)
        .display_utf16()
        .ok()?;
    let _ = session.insert("userId".into(), user_id.into());
    session.get("token")?.as_str()?;
    if !session
        .get("expiresAt")?
        .as_date()?
        .milliseconds()
        .is_finite()
        || !optional_string(&session, "ipAddress")
        || !optional_string(&session, "userAgent")
    {
        return None;
    }
    let session = session.in_field_order(&[
        "id".into(),
        "createdAt".into(),
        "updatedAt".into(),
        "userId".into(),
        "expiresAt".into(),
        "token".into(),
        "ipAddress".into(),
        "userAgent".into(),
    ]);
    Some(CachedSession {
        data: SessionData {
            user: crate::UserView::from_field_values(user).ok()?,
            session: crate::SessionView::from_field_values(session).ok()?,
        },
        version,
    })
}

pub(super) fn parse_jwt(payload: serde_json::Map<String, Value>) -> Option<(CachedSession, i64)> {
    let expires = crate::utils::date::from_milliseconds(payload.get("exp")?.as_f64()? * 1000.0)?
        .timestamp_millis();
    let mut parsed: CachedSession = parse_payload(Value::Object(payload))?;
    parsed.data.session.active = true;
    Some((parsed, expires))
}

pub(super) fn decode(
    value: &str,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
) -> Option<(CachedSession, i64)> {
    let (payload, expires_at) = match cache.strategy() {
        CookieCacheStrategy::Compact => {
            let mut raw: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).ok()?).ok()?;
            normalize_dates(&mut raw);
            let payload = raw.get("session")?.as_object()?;
            let expires = raw.get("expiresAt")?.as_i64()?;
            let signature = URL_SAFE_NO_PAD
                .decode(raw.get("signature")?.as_str()?)
                .ok()?;
            let mut signed = payload.clone();
            let _ = signed.insert("expiresAt".into(), expires.into());
            let mut mac =
                Hmac::<Sha256>::new_from_slice(config.signing_secret().as_bytes()).ok()?;
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
                &DecodingKey::from_secret(config.signing_secret().as_bytes()),
                &validation,
            )
            .ok()?
            .claims;
            let expires =
                crate::utils::date::from_milliseconds(payload.get("exp")?.as_f64()? * 1000.0)?
                    .timestamp_millis();
            (payload, expires)
        }
        CookieCacheStrategy::Jwe => {
            let payload = Value::Object(crate::utils::jwe::decode(
                value,
                config.encryption_secret(),
                "better-auth-session",
            )?);
            let expires =
                crate::utils::date::from_milliseconds(payload.get("exp")?.as_f64()? * 1000.0)?
                    .timestamp_millis();
            (payload, expires)
        }
    };
    let mut payload = parse_payload(payload)?;
    // `active` is internal state and is intentionally absent from wire payloads.
    payload.data.session.active = true;
    Some((payload, expires_at))
}

pub(super) fn clear_existing(req: &AuthRequest, config: &AuthConfig) -> AuthResult<()> {
    clear_existing_cookies(
        req,
        &config.auth_cookie("session_data", Default::default()),
        None,
    )
}

pub(super) fn expire(req: &AuthRequest, config: &AuthConfig) -> AuthResult<()> {
    expire_cookie(
        req,
        &config.auth_cookie("session_data", Default::default()),
        None,
    )
}

pub(super) async fn write(
    req: &AuthRequest,
    data: &NativeSessionData,
    config: &AuthConfig,
    dont_remember: bool,
    signed: Option<String>,
    bind_account_user: bool,
    response_headers: Option<&crate::Headers>,
) -> AuthResult<()> {
    let Some(cache) = config
        .session
        .cookie_cache
        .as_ref()
        .filter(|cache| cache.enabled())
    else {
        return Ok(());
    };
    let value = match signed {
        Some(value) => value,
        None => encode(data, config, cache, dont_remember).await?,
    };
    let cookie = cache_cookie(config, cache, dont_remember);
    for cookie in create_chunked_cookies(req, &cookie, &value)? {
        req.append_response_header("Set-Cookie", cookie)?;
    }
    renew_account_cookie(
        req,
        data,
        config,
        cache,
        bind_account_user,
        response_headers,
    )
}

fn renew_account_cookie(
    req: &AuthRequest,
    data: &NativeSessionData,
    config: &AuthConfig,
    cache: &CookieCacheConfig,
    bind_account_user: bool,
    response_headers: Option<&crate::Headers>,
) -> AuthResult<()> {
    let name = related_cookie_name(config, "account_data");
    if !config.account.store_account_cookie()
        || req.has_response_cookie(&name)?
        || response_headers.is_some_and(|headers| headers.has_set_cookie(&name))
    {
        return Ok(());
    }
    let Some(account) = read(req, &name).and_then(|value| {
        crate::utils::jwe::decode(&value, config.encryption_secret(), "better-auth-account")
    }) else {
        return Ok(());
    };
    if bind_account_user
        && account.get("userId").and_then(Value::as_str) != data.user_field("id").as_str()
    {
        let cookie = config.auth_cookie("account_data", Default::default());
        expire_cookie(req, &cookie, None)?;
        return clear_existing_cookies(req, &cookie, None);
    }
    let cookie = config.auth_cookie(
        "account_data",
        CookieAttributes {
            max_age: Some(cache.max_age().as_seconds_f64()),
            ..Default::default()
        },
    );
    let max_age = cookie.attributes.max_age.unwrap_or(300.0);
    let value = crate::utils::jwe::encode(
        account,
        config.encryption_secret(),
        "better-auth-account",
        max_age,
    )?;
    for cookie in create_chunked_cookies(req, &cookie, &value)? {
        req.append_response_header("Set-Cookie", cookie)?;
    }
    Ok(())
}
