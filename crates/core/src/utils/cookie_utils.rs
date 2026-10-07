//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

mod chunks;
pub(crate) use chunks::clear_existing_cookies;
pub use chunks::{
    clear_chunked_cookie, create_chunked_cookies, create_clear_chunked_cookies, get_chunked_cookie,
};

use crate::{AuthError, AuthResult, config::AuthConfig, request_runtime::ResolvedCookie};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

const COOKIE_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');
const COOKIE_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
use cookie::{Cookie, SameSite as CookieSameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Sign a cookie value using the upstream HMAC-SHA256 format.
#[expect(clippy::expect_used, reason = "HMAC-SHA256 accepts every key length")]
pub fn sign_cookie_value_raw(value: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts every key length");
    mac.update(value.as_bytes());
    format!("{value}.{}", STANDARD.encode(mac.finalize().into_bytes()))
}

/// Sign and percent-encode a cookie value for an HTTP response.
pub fn sign_cookie_value(value: &str, secret: &str) -> String {
    encode_cookie_value(&sign_cookie_value_raw(value, secret))
}

/// Verify a signed cookie. Invalid or malformed signatures are unauthenticated.
pub fn verify_cookie_value(value: &str, secret: &str) -> Option<String> {
    let decoded = percent_decode_str(value).decode_utf8().ok()?;
    let (value, signature) = decoded.rsplit_once('.')?;
    let signature = COOKIE_BASE64.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(value.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(value.to_string())
}

/// Read a cookie by its exact name.
pub fn get_cookie(req: &crate::AuthRequest, name: &str) -> Option<String> {
    cookie::Cookie::split_parse(req.headers.get("cookie")?)
        .flatten()
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.value().to_string())
}

/// Encode a cookie value using the upstream `encodeURIComponent` character set.
pub fn encode_cookie_value(value: &str) -> String {
    utf8_percent_encode(value, COOKIE_COMPONENT).to_string()
}

/// Materialize session cookie attributes without a value or HTTP lifetime validation.
/// Date conversion errors propagate; the HTTP writer checks the 400-day limit.
pub fn session_cookie_template(config: &AuthConfig) -> AuthResult<Cookie<'static>> {
    resolved_template(&config.auth_cookie("session_token", Default::default()))
}

fn resolved_template(resolved: &ResolvedCookie) -> AuthResult<Cookie<'static>> {
    let attrs = &resolved.attributes;
    let mut cookie = Cookie::new(resolved.name.clone(), String::new());
    if let Some(value) = &attrs.path {
        cookie.set_path(value.clone());
    }
    if let Some(value) = &attrs.domain {
        cookie.set_domain(value.clone());
    }
    if let Some(value) = attrs.secure {
        cookie.set_secure(value);
    }
    cookie.set_partitioned(attrs.partitioned);
    if let Some(value) = attrs.http_only {
        cookie.set_http_only(value);
    }
    if let Some(value) = &attrs.same_site {
        cookie.set_same_site(map_same_site(value));
    }
    if let Some(value) = attrs.max_age.filter(|value| *value >= 0.0) {
        cookie.set_max_age(cookie::time::Duration::seconds(value.floor() as i64));
    }
    if let Some(value) = attrs.expires {
        let date = cookie::time::OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(value.timestamp_millis()) * 1_000_000,
        )
        .map_err(|error| AuthError::internal(format!("Converting cookie expiration: {error}")))?;
        cookie.set_expires(date);
    }
    if cookie.name().starts_with("__Secure-") || cookie.name().starts_with("__Host-") {
        cookie.set_secure(true);
    }
    if cookie.name().starts_with("__Host-") {
        cookie.set_path("/");
        cookie.unset_domain();
    }
    Ok(cookie)
}

/// Build a `Set-Cookie` header value for an arbitrary cookie using the auth
/// config's session cookie attributes for consistency.
/// The lifetime is measured in seconds and validated before fractional values are rounded.
pub fn create_cookie(
    name: &str,
    value: &str,
    max_age_seconds: f64,
    config: &AuthConfig,
) -> AuthResult<String> {
    create_session_like_cookie(name, value, Some(max_age_seconds), config)
}

/// Build a signed session-token header with the upstream attribute order.
pub fn create_session_cookie(token: &str, config: &AuthConfig) -> AuthResult<String> {
    create_session_cookie_with_max_age(
        Some(token),
        Some(config.session.expires_in().as_seconds_f64()),
        config,
    )
}

/// Build a `Set-Cookie` header value for a session token using the session
/// cookie attributes, optionally omitting `Max-Age` to create a
/// browser-session cookie.
/// A supplied lifetime uses seconds, including fractional values.
pub fn create_session_cookie_with_max_age(
    token: Option<&str>,
    max_age_seconds: Option<f64>,
    config: &AuthConfig,
) -> AuthResult<String> {
    let signed = token
        .filter(|token| !token.is_empty())
        .map(|token| sign_cookie_value(token, config.signing_secret()));
    let mut resolved = config.auth_cookie("session_token", Default::default());
    resolved.attributes.max_age = max_age_seconds;
    render_cookie(&signed.unwrap_or_default(), &resolved)
}

/// Build session-token cookies and the explicit browser-session preference.
pub fn create_session_cookies(
    token: &str,
    dont_remember: bool,
    config: &AuthConfig,
) -> AuthResult<Vec<String>> {
    session_cookie_headers(token, dont_remember, config).collect()
}

pub(crate) fn session_cookie_headers<'a>(
    token: &'a str,
    dont_remember: bool,
    config: &'a AuthConfig,
) -> impl Iterator<Item = AuthResult<String>> + 'a {
    // Build each header only when requested so a later failure retains earlier writes.
    std::iter::once_with(move || {
        create_session_cookie_with_max_age(
            Some(token),
            (!dont_remember).then_some(config.session.expires_in().as_seconds_f64()),
            config,
        )
    })
    .chain(dont_remember.then_some(()).into_iter().map(move |()| {
        create_session_like_cookie(
            &related_cookie_name(config, "dont_remember"),
            &sign_cookie_value("true", config.signing_secret()),
            None,
            config,
        )
    }))
}

/// Build a `Set-Cookie` header value using the session cookie attributes for
/// an arbitrary cookie name.
/// A supplied lifetime uses seconds, including fractional values.
pub fn create_session_like_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<f64>,
    config: &AuthConfig,
) -> AuthResult<String> {
    let resolved = template_for_name(name, max_age_seconds, config);
    render_cookie(value, &resolved)
}

/// Validate and render a cookie from its resolved attributes and encoded value.
/// Lifetime limits use the original precision before HTTP formatting.
pub fn render_cookie(value: &str, resolved: &ResolvedCookie) -> AuthResult<String> {
    validate_lifetime(&resolved.attributes, chrono::Utc::now().timestamp_millis())?;
    let cookie = resolved_template(resolved)?;
    let mut rendered = format!("{}={value}", cookie.name());
    if let Some(age) = cookie.max_age() {
        rendered.push_str(&format!("; Max-Age={}", age.whole_seconds()));
    }
    // cookie::Cookie strips a leading dot from Domain; Better Call preserves it on the wire.
    let domain = (!cookie.name().starts_with("__Host-"))
        .then_some(resolved.attributes.domain.as_deref())
        .flatten()
        .filter(|domain| !domain.is_empty());
    if let Some(domain) = domain {
        rendered.push_str("; Domain=");
        rendered.push_str(domain);
    }
    if let Some(path) = cookie.path() {
        rendered.push_str("; Path=");
        rendered.push_str(path);
    }
    if let Some(expires) = cookie.expires_datetime() {
        let format = cookie::time::format_description::parse_borrowed::<2>(
            "; Expires=[weekday repr:short], [day] [month repr:short] [year padding:none] [hour]:[minute]:[second] GMT",
        )
        .map_err(|error| AuthError::internal(format!("Parsing cookie expiration format: {error}")))?;
        let expires = expires
            .to_offset(cookie::time::UtcOffset::UTC)
            .format(&format)
            .map_err(|error| {
                AuthError::internal(format!("Formatting cookie expiration: {error}"))
            })?;
        rendered.push_str(&expires);
    }
    if cookie.http_only() == Some(true) {
        rendered.push_str("; HttpOnly");
    }
    // Preserve the cookie crate's Secure policy while using Better Call's attribute order.
    if cookie.secure() == Some(true)
        || cookie.partitioned() == Some(true)
        || cookie.secure().is_none() && cookie.same_site() == Some(CookieSameSite::None)
    {
        rendered.push_str("; Secure");
    }
    if let Some(same_site) = cookie.same_site() {
        rendered.push_str(&format!("; SameSite={same_site}"));
    }
    if cookie.partitioned() == Some(true) {
        rendered.push_str("; Partitioned");
    }
    Ok(rendered)
}

fn validate_lifetime(attributes: &crate::CookieAttributes, now_millis: i64) -> AuthResult<()> {
    let max_age = attributes.max_age.filter(|age| *age >= 0.0);
    if max_age.is_some_and(|age| age > 34_560_000.0) {
        return Err(AuthError::internal(
            "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.",
        ));
    }
    if attributes
        .expires
        .is_some_and(|expires| expires.timestamp_millis() - now_millis > 34_560_000_000)
    {
        return Err(AuthError::internal(
            "Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.",
        ));
    }
    Ok(())
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn create_clear_session_cookie(config: &AuthConfig) -> AuthResult<String> {
    let mut resolved = config.auth_cookie("session_token", Default::default());
    resolved.attributes.max_age = Some(0.0);
    render_cookie("", &resolved)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, including an explicit `Expires`.
pub fn create_clear_cookie(name: &str, config: &AuthConfig) -> AuthResult<String> {
    let mut resolved = template_for_name(name, None, config);
    resolved.attributes.max_age = Some(0.0);
    render_cookie("", &resolved)
}

/// Clear session cookies, publishing each header before attempting the next cookie.
pub fn delete_session_cookies(
    req: &crate::AuthRequest,
    config: &AuthConfig,
    skip_dont_remember: bool,
    mut response_headers: Option<&mut crate::Headers>,
) -> AuthResult<()> {
    for logical in ["session_token", "session_data"] {
        expire_cookie(
            req,
            &config.auth_cookie(logical, Default::default()),
            response_headers.as_deref_mut(),
        )?;
    }
    if config.account.store_account_cookie() {
        let cookie = config.auth_cookie("account_data", Default::default());
        expire_cookie(req, &cookie, response_headers.as_deref_mut())?;
        chunks::clear_existing_cookies(req, &cookie, response_headers.as_deref_mut())?;
    }
    if config.account.store_state_strategy() == crate::config::OAuthStateStrategy::Cookie {
        expire_cookie(
            req,
            &config.auth_cookie("oauth_state", Default::default()),
            response_headers.as_deref_mut(),
        )?;
    }
    // Existing entries append after the base expiration, including an incoming base cookie.
    // Removing the family here would discard that earlier expiration header.
    chunks::clear_existing_cookies(
        req,
        &config.auth_cookie("session_data", Default::default()),
        response_headers.as_deref_mut(),
    )?;
    if !skip_dont_remember {
        expire_cookie(
            req,
            &config.auth_cookie("dont_remember", Default::default()),
            response_headers,
        )?;
    }
    Ok(())
}

pub(crate) fn expire_cookie(
    req: &crate::AuthRequest,
    cookie: &ResolvedCookie,
    mut response_headers: Option<&mut crate::Headers>,
) -> AuthResult<()> {
    remove_set_cookie_entries(req, response_headers.as_deref_mut(), &cookie.name)?;
    let mut cookie = cookie.clone();
    cookie.attributes.max_age = Some(0.0);
    let header = render_cookie("", &cookie)?;
    if let Some(headers) = response_headers {
        headers.append("Set-Cookie", header);
    } else {
        req.append_response_header("Set-Cookie", header)?;
    }
    Ok(())
}

/// Remove a cookie and its chunks from both response scopes before explicit expiration.
pub fn remove_set_cookie_entries(
    req: &crate::AuthRequest,
    response_headers: Option<&mut crate::Headers>,
    name: &str,
) -> crate::AuthResult<()> {
    req.remove_response_cookie(name)?;
    if let Some(headers) = response_headers {
        headers.remove_set_cookie(name);
    }
    Ok(())
}

fn template_for_name(name: &str, max_age: Option<f64>, config: &AuthConfig) -> ResolvedCookie {
    let settings = config.cookie_settings();
    let logical = settings.logical_name(name).unwrap_or("session_token");
    let mut cookie = settings.get(
        logical,
        crate::CookieAttributes {
            max_age,
            ..Default::default()
        },
    );
    cookie.name = name.to_owned();
    cookie
}

/// Build a Better Auth related cookie name using the configured session cookie
/// prefix. For example, `better-auth.session_token` + `session_data` becomes
/// `better-auth.session_data`.
pub fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config.auth_cookie(suffix, Default::default()).name
}

fn map_same_site(s: &crate::config::SameSite) -> CookieSameSite {
    match s {
        crate::config::SameSite::Strict => CookieSameSite::Strict,
        crate::config::SameSite::Lax => CookieSameSite::Lax,
        crate::config::SameSite::None => CookieSameSite::None,
    }
}

#[cfg(test)]
#[path = "cookie_utils/expires_tests.rs"]
mod expires_tests;

#[cfg(test)]
#[path = "cookie_utils/cache_cleanup_tests.rs"]
mod cache_cleanup_tests;
