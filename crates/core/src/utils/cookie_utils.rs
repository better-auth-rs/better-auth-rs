//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

mod chunks;
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

/// Current session cookie attributes, without a value or an expiration override.
pub fn session_cookie_template(config: &AuthConfig) -> Cookie<'static> {
    resolved_template(&config.auth_cookie("session_token", Default::default()))
}

fn resolved_template(resolved: &ResolvedCookie) -> Cookie<'static> {
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
    if cookie.name().starts_with("__Secure-") || cookie.name().starts_with("__Host-") {
        cookie.set_secure(true);
    }
    if cookie.name().starts_with("__Host-") {
        cookie.set_path("/");
        cookie.unset_domain();
    }
    cookie
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

/// Build a `Set-Cookie` header value for a session token using the `cookie`
/// crate for correct formatting and escaping.
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
    serialize_cookie(
        resolved_template(&resolved),
        &signed.unwrap_or_default(),
        &resolved,
    )
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
    serialize_cookie(resolved_template(&resolved), value, &resolved)
}

fn serialize_cookie(
    mut cookie: Cookie<'static>,
    value: &str,
    resolved: &ResolvedCookie,
) -> AuthResult<String> {
    let max_age = resolved.attributes.max_age.filter(|age| *age >= 0.0);
    if max_age.is_some_and(|age| age > 34_560_000.0) {
        return Err(AuthError::internal(
            "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.",
        ));
    }
    cookie.set_max_age(max_age.map(|age| cookie::time::Duration::seconds(age.floor() as i64)));
    cookie.set_value(value.to_owned());
    Ok(render_cookie(cookie, resolved))
}

/// Render cookie attributes while preserving the configured Domain spelling.
pub fn render_cookie(mut cookie: Cookie<'static>, resolved: &ResolvedCookie) -> String {
    // cookie::Cookie strips a leading dot from Domain; Better Call preserves it on the wire.
    let domain = (!cookie.name().starts_with("__Host-"))
        .then_some(resolved.attributes.domain.as_deref())
        .flatten()
        .filter(|domain| !domain.is_empty());
    cookie.unset_domain();
    let mut rendered = cookie.to_string();
    if let Some(domain) = domain {
        rendered.push_str("; Domain=");
        rendered.push_str(domain);
    }
    rendered
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn create_clear_session_cookie(config: &AuthConfig) -> String {
    let resolved = config.auth_cookie("session_token", Default::default());
    let mut cookie = resolved_template(&resolved);
    cookie.set_max_age(cookie::time::Duration::ZERO);
    cookie.unset_expires();
    render_cookie(cookie, &resolved)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, and emits no `Expires`.
pub fn create_clear_cookie(name: &str, config: &AuthConfig) -> String {
    let resolved = template_for_name(name, None, config);
    let mut cookie = resolved_template(&resolved);
    cookie.set_max_age(cookie::time::Duration::seconds(0));
    cookie.unset_expires();
    render_cookie(cookie, &resolved)
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
