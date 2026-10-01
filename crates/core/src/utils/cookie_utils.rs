//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

mod chunks;
pub use chunks::{
    clear_chunked_cookie, create_chunked_cookies, create_clear_chunked_cookies, get_chunked_cookie,
};

use crate::config::AuthConfig;
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
pub fn sign_cookie_value(value: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts every key length");
    mac.update(value.as_bytes());
    let signed = format!("{value}.{}", STANDARD.encode(mac.finalize().into_bytes()));
    utf8_percent_encode(&signed, COOKIE_COMPONENT).to_string()
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
    let session = &config.session;
    Cookie::build((session.cookie_name.clone(), String::new()))
        .path("/")
        .secure(
            session.cookie_secure
                || matches!(session.cookie_same_site, crate::config::SameSite::None),
        )
        .http_only(session.cookie_http_only)
        .same_site(map_same_site(&session.cookie_same_site))
        .build()
}

/// Build a `Set-Cookie` header value for an arbitrary cookie using the auth
/// config's session cookie attributes for consistency.
pub fn create_cookie(name: &str, value: &str, max_age_seconds: i64, config: &AuthConfig) -> String {
    create_session_like_cookie(name, value, Some(max_age_seconds), config)
}

/// Build a `Set-Cookie` header value for a session token using the `cookie`
/// crate for correct formatting and escaping.
pub fn create_session_cookie(token: &str, config: &AuthConfig) -> String {
    create_session_cookie_with_max_age(
        Some(token),
        Some(config.session.expires_in.num_seconds()),
        config,
    )
}

/// Build a `Set-Cookie` header value for a session token using the session
/// cookie attributes, optionally omitting `Max-Age` / `Expires` to create a
/// browser-session cookie.
pub fn create_session_cookie_with_max_age(
    token: Option<&str>,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let signed = token
        .filter(|token| !token.is_empty())
        .map(|token| sign_cookie_value(token, config.signing_secret()));
    create_session_like_cookie(
        &config.session.cookie_name,
        signed.as_deref().unwrap_or(""),
        max_age_seconds,
        config,
    )
}

/// Build session-token cookies and the explicit browser-session preference.
pub fn create_session_cookies(
    token: &str,
    dont_remember: bool,
    config: &AuthConfig,
) -> Vec<String> {
    let mut cookies = vec![create_session_cookie_with_max_age(
        Some(token),
        (!dont_remember).then_some(config.session.expires_in.num_seconds()),
        config,
    )];
    if dont_remember {
        cookies.push(create_session_like_cookie(
            &related_cookie_name(config, "dont_remember"),
            &sign_cookie_value("true", config.signing_secret()),
            None,
            config,
        ));
    }
    cookies
}

/// Build a `Set-Cookie` header value using the session cookie attributes for
/// an arbitrary cookie name.
pub fn create_session_like_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let mut cookie = session_cookie_template(config);
    cookie.set_name(name.to_owned());
    cookie.set_value(value.to_owned());
    if let Some(max_age_seconds) = max_age_seconds {
        let age = cookie::time::Duration::seconds(max_age_seconds);
        cookie.set_expires(cookie::time::OffsetDateTime::now_utc() + age);
        cookie.set_max_age(age);
    }
    cookie.to_string()
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn create_clear_session_cookie(config: &AuthConfig) -> String {
    create_clear_cookie(&config.session.cookie_name, config)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, and emits no `Expires`.
pub fn create_clear_cookie(name: &str, config: &AuthConfig) -> String {
    let session_config = &config.session;
    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((name, ""))
        .path("/")
        .max_age(cookie::time::Duration::seconds(0))
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

    if session_config.cookie_secure
        || matches!(
            session_config.cookie_same_site,
            crate::config::SameSite::None
        )
    {
        cookie = cookie.secure(true);
    }

    cookie.build().to_string()
}

/// Build a Better Auth related cookie name using the configured session cookie
/// prefix. For example, `better-auth.session_token` + `session_data` becomes
/// `better-auth.session_data`.
pub fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{}{}", prefix, suffix))
        .unwrap_or_else(|| format!("better-auth.{}", suffix))
}

fn map_same_site(s: &crate::config::SameSite) -> CookieSameSite {
    match s {
        crate::config::SameSite::Strict => CookieSameSite::Strict,
        crate::config::SameSite::Lax => CookieSameSite::Lax,
        crate::config::SameSite::None => CookieSameSite::None,
    }
}
