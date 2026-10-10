//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

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
        .map(|token| sign_cookie_value(token, &config.secret));
    create_session_like_cookie(
        &config.session.cookie_name,
        signed.as_deref().unwrap_or(""),
        max_age_seconds,
        config,
    )
}

/// Build a `Set-Cookie` header value using the session cookie attributes for
/// an arbitrary cookie name.
pub fn create_session_like_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let session_config = &config.session;
    // SameSite=None requires the Secure attribute per the spec
    let secure = session_config.cookie_secure
        || matches!(
            session_config.cookie_same_site,
            crate::config::SameSite::None
        );
    serialize_cookie(
        name,
        value,
        max_age_seconds,
        session_config.cookie_http_only,
        secure,
        &session_config.cookie_same_site,
    )
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
    create_session_like_cookie(name, "", Some(0), config)
}

/// Serialize a cookie as better-call's `serializeCookie` does: `Max-Age`, `Path`,
/// `HttpOnly`, `Secure`, then `SameSite`, in that order. Better Auth sets no `Expires`
/// on these cookies; browsers apply `Max-Age`.
fn serialize_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    http_only: bool,
    secure: bool,
    same_site: &crate::config::SameSite,
) -> String {
    let mut cookie = format!("{name}={value}");
    if let Some(max_age) = max_age_seconds.filter(|max_age| *max_age >= 0) {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }
    cookie.push_str("; Path=/");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure || name.starts_with("__Secure-") || name.starts_with("__Host-") {
        cookie.push_str("; Secure");
    }
    cookie.push_str(match same_site {
        crate::config::SameSite::Strict => "; SameSite=Strict",
        crate::config::SameSite::Lax => "; SameSite=Lax",
        crate::config::SameSite::None => "; SameSite=None",
    });
    cookie
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

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream source: better-call src/cookies.ts :: `serializeCookie` writes
    // `Max-Age`, `Domain`, `Path`, `Expires`, `HttpOnly`, `Secure`, then `SameSite`;
    // Better Auth's session cookies pass no `expires`.
    #[test]
    fn cookies_follow_better_calls_attribute_order() {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        assert_eq!(
            create_cookie("better-auth.state", "abc", 300, &config),
            "better-auth.state=abc; Max-Age=300; Path=/; HttpOnly; SameSite=Lax"
        );
        config.session.cookie_secure = true;
        assert_eq!(
            create_clear_cookie("better-auth.state", &config),
            "better-auth.state=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
        );
    }
}
