//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

use crate::config::AuthConfig;
use cookie::{Cookie, SameSite as CookieSameSite};

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
    create_session_like_cookie(
        &config.session.cookie_name,
        token.unwrap_or(""),
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
    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((name, value))
        .path("/")
        .secure(session_config.cookie_secure)
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

    if let Some(max_age_seconds) = max_age_seconds {
        let expires_offset = cookie::time::OffsetDateTime::now_utc()
            + cookie::time::Duration::seconds(max_age_seconds);
        cookie = cookie
            .expires(expires_offset)
            .max_age(cookie::time::Duration::seconds(max_age_seconds));
    }

    // SameSite=None requires the Secure attribute per the spec
    if matches!(
        session_config.cookie_same_site,
        crate::config::SameSite::None
    ) {
        cookie = cookie.secure(true);
    }

    cookie.build().to_string()
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
