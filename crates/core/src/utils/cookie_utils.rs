//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

use crate::config::AuthConfig;
use cookie::{Cookie, SameSite as CookieSameSite};

/// Build a `Set-Cookie` header value for a session token using the `cookie`
/// crate for correct formatting and escaping.
pub fn create_session_cookie(token: &str, config: &AuthConfig) -> String {
    let session_config = &config.session;

    let expires_offset = cookie::time::OffsetDateTime::now_utc()
        + cookie::time::Duration::seconds(session_config.expires_in.num_seconds());

    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((&*session_config.cookie_name, token))
        .path("/")
        .expires(expires_offset)
        .secure(session_config.cookie_secure)
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

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
    let session_config = &config.session;

    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((&*session_config.cookie_name, ""))
        .path("/")
        .expires(cookie::time::OffsetDateTime::UNIX_EPOCH)
        .secure(session_config.cookie_secure)
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

    if matches!(
        session_config.cookie_same_site,
        crate::config::SameSite::None
    ) {
        cookie = cookie.secure(true);
    }

    cookie.build().to_string()
}

fn map_same_site(s: &crate::config::SameSite) -> CookieSameSite {
    match s {
        crate::config::SameSite::Strict => CookieSameSite::Strict,
        crate::config::SameSite::Lax => CookieSameSite::Lax,
        crate::config::SameSite::None => CookieSameSite::None,
    }
}
