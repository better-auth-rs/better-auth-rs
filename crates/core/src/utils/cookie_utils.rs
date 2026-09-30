//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).
//!
//! Empty cross-subdomain domains fall back to the hostname from `base_url`.
//! [`AuthConfig::into_validated`] resolves this once for runtime configurations;
//! direct callers can use [`AuthConfig::validate`] to check their configuration.
//!
//! These helpers return strings and panic if a required cookie-domain fallback
//! is invalid. Validate configuration first to receive an [`AuthError`](crate::error::AuthError)
//! instead.

use crate::config::AuthConfig;
use cookie::{Cookie, SameSite as CookieSameSite};

/// Build a `Set-Cookie` header value for an arbitrary cookie using the auth
/// config's session cookie attributes for consistency.
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
pub fn create_cookie(name: &str, value: &str, max_age_seconds: i64, config: &AuthConfig) -> String {
    create_session_like_cookie(name, value, Some(max_age_seconds), config)
}

/// Build a `Set-Cookie` header value for a session token using the `cookie`
/// crate for correct formatting and escaping.
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
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
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
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
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
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

    serialize_cookie(cookie.build(), config)
}

/// Build a `Set-Cookie` header value that clears the session cookie.
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
pub fn create_clear_session_cookie(config: &AuthConfig) -> String {
    create_clear_cookie(&config.session.cookie_name, config)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, and emits no `Expires`.
///
/// # Panics
/// Panics if a required cross-subdomain cookie domain cannot be resolved.
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

    serialize_cookie(cookie.build(), config)
}

fn serialize_cookie(cookie: Cookie<'_>, config: &AuthConfig) -> String {
    let mut header = cookie.to_string();
    if cookie.name().starts_with("__Host-") {
        return header;
    }

    if let Some(cross_sub_domain) = &config.advanced.cross_sub_domain_cookies {
        // Runtime configs already have a resolved domain. Direct utility calls
        // also support an empty domain after immutable AuthConfig::validate.
        #[expect(
            clippy::expect_used,
            reason = "string-returning cookie helpers require a valid domain; AuthConfig::validate reports configuration errors"
        )]
        let fallback = config
            .resolve_cookie_domain_fallback()
            .expect("invalid cross-subdomain cookie configuration");
        let domain = fallback.as_deref().unwrap_or(&cross_sub_domain.domain);

        // TS/better-call serializes the configured domain without validation.
        // Preserve that behavior, including leading dots; Cookie::domain()
        // strips a leading dot during serialization.
        header.push_str("; Domain=");
        header.push_str(domain);
    }
    header
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_headers(config: &AuthConfig) -> [String; 6] {
        [
            create_session_cookie("token", config),
            create_session_cookie_with_max_age(Some("token"), None, config),
            create_cookie("better-auth.oauth_state", "state", 600, config),
            create_session_like_cookie("better-auth.dont_remember", "true", None, config),
            create_clear_session_cookie(config),
            create_clear_cookie("better-auth.session_data", config),
        ]
    }

    #[test]
    fn cookies_share_the_configured_domain_when_set_and_cleared() {
        for domain in ["example.com", ".example.com"] {
            let config = AuthConfig::new("test-secret-min-32-chars-1234567")
                .cross_sub_domain_cookies(domain);
            let expected = format!("Domain={domain}");

            for header in cookie_headers(&config) {
                let domains: Vec<_> = header
                    .split("; ")
                    .filter(|attribute| attribute.starts_with("Domain="))
                    .collect();
                assert_eq!(domains, [expected.as_str()], "{header}");
            }
        }
    }

    #[test]
    fn cookies_remain_host_only_without_cross_subdomain_config() {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://auth.example.com");

        for header in cookie_headers(&config) {
            assert!(!header.contains("Domain="), "{header}");
        }
    }

    #[test]
    fn cross_subdomain_cookies_preserve_session_and_deletion_lifetimes() {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .cross_sub_domain_cookies(".example.com");
        let session = create_session_cookie_with_max_age(Some("token"), None, &config);
        assert!(session.contains("Domain=.example.com"));
        assert!(!session.contains("Max-Age="));
        assert!(!session.contains("Expires="));

        let cleared = create_clear_session_cookie(&config);
        assert!(cleared.starts_with("better-auth.session_token=;"));
        assert!(cleared.contains("Domain=.example.com"));
        assert!(cleared.contains("Max-Age=0"));
        assert!(!cleared.contains("Expires="));
    }

    #[test]
    fn empty_cross_subdomain_domain_falls_back_to_base_url_hostname()
    -> Result<(), crate::error::AuthError> {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://auth.example.com:8443")
            .cross_sub_domain_cookies("")
            .into_validated()?;

        for header in cookie_headers(&config) {
            assert!(header.ends_with("; Domain=auth.example.com"), "{header}");
        }
        Ok(())
    }

    #[test]
    fn directly_validated_config_resolves_empty_cookie_domains()
    -> Result<(), crate::error::AuthError> {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://auth.example.com:8443/api/auth")
            .cross_sub_domain_cookies("");
        config.validate()?;

        for header in cookie_headers(&config) {
            assert!(header.ends_with("; Domain=auth.example.com"), "{header}");
        }
        Ok(())
    }

    #[test]
    #[should_panic(expected = "invalid cross-subdomain cookie configuration")]
    fn direct_cookie_creation_rejects_a_hostless_domain_fallback() {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("localhost:3000")
            .cross_sub_domain_cookies("");
        let _ = create_session_cookie("token", &config);
    }

    #[test]
    #[should_panic(expected = "invalid cross-subdomain cookie configuration")]
    fn direct_cookie_clearing_rejects_an_invalid_domain_fallback() {
        let config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("http://[")
            .cross_sub_domain_cookies("");
        let _ = create_clear_session_cookie(&config);
    }

    #[test]
    fn host_prefixed_cookies_omit_the_cross_subdomain_domain() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567")
            .cross_sub_domain_cookies(".example.com");
        config.session.cookie_name = "__Host-session_token".to_string();

        for header in [
            create_session_cookie("token", &config),
            create_clear_session_cookie(&config),
        ] {
            assert!(!header.contains("Domain="), "{header}");
        }
    }
}
