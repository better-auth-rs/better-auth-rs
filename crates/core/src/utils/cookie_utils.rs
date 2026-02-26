//! Shared cookie helpers used across plugins.
//!
//! Centralises the `Set-Cookie` header construction so that each plugin does
//! not have to duplicate the same formatting logic.

use crate::adapters::DatabaseAdapter;
use crate::config::AuthConfig;
use crate::plugin::AuthContext;
use std::sync::Arc;

/// Build a `Set-Cookie` header value for a session token.
pub fn create_session_cookie<DB: DatabaseAdapter>(token: &str, ctx: &AuthContext<DB>) -> String {
    build_session_cookie_from_config(token, &ctx.config)
}

/// Build a `Set-Cookie` header that clears (expires) the session cookie.
pub fn create_clear_session_cookie<DB: DatabaseAdapter>(ctx: &AuthContext<DB>) -> String {
    let session_config = &ctx.config.session;
    let attrs = cookie_attributes(session_config);

    format!(
        "{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
        session_config.cookie_name, attrs
    )
}

/// Internal: shared cookie builder logic operating on an `AuthConfig`.
fn build_session_cookie_from_config(token: &str, config: &Arc<AuthConfig>) -> String {
    let session_config = &config.session;
    let attrs = cookie_attributes(session_config);

    let expires = chrono::Utc::now() + session_config.expires_in;
    let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

    format!(
        "{}={}; Path=/; Expires={}{}",
        session_config.cookie_name, token, expires_str, attrs
    )
}

/// Format the common "; Secure; HttpOnly; SameSite=…" suffix.
fn cookie_attributes(session_config: &crate::config::SessionConfig) -> String {
    let secure = if session_config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let http_only = if session_config.cookie_http_only {
        "; HttpOnly"
    } else {
        ""
    };

    format!(
        "{}{}; SameSite={}",
        secure, http_only, session_config.cookie_same_site
    )
}
