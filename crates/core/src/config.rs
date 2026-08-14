use crate::email::EmailProvider;
use crate::error::AuthError;
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;

/// Well-known core route paths.
///
/// These constants are the single source of truth for route paths used by both
/// the core request dispatcher (`handle_core_request`) and framework-specific
/// routers (e.g. Axum) so that path strings are never duplicated.
pub mod core_paths {
    pub const OK: &str = "/ok";
    pub const ERROR: &str = "/error";
    pub const HEALTH: &str = "/health";
    pub const OPENAPI_SPEC: &str = "/__test/openapi.json";
    pub const UPDATE_USER: &str = "/update-user";
    pub const DELETE_USER: &str = "/delete-user";
    pub const CHANGE_EMAIL: &str = "/change-email";
    pub const DELETE_USER_CALLBACK: &str = "/delete-user/callback";

    fn valid_error_code(input: &str) -> bool {
        !input.is_empty()
            && input
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '\'')
    }

    fn is_preserved_entity(input: &str) -> bool {
        input.starts_with("amp;")
            || input.starts_with("lt;")
            || input.starts_with("gt;")
            || input.starts_with("quot;")
            || input.starts_with("#39;")
            || input.strip_prefix("#x").is_some_and(|hex| {
                let Some(hex) = hex.strip_suffix(';') else {
                    return false;
                };
                !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
            })
            || input.strip_prefix('#').is_some_and(|digits| {
                let Some(digits) = digits.strip_suffix(';') else {
                    return false;
                };
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            })
    }

    fn sanitize_html(input: &str) -> String {
        let mut out = String::with_capacity(input.len());

        for (idx, ch) in input.char_indices() {
            match ch {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                '&' => {
                    let rest = &input[idx + ch.len_utf8()..];
                    if is_preserved_entity(rest) {
                        out.push('&');
                    } else {
                        out.push_str("&amp;");
                    }
                }
                _ => out.push(ch),
            }
        }

        out
    }

    fn default_error_description(code: &str) -> String {
        format!(
            "We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find more information about the error <a href='https://better-auth.com/docs/reference/errors/{code}' target='_blank' rel=\"noopener noreferrer\" style='color: var(--foreground); text-decoration: underline;'>here</a>."
        )
    }

    /// Build the HTML error page returned by `GET /error`.
    ///
    /// Matches the current TS better-auth error page renderer.
    pub fn error_page_html(error_code: &str) -> String {
        error_page_html_with_description(error_code, None)
    }

    /// Build the HTML error page returned by `GET /error`, optionally
    /// overriding the default description text.
    pub fn error_page_html_with_description(
        error_code: &str,
        error_description: Option<&str>,
    ) -> String {
        let safe_code = if valid_error_code(error_code) {
            error_code
        } else {
            "UNKNOWN"
        };
        let description = error_description
            .map(sanitize_html)
            .unwrap_or_else(|| default_error_description(safe_code));
        let ask_ai_query = format!("What%20does%20the%20error%20code%20{safe_code}%20mean%3F");

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Error</title>
    <style>
      * {{
        box-sizing: border-box;
      }}
      body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: var(--background);
        color: var(--foreground);
        margin: 0;
      }}
      :root,
      :host {{
        --spacing: 0.25rem;
        --container-md: 28rem;
        --text-sm: 0.875rem;
        --text-sm--line-height: calc(1.25 / 0.875);
        --text-2xl: 1.5rem;
        --text-2xl--line-height: calc(2 / 1.5);
        --text-4xl: 2.25rem;
        --text-4xl--line-height: calc(2.5 / 2.25);
        --text-6xl: 3rem;
        --text-6xl--line-height: 1;
        --font-weight-medium: 500;
        --font-weight-semibold: 600;
        --font-weight-bold: 700;
        --default-transition-duration: 150ms;
        --default-transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
        --radius: 0.625rem;
        --default-mono-font-family: var(--font-geist-mono);
        --primary: black;
        --primary-foreground: white;
        --background: white;
        --foreground: oklch(0.271 0 0);
        --border: oklch(0.89 0 0);
        --destructive: oklch(0.55 0.15 25.723);
        --muted-foreground: oklch(0.545 0 0);
        --corner-border: #404040;
      }}

      button, .btn {{
        cursor: pointer;
        background: none;
        border: none;
        color: inherit;
        font: inherit;
        transition: all var(--default-transition-duration)
          var(--default-transition-timing-function);
      }}
      button:hover, .btn:hover {{
        opacity: 0.8;
      }}

      @media (prefers-color-scheme: dark) {{
        :root,
        :host {{
          --primary: white;
          --primary-foreground: black;
          --background: oklch(0.15 0 0);
          --foreground: oklch(0.98 0 0);
          --border: oklch(0.27 0 0);
          --destructive: oklch(0.65 0.15 25.723);
          --muted-foreground: oklch(0.65 0 0);
          --corner-border: #a0a0a0;
        }}
      }}
      @media (max-width: 640px) {{
        :root, :host {{
          --text-6xl: 2.5rem;
          --text-2xl: 1.25rem;
          --text-sm: 0.8125rem;
        }}
      }}
      @media (max-width: 480px) {{
        :root, :host {{
          --text-6xl: 2rem;
          --text-2xl: 1.125rem;
        }}
      }}
    </style>
  </head>
  <body style="width: 100vw; min-height: 100vh; overflow-x: hidden; overflow-y: auto;">
    <div
        style="
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
            position: relative;
            width: 100%;
            min-height: 100vh;
            padding: 1rem;
        "
        >

      <div
        style="
          position: absolute;
          inset: 0;
          background-image: linear-gradient(to right, var(--border) 1px, transparent 1px),
            linear-gradient(to bottom, var(--border) 1px, transparent 1px);
          background-size: 40px 40px;
          opacity: 0.6;
          pointer-events: none;
          width: 100vw;
          height: 100vh;
        "
      ></div>
      <div
        style="
          position: absolute;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: var(--background);
          mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          -webkit-mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          pointer-events: none;
        "
      ></div>


<div
  style="
    position: relative;
    z-index: 10;
    border: 2px solid var(--border);
    background: var(--background);
    padding: 1.5rem;
    max-width: 42rem;
    width: 100%;
  "
>
    
        <!-- Corner decorations -->
        <div
          style="
            position: absolute;
            top: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            top: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>
  
        <div
          style="
            position: absolute;
            bottom: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>

        <div style="text-align: center; margin-bottom: 1.5rem;">
          <div style="margin-bottom: 1.5rem;">
            <div
              style="
                display: inline-block;
                border: 2px solid var(--destructive);
                padding: 0.375rem 1rem;
              "
            >
              <h1
                style="
                  font-size: var(--text-6xl);
                  font-weight: var(--font-weight-semibold);
                  color: var(--foreground);
                  letter-spacing: -0.02em;
                  margin: 0;
                "
              >
                ERROR
              </h1>
            </div>
            <div
              style="
                height: 2px;
                background-color: var(--border);
                width: calc(100% + 3rem);
                margin-left: -1.5rem;
                margin-top: 1.5rem;
              "
            ></div>
          </div>

          <h2
            style="
              font-size: var(--text-2xl);
              font-weight: var(--font-weight-semibold);
              color: var(--foreground);
              margin: 0 0 1rem;
            "
          >
            Something went wrong
          </h2>

          <div
            style="
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                border: 2px solid var(--border);
                background-color: var(--muted);
                padding: 0.375rem 0.75rem;
                margin: 0 0 1rem;
                flex-wrap: wrap;
                justify-content: center;
            "
            >
            <span
                style="
                font-size: 0.75rem;
                color: var(--muted-foreground);
                font-weight: var(--font-weight-semibold);
                "
            >
                CODE:
            </span>
            <span
                style="
                font-size: var(--text-sm);
                font-family: var(--default-mono-font-family, monospace);
                color: var(--foreground);
                word-break: break-all;
                "
            >
                {safe_code}
            </span>
            </div>

          <p
            style="
              color: var(--muted-foreground);
              max-width: 28rem;
              margin: 0 auto;
              font-size: var(--text-sm);
              line-height: 1.5;
              text-wrap: pretty;
            "
          >
            {description}
          </p>
        </div>

        <div
          style="
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
          "
        >
          <a
            href="/"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: var(--primary);
                color: var(--primary-foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Go Home
            </div>
          </a>
          <a
            href="https://better-auth.com/docs/reference/errors/{safe_code}?askai={ask_ai_query}"
            target="_blank"
            rel="noopener noreferrer"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: transparent;
                color: var(--foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Ask AI
            </div>
          </a>
        </div>
      </div>
    </div>
  </body>
</html>"#
        )
    }
}

/// Main configuration for BetterAuth
#[derive(Clone)]
pub struct AuthConfig {
    /// Secret key for signing tokens and sessions
    pub secret: String,

    /// Application name, used for cookie prefixes, email templates, etc.
    ///
    /// Defaults to `"Better Auth"`.
    pub app_name: String,

    /// Base URL for the authentication service (e.g. `"http://localhost:3000"`).
    pub base_url: String,

    /// Base path where the auth routes are mounted.
    ///
    /// All routes handled by BetterAuth will be prefixed with this path.
    /// For example, with the default `"/api/auth"`, the sign-in route becomes
    /// `"/api/auth/sign-in/email"`.
    ///
    /// Defaults to `"/api/auth"`.
    pub base_path: String,

    /// Origins that are trusted for CSRF and other cross-origin checks.
    ///
    /// Supports glob patterns (e.g. `"https://*.example.com"`).
    /// These are shared across all middleware that needs origin validation
    /// (CSRF, CORS, etc.).
    pub trusted_origins: Vec<String>,

    /// Paths that should be disabled (skipped) by the router.
    ///
    /// Any request whose path matches an entry in this list will receive
    /// a 404 response, even if a handler is registered for it.
    pub disabled_paths: Vec<String>,
    /// Session configuration
    pub session: SessionConfig,

    /// JWT configuration
    pub jwt: JwtConfig,

    /// Password configuration
    pub password: PasswordConfig,

    /// Account configuration (linking, token encryption, etc.)
    pub account: AccountConfig,

    /// Email provider for sending emails (verification, password reset, etc.)
    pub email_provider: Option<Arc<dyn EmailProvider>>,

    /// Advanced configuration options
    pub advanced: AdvancedConfig,
}

/// Account-level configuration: linking, token encryption, sign-in behavior.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// Update OAuth tokens on every sign-in (default: true)
    pub update_account_on_sign_in: bool,
    /// Account linking settings
    pub account_linking: AccountLinkingConfig,
    /// Encrypt OAuth tokens at rest (default: false)
    pub encrypt_oauth_tokens: bool,
    /// Store account data in an account cookie for OAuth-backed access token flows.
    pub store_account_cookie: bool,
    /// Where to persist OAuth state during the authorization flow.
    pub store_state_strategy: OAuthStateStrategy,
    /// Skip state-cookie verification during callback processing.
    ///
    /// This is security-sensitive and should stay disabled in normal use.
    pub skip_state_cookie_check: bool,
}

/// Settings that control how OAuth accounts are linked to existing users.
#[derive(Debug, Clone)]
pub struct AccountLinkingConfig {
    /// Enable account linking (default: true)
    pub enabled: bool,
    /// Trusted providers that can auto-link (default: empty = all trusted)
    pub trusted_providers: Vec<String>,
    /// Allow linking accounts with different emails (default: false) - SECURITY WARNING
    pub allow_different_emails: bool,
    /// Allow unlinking all accounts (default: false)
    pub allow_unlinking_all: bool,
    /// Disable implicit linking during sign-in; only explicit link-social may link.
    pub disable_implicit_linking: bool,
    /// Update user info when a new account is linked (default: false)
    pub update_user_info_on_link: bool,
}

/// Strategy for persisting OAuth state between the sign-in and callback steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OAuthStateStrategy {
    /// Persist state in an encrypted cookie.
    #[default]
    Cookie,
    /// Persist state in the verification store plus a signed state cookie.
    Database,
}

/// Session-specific configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session expiration duration
    pub expires_in: Duration,

    /// How often to refresh the session expiry (as a Duration).
    ///
    /// When set, session expiry is only updated if the session is older than
    /// this duration since the last update. When `None`, every request
    /// refreshes the session (equivalent to the old `update_age: true`).
    pub update_age: Option<Duration>,

    /// If `true`, sessions are never automatically refreshed on access.
    pub disable_session_refresh: bool,

    /// Session freshness window. A session younger than this is considered
    /// "fresh" (useful for step-up auth or sensitive operations).
    pub fresh_age: Option<Duration>,

    /// Cookie name for session token
    pub cookie_name: String,

    /// Cookie settings
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,

    /// Optional cookie-based session cache to avoid DB lookups.
    ///
    /// When enabled, session data is cached in a signed/encrypted cookie.
    /// `SessionManager` checks the cookie cache before hitting the database.
    pub cookie_cache: Option<CookieCacheConfig>,
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// JWT expiration duration
    pub expires_in: Duration,

    /// JWT algorithm
    pub algorithm: String,

    /// Issuer claim
    pub issuer: Option<String>,

    /// Audience claim
    pub audience: Option<String>,
}

/// Password hashing configuration
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Minimum password length
    pub min_length: usize,

    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special: bool,

    /// Argon2 configuration
    pub argon2_config: Argon2Config,
}

/// Argon2 hashing configuration
#[derive(Debug, Clone)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// Configuration for cookie-based session caching.
///
/// When enabled, session data is stored in a signed or encrypted cookie so that
/// subsequent requests can skip the database lookup.
#[derive(Debug, Clone)]
pub struct CookieCacheConfig {
    /// Whether the cookie cache is active.
    pub enabled: bool,

    /// Maximum age of the cached cookie before a fresh DB lookup is required.
    ///
    /// Default: 5 minutes.
    pub max_age: Duration,

    /// Strategy used to protect the cached cookie value.
    pub strategy: CookieCacheStrategy,
}

/// Strategy for signing / encrypting the cookie cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    /// Base64url-encoded payload + HMAC-SHA256 signature.
    Compact,
    /// Standard JWT with HMAC signing.
    Jwt,
    /// JWE with AES-256-GCM encryption.
    Jwe,
}

impl Default for CookieCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: Duration::minutes(5),
            strategy: CookieCacheStrategy::Compact,
        }
    }
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            update_account_on_sign_in: true,
            account_linking: AccountLinkingConfig::default(),
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            store_state_strategy: OAuthStateStrategy::Database,
            skip_state_cookie_check: false,
        }
    }
}

impl Default for AccountLinkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: Vec::new(),
            allow_different_emails: false,
            allow_unlinking_all: false,
            disable_implicit_linking: false,
            update_user_info_on_link: false,
        }
    }
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => f.write_str("Strict"),
            SameSite::Lax => f.write_str("Lax"),
            SameSite::None => f.write_str("None"),
        }
    }
}

// ── Advanced configuration ──────────────────────────────────────────────

/// Advanced configuration options (mirrors TS `advanced` block).
#[derive(Debug, Clone, Default)]
pub struct AdvancedConfig {
    /// IP address extraction configuration.
    pub ip_address: IpAddressConfig,

    /// If `true`, the CSRF-check middleware is disabled.
    pub disable_csrf_check: bool,

    /// If `true`, callback / redirect target origin validation is skipped.
    ///
    /// This mirrors Better Auth TS `advanced.disableOriginCheck`.
    /// It does **not** disable the request-origin CSRF checks.
    pub disable_origin_check: bool,

    /// Cross-subdomain cookie sharing configuration.
    pub cross_sub_domain_cookies: Option<CrossSubDomainConfig>,

    /// Per-cookie-name overrides (name, attributes, prefix).
    ///
    /// Keys are the *logical* cookie names (e.g. `"session_token"`,
    /// `"csrf_token"`). Values specify the attributes to override.
    pub cookies: HashMap<String, CookieOverride>,

    /// Default cookie attributes applied to *every* cookie the library sets
    /// (individual overrides in `cookies` take precedence).
    pub default_cookie_attributes: CookieAttributes,

    /// Optional prefix prepended to every cookie name (e.g. `"myapp"` →
    /// `"myapp.session_token"`).
    pub cookie_prefix: Option<String>,

    /// Database-related advanced options.
    pub database: AdvancedDatabaseConfig,

    /// List of header names the framework trusts for extracting the
    /// client's real IP when behind a proxy (e.g. `X-Forwarded-For`).
    pub trusted_proxy_headers: Vec<String>,
}

/// IP-address extraction configuration.
#[derive(Debug, Clone)]
pub struct IpAddressConfig {
    /// Ordered list of headers to check for the client IP.
    /// Defaults to `["x-forwarded-for", "x-real-ip"]`.
    pub headers: Vec<String>,

    /// If `true`, IP tracking is entirely disabled (no IP stored in sessions).
    pub disable_ip_tracking: bool,
}

/// Configuration for sharing cookies across sub-domains.
#[derive(Debug, Clone)]
pub struct CrossSubDomainConfig {
    /// The parent domain (e.g. `".example.com"`).
    pub domain: String,
}

/// Overridable cookie attributes.
#[derive(Debug, Clone, Default)]
pub struct CookieAttributes {
    /// Override `Secure` flag.
    pub secure: Option<bool>,
    /// Override `HttpOnly` flag.
    pub http_only: Option<bool>,
    /// Override `SameSite` policy.
    pub same_site: Option<SameSite>,
    /// Override `Path`.
    pub path: Option<String>,
    /// Override `Max-Age` (seconds).
    pub max_age: Option<i64>,
    /// Override cookie `Domain`.
    pub domain: Option<String>,
}

/// Per-cookie override entry.
#[derive(Debug, Clone, Default)]
pub struct CookieOverride {
    /// Custom name to use instead of the logical name.
    pub name: Option<String>,
    /// Attribute overrides for this cookie.
    pub attributes: CookieAttributes,
}

/// Database-related advanced options.
#[derive(Debug, Clone)]
pub struct AdvancedDatabaseConfig {
    /// Default `LIMIT` for "find many" queries.
    pub default_find_many_limit: usize,

    /// If `true`, auto-generated IDs will be numeric (auto-increment style)
    /// rather than UUIDs.
    pub use_number_id: bool,
}
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            app_name: "Better Auth".to_string(),
            base_url: "http://localhost:3000".to_string(),
            base_path: "/api/auth".to_string(),
            trusted_origins: Vec::new(),
            disabled_paths: Vec::new(),
            session: SessionConfig::default(),
            jwt: JwtConfig::default(),
            password: PasswordConfig::default(),
            account: AccountConfig::default(),
            email_provider: None,
            advanced: AdvancedConfig::default(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::hours(24 * 7),   // 7 days
            update_age: Some(Duration::hours(24)), // refresh once per day
            disable_session_refresh: false,
            fresh_age: None,
            cookie_name: "better-auth.session_token".to_string(),
            // Secure flag is derived from base_url scheme (HTTPS → true).
            // Default base_url is http://localhost:3000, so default is false.
            cookie_secure: false,
            cookie_http_only: true,
            cookie_same_site: SameSite::Lax,
            cookie_cache: None,
        }
    }
}

impl Default for IpAddressConfig {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".to_string(), "x-real-ip".to_string()],
            disable_ip_tracking: false,
        }
    }
}

impl Default for AdvancedDatabaseConfig {
    fn default() -> Self {
        Self {
            default_find_many_limit: 100,
            use_number_id: false,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::hours(24), // 1 day
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
        }
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_numbers: false,
            require_special: false,
            argon2_config: Argon2Config::default(),
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 4096, // 4MB
            time_cost: 3,      // 3 iterations
            parallelism: 1,    // 1 thread
        }
    }
}

impl AuthConfig {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Set the application name.
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Set the base URL (e.g. `"https://myapp.com"`).
    ///
    /// Also updates `session.cookie_secure` to match the URL scheme:
    /// HTTPS URLs set `Secure=true`, HTTP URLs set `Secure=false`.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self.session.cookie_secure = self.base_url.starts_with("https://");
        self
    }

    pub fn account(mut self, account: AccountConfig) -> Self {
        self.account = account;
        self
    }

    /// Set the base path where auth routes are mounted.
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    /// Add a trusted origin. Supports glob patterns (e.g. `"https://*.example.com"`).
    pub fn trusted_origin(mut self, origin: impl Into<String>) -> Self {
        self.trusted_origins.push(origin.into());
        self
    }

    /// Set all trusted origins at once.
    pub fn trusted_origins(mut self, origins: Vec<String>) -> Self {
        self.trusted_origins = origins;
        self
    }

    /// Add a path to the disabled paths list.
    pub fn disabled_path(mut self, path: impl Into<String>) -> Self {
        self.disabled_paths.push(path.into());
        self
    }

    /// Set all disabled paths at once.
    pub fn disabled_paths(mut self, paths: Vec<String>) -> Self {
        self.disabled_paths = paths;
        self
    }

    /// Set the session expiration duration.
    pub fn session_expires_in(mut self, duration: Duration) -> Self {
        self.session.expires_in = duration;
        self
    }

    pub fn session_update_age(mut self, duration: Duration) -> Self {
        self.session.update_age = Some(duration);
        self
    }

    pub fn disable_session_refresh(mut self, disabled: bool) -> Self {
        self.session.disable_session_refresh = disabled;
        self
    }

    pub fn session_fresh_age(mut self, duration: Duration) -> Self {
        self.session.fresh_age = Some(duration);
        self
    }

    /// Set the cookie cache configuration for sessions.
    pub fn session_cookie_cache(mut self, config: CookieCacheConfig) -> Self {
        self.session.cookie_cache = Some(config);
        self
    }

    /// Set the JWT expiration duration.
    pub fn jwt_expires_in(mut self, duration: Duration) -> Self {
        self.jwt.expires_in = duration;
        self
    }

    /// Set the minimum password length.
    pub fn password_min_length(mut self, length: usize) -> Self {
        self.password.min_length = length;
        self
    }

    pub fn advanced(mut self, advanced: AdvancedConfig) -> Self {
        self.advanced = advanced;
        self
    }

    pub fn cookie_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.advanced.cookie_prefix = Some(prefix.into());
        self
    }

    pub fn disable_csrf_check(mut self, disabled: bool) -> Self {
        self.advanced.disable_csrf_check = disabled;
        self
    }

    pub fn disable_origin_check(mut self, disabled: bool) -> Self {
        self.advanced.disable_origin_check = disabled;
        self
    }

    pub fn cross_sub_domain_cookies(mut self, domain: impl Into<String>) -> Self {
        self.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
            domain: domain.into(),
        });
        self
    }

    /// Check whether a given origin is trusted.
    ///
    /// An origin is trusted if it matches:
    /// 1. The origin extracted from [`base_url`](Self::base_url), or
    /// 2. Any pattern in [`trusted_origins`](Self::trusted_origins) (after
    ///    extracting the origin portion from the pattern).
    ///
    /// Glob patterns are supported — `*` matches any characters except `/`,
    /// `**` matches any characters including `/`.
    pub fn is_origin_trusted(&self, origin: &str) -> bool {
        // Check base_url origin
        if let Some(base_origin) = extract_origin(&self.base_url)
            && origin == base_origin
        {
            return true;
        }
        // Check trusted_origins patterns
        self.trusted_origins.iter().any(|pattern| {
            let pattern_origin = extract_origin(pattern).unwrap_or_default();
            glob_match::glob_match(&pattern_origin, origin)
        })
    }

    /// Check whether a URL is a safe redirect target.
    ///
    /// A URL is safe if it is a relative path (starts with `/`, no
    /// traversal tricks) or its origin matches [`base_url`](Self::base_url)
    /// or [`trusted_origins`](Self::trusted_origins).
    ///
    /// This is used by both the CSRF middleware (for POST body/query
    /// targets) and per-endpoint origin checks (e.g. verify-email GET).
    pub fn is_redirect_target_trusted(&self, url: &str) -> bool {
        if is_safe_relative_path(url) {
            return true;
        }
        extract_origin(url).is_some_and(|origin| self.is_origin_trusted(&origin))
    }

    /// Check whether a given path is disabled.
    pub fn is_path_disabled(&self, path: &str) -> bool {
        self.disabled_paths.iter().any(|disabled| disabled == path)
    }
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.secret.is_empty() {
            return Err(AuthError::config("Secret key cannot be empty"));
        }

        if self.secret.len() < 32 {
            return Err(AuthError::config(
                "Secret key must be at least 32 characters",
            ));
        }

        Ok(())
    }
}

/// Check whether a URL is a safe relative path.
///
/// A relative path is safe if it starts with a single `/` and has no
/// traversal or scheme-escape tricks (`//`, `\`, `%2f`, `%5c`).
///
/// This is used by [`AuthConfig::is_redirect_target_trusted`] and the
/// CSRF middleware.
pub fn is_safe_relative_path(value: &str) -> bool {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return false;
    }

    let tail = &value[1..];
    let lower = tail.to_ascii_lowercase();
    !lower.starts_with("%2f") && !lower.starts_with("%5c")
}

/// Extract the origin (scheme + host + port) from a URL string.
///
/// For example, `"https://example.com/path"` → `"https://example.com"`.
///
/// This is used by [`AuthConfig::is_origin_trusted`] and the CSRF middleware
/// so that origin comparison is centralised in one place.
pub fn extract_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = format!("{}{}", &url[..scheme_end + 3], &rest[..host_end]);
    Some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_origin ──────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_path() {
        assert_eq!(
            extract_origin("https://example.com/path"),
            Some("https://example.com".to_string())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_without_path() {
        assert_eq!(
            extract_origin("https://example.com"),
            Some("https://example.com".to_string())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_port() {
        assert_eq!(
            extract_origin("http://localhost:3000/api"),
            Some("http://localhost:3000".to_string())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_query() {
        assert_eq!(
            extract_origin("https://example.com?foo=bar"),
            Some("https://example.com".to_string())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_fragment() {
        assert_eq!(
            extract_origin("https://example.com#fragment"),
            Some("https://example.com".to_string())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_no_scheme() {
        assert_eq!(extract_origin("example.com"), None);
    }

    // ── AuthConfig::new ─────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn new_config_sets_secret() {
        let cfg = AuthConfig::new("a]secret-that-is-at-least-32-characters-long");
        assert_eq!(cfg.secret, "a]secret-that-is-at-least-32-characters-long");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn new_config_uses_defaults() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567");
        assert_eq!(cfg.app_name, "Better Auth");
        assert_eq!(cfg.base_url, "http://localhost:3000");
        assert_eq!(cfg.base_path, "/api/auth");
        assert!(cfg.trusted_origins.is_empty());
    }

    // ── Builder methods ─────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn base_url_sets_cookie_secure_for_https() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.session.cookie_secure);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn base_url_clears_cookie_secure_for_http() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://myapp.com")
            .base_url("http://localhost:3000");
        assert!(!cfg.session.cookie_secure);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn builder_chaining() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .app_name("MyApp")
            .base_path("/auth")
            .password_min_length(12)
            .disable_csrf_check(true)
            .disable_origin_check(true)
            .cookie_prefix("myapp");

        assert_eq!(cfg.app_name, "MyApp");
        assert_eq!(cfg.base_path, "/auth");
        assert_eq!(cfg.password.min_length, 12);
        assert!(cfg.advanced.disable_csrf_check);
        assert!(cfg.advanced.disable_origin_check);
        assert_eq!(cfg.advanced.cookie_prefix, Some("myapp".to_string()));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn trusted_origin_appends() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://a.com")
            .trusted_origin("https://b.com");
        assert_eq!(cfg.trusted_origins.len(), 2);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn trusted_origins_replaces() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://old.com")
            .trusted_origins(vec!["https://new.com".to_string()]);
        assert_eq!(cfg.trusted_origins, vec!["https://new.com"]);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn disabled_path_appends() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .disabled_path("/admin")
            .disabled_path("/debug");
        assert_eq!(cfg.disabled_paths.len(), 2);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn disabled_paths_replaces() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .disabled_path("/old")
            .disabled_paths(vec!["/new".to_string()]);
        assert_eq!(cfg.disabled_paths, vec!["/new"]);
    }

    // ── is_origin_trusted ───────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_matches_base_url() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_origin_trusted("https://myapp.com"));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_rejects_unknown() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_origin_trusted("https://evil.com"));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_glob_pattern() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://*.example.com");
        assert!(cfg.is_origin_trusted("https://sub.example.com"));
        assert!(!cfg.is_origin_trusted("https://other.com"));
    }

    // ── is_redirect_target_trusted ─────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_relative_path() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        assert!(cfg.is_redirect_target_trusted("/callback?foo=bar"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_same_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_redirect_target_trusted("https://myapp.com/verified"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_trusted_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://myapp.com")
            .trusted_origin("https://trusted.com");
        assert!(cfg.is_redirect_target_trusted("https://trusted.com/path"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_rejects_untrusted_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_redirect_target_trusted("https://evil.com/phish"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_rejects_protocol_relative() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_redirect_target_trusted("//evil.com"));
    }

    // ── is_path_disabled ────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_path_disabled_matches() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").disabled_path("/admin");
        assert!(cfg.is_path_disabled("/admin"));
        assert!(!cfg.is_path_disabled("/user"));
    }

    // ── validate ────────────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_rejects_empty_secret() {
        let cfg = AuthConfig::default();
        assert!(cfg.validate().is_err());
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_rejects_short_secret() {
        let cfg = AuthConfig::new("short");
        assert!(cfg.validate().is_err());
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_accepts_valid_secret() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567");
        assert!(cfg.validate().is_ok());
    }

    // ── Defaults ────────────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_config_defaults() {
        let s = SessionConfig::default();
        assert_eq!(s.expires_in, Duration::hours(24 * 7));
        assert_eq!(s.update_age, Some(Duration::hours(24)));
        assert!(!s.disable_session_refresh);
        assert_eq!(s.cookie_name, "better-auth.session_token");
        assert!(s.cookie_http_only);
        assert_eq!(s.cookie_same_site, SameSite::Lax);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn jwt_config_defaults() {
        let j = JwtConfig::default();
        assert_eq!(j.expires_in, Duration::hours(24));
        assert_eq!(j.algorithm, "HS256");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn password_config_defaults() {
        let p = PasswordConfig::default();
        assert_eq!(p.min_length, 8);
        assert!(!p.require_uppercase);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn same_site_display() {
        assert_eq!(SameSite::Strict.to_string(), "Strict");
        assert_eq!(SameSite::Lax.to_string(), "Lax");
        assert_eq!(SameSite::None.to_string(), "None");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn cookie_cache_config_defaults() {
        let c = CookieCacheConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.max_age, Duration::minutes(5));
        assert_eq!(c.strategy, CookieCacheStrategy::Compact);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn account_config_defaults() {
        let a = AccountConfig::default();
        assert!(a.update_account_on_sign_in);
        assert!(!a.encrypt_oauth_tokens);
        assert!(a.account_linking.enabled);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn core_paths_error_page() {
        let html = core_paths::error_page_html("TEST_ERROR");
        assert!(html.contains("TEST_ERROR"));
        assert!(html.contains("Ask AI"));
        assert!(html.contains("<title>Error</title>"));
    }

    // Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
    #[test]
    fn error_page_sanitizes_script_tag() {
        let html = core_paths::error_page_html("<script>alert(1)</script>");
        assert!(html.contains("UNKNOWN"));
        assert!(!html.contains("<script>"));
    }

    // Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
    #[test]
    fn error_page_allows_valid_codes() {
        assert!(core_paths::error_page_html("SOME_ERROR-CODE").contains("SOME_ERROR-CODE"));
        assert!(core_paths::error_page_html("it's").contains("it's"));
    }

    // ── session builder methods ─────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_builder_methods() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .session_expires_in(Duration::hours(1))
            .session_update_age(Duration::minutes(30))
            .disable_session_refresh(true)
            .session_fresh_age(Duration::minutes(5));

        assert_eq!(cfg.session.expires_in, Duration::hours(1));
        assert_eq!(cfg.session.update_age, Some(Duration::minutes(30)));
        assert!(cfg.session.disable_session_refresh);
        assert_eq!(cfg.session.fresh_age, Some(Duration::minutes(5)));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_cookie_cache_builder() {
        let cache = CookieCacheConfig {
            enabled: true,
            max_age: Duration::minutes(10),
            strategy: CookieCacheStrategy::Jwt,
        };
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").session_cookie_cache(cache);

        let cc = cfg.session.cookie_cache.as_ref();
        assert!(cc.is_some());
        let cc = cc.unwrap();
        assert!(cc.enabled);
        assert_eq!(cc.strategy, CookieCacheStrategy::Jwt);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn cross_sub_domain_cookies_builder() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .cross_sub_domain_cookies(".example.com");
        let csd = cfg.advanced.cross_sub_domain_cookies.as_ref();
        assert!(csd.is_some());
        assert_eq!(csd.unwrap().domain, ".example.com");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn advanced_database_defaults() {
        let d = AdvancedDatabaseConfig::default();
        assert_eq!(d.default_find_many_limit, 100);
        assert!(!d.use_number_id);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn ip_address_config_defaults() {
        let ip = IpAddressConfig::default();
        assert_eq!(ip.headers, vec!["x-forwarded-for", "x-real-ip"]);
        assert!(!ip.disable_ip_tracking);
    }
}
