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
    pub const OPENAPI_SPEC: &str = "/reference/openapi.json";
    pub const UPDATE_USER: &str = "/update-user";
    pub const DELETE_USER: &str = "/delete-user";
    pub const CHANGE_EMAIL: &str = "/change-email";
    pub const DELETE_USER_CALLBACK: &str = "/delete-user/callback";
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
    /// Update user info when a new account is linked (default: false)
    pub update_user_info_on_link: bool,
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

    /// If `true`, the Origin header check is skipped.
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
            cookie_name: "better-auth.session-token".to_string(),
            cookie_secure: true,
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
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
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
    /// `**` matches any characters including `/`. Non-wildcard patterns
    /// are parsed with the strict WHATWG URL parser so scheme, host, and
    /// default port match exactly what runtime callback URLs normalise
    /// to. Wildcard patterns fall back to naïve scheme/authority
    /// splitting so `http://localhost:*` and `*://app.com` still work;
    /// their non-wildcard host labels are still IDN-canonicalised.
    pub fn is_origin_trusted(&self, origin: &str) -> bool {
        // Check base_url origin
        if let Some(base_origin) = extract_origin(&self.base_url)
            && origin == base_origin
        {
            return true;
        }
        // Check trusted_origins patterns
        self.trusted_origins.iter().any(|pattern| {
            let pattern_origin = extract_pattern_origin(pattern);
            glob_match::glob_match(&pattern_origin, origin)
        })
    }

    /// Check whether a given path is disabled.
    pub fn is_path_disabled(&self, path: &str) -> bool {
        self.disabled_paths.iter().any(|disabled| disabled == path)
    }

    /// Check whether `target` is safe to use as the value of a server-issued
    /// redirect (302 `Location`) or an absolute link embedded in an outgoing
    /// email. Safe targets are:
    ///
    /// - a relative path starting with `/` whose second character is not
    ///   `/` or `\` (authority smuggling — `//evil.com`, `/\evil.com` —
    ///   is rejected even when the caller opts out of origin checks;
    ///   browsers normalise `\` to `/` in the authority component);
    /// - an absolute `http`/`https` URL whose origin matches
    ///   [`base_url`](Self::base_url) or a
    ///   [`trusted_origins`](Self::trusted_origins) pattern;
    /// - any path/URL when `advanced.disable_origin_check` is set, with
    ///   the authority-smuggling exception above.
    ///
    /// Other schemes (`javascript:`, `data:`, `file:`, …) are always
    /// rejected. Prevents open-redirect via user-supplied `callbackURL`
    /// / `redirectTo`.
    pub fn is_redirect_target_trusted(&self, target: &str) -> bool {
        // Reject control characters (CR/LF, NUL, TAB, etc.) and the
        // double-quote character outright. Any of them would let the
        // caller break out of the Location header or the surrounding
        // email-HTML `href="..."` attribute once this value is
        // interpolated by a downstream `format!`. WHATWG URL parsers
        // strip most of these silently but our callers treat the string
        // as opaque, so the guard must live here.
        if target.chars().any(|c| c.is_control() || c == '"') {
            return false;
        }
        // Authority smuggling must NEVER be accepted, even under
        // `disable_origin_check`. That flag is an opt-out of same-origin
        // checks, not a licence to let the caller pick the host.
        if is_authority_smuggling(target) {
            return false;
        }
        if self.advanced.disable_origin_check {
            // Even with origin checks disabled, reject non-http(s) URLs.
            // `javascript:`, `data:`, `file:`, and other schemes would
            // execute in the caller's browser / expose local files if
            // reflected into a Location header. Relative paths and
            // well-formed http/https URLs are allowed; `extract_origin`
            // already filters the unsafe schemes.
            return target.starts_with('/') || extract_origin(target).is_some();
        }
        if target.starts_with('/') {
            return true;
        }
        match extract_origin(target) {
            Some(origin) => self.is_origin_trusted(&origin),
            None => false,
        }
    }

    /// Stricter variant of [`is_redirect_target_trusted`] that requires
    /// an absolute `http`/`https` URL. Use this for `callbackURL` values
    /// that are **embedded in an email body** or **forwarded to an OAuth
    /// provider as `redirect_uri`** — in both contexts a relative path
    /// produces a broken link (mail clients have no base URL to resolve
    /// against; OAuth spec requires absolute URIs).
    ///
    /// For server-issued `Location` redirects (GET handlers reached via
    /// email link clicks), relative paths are fine; use the less strict
    /// [`is_redirect_target_trusted`] there.
    pub fn is_absolute_trusted_callback_url(&self, target: &str) -> bool {
        if !self.is_redirect_target_trusted(target) {
            return false;
        }
        // `extract_origin` returns `Some(_)` only for well-formed http/https
        // absolute URLs; relative paths return `None`.
        extract_origin(target).is_some()
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

/// Default hard cap for request body reads.
///
/// Applied by the root-crate axum entry handler and by
/// `AuthRequestExt::from_request` when no explicit limit is configured,
/// so chunked bodies cannot exhaust memory before `BodyLimitMiddleware`
/// runs. Matches the `BodyLimitConfig::default().max_bytes` value and
/// upstream TypeScript `better-auth@1.4.19`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Extract the origin (scheme + host + port) from a URL string.
///
/// For example, `"https://example.com/path"` → `"https://example.com"`.
///
/// Uses the WHATWG URL parser so query strings, fragments, and userinfo
/// are stripped correctly (the hand-rolled version this replaced returned
/// `"https://app.example.com?foo=bar"` for `"https://app.example.com?foo=bar"`,
/// and kept userinfo, which let an `app.example.com@evil.com` authority
/// masquerade as an app-origin URL in string comparisons).
///
/// Only `http` and `https` origins are returned; opaque or unusual schemes
/// (`javascript:`, `data:`, `file:`) return `None` so they cannot sneak
/// through the origin-comparison path.
///
/// This is used by [`AuthConfig::is_origin_trusted`],
/// [`AuthConfig::is_redirect_target_trusted`], and the CSRF middleware so
/// that origin comparison is centralised in one place.
pub fn extract_origin(url: &str) -> Option<String> {
    let parsed = ::url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    match parsed.origin() {
        ::url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        ::url::Origin::Opaque(_) => None,
    }
}

/// Naïve origin extractor used only for matching `trusted_origins`
/// patterns. Unlike [`extract_origin`] this does not invoke a strict URL
/// parser, so glob patterns with non-RFC characters (`*`, wildcard
/// ports) survive. For any value an operator is likely to configure —
/// `https://*.example.com`, `http://localhost:*`, `*://app.com` — we
/// return the `"scheme://authority"` prefix unchanged and let
/// `glob_match` do the final comparison.
///
/// Default ports (`:80` for `http`, `:443` for `https`) are stripped so
/// that a pattern like `https://admin.example.com:443` still matches the
/// origin produced by `extract_origin("https://admin.example.com/x")`,
/// which is `https://admin.example.com` — `url::Url::origin()` omits
/// default ports per the WHATWG URL spec.
fn extract_pattern_origin(pattern: &str) -> String {
    // When the pattern is a well-formed absolute URL with no glob
    // wildcards, round-trip it through `extract_origin` so the result
    // uses exactly the same normalisation (punycode host, lower-case
    // scheme, omitted default port) as the runtime origin comparisons
    // produced by `url::Url::parse`. Otherwise (bare hostnames, glob
    // wildcards like `http://localhost:*`, non-http schemes, …) fall
    // back to a naïve scheme://authority split so wildcards survive.
    if !pattern.contains('*')
        && let Some(canonical) = extract_origin(pattern)
    {
        return canonical;
    }

    let Some(scheme_end) = pattern.find("://") else {
        return String::new();
    };
    let scheme = pattern[..scheme_end].to_ascii_lowercase();
    let rest = &pattern[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..host_end];

    // Split host from port so IDN normalisation only runs on the host.
    let (host, port_suffix) = match authority.rfind(':') {
        Some(idx)
            if authority[idx + 1..]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '*') =>
        {
            (&authority[..idx], &authority[idx..])
        }
        _ => (authority, ""),
    };

    // IDN-canonicalise each label that does not contain a glob wildcard
    // so `https://*.bücher.example` matches callbacks that
    // `url::Url::parse` normalises to `https://shop.xn--bcher-kva.example`.
    // Labels that contain `*` / `**` stay raw, otherwise we would break
    // the glob. Purely ASCII labels pass through unchanged.
    let canonical_host: String = host
        .split('.')
        .map(|label| {
            if label.contains('*') || label.is_ascii() {
                label.to_ascii_lowercase()
            } else {
                idna::domain_to_ascii(label).unwrap_or_else(|_| label.to_ascii_lowercase())
            }
        })
        .collect::<Vec<_>>()
        .join(".");

    // Strip default ports for http/https to match `extract_origin`.
    let port_suffix = match (scheme.as_str(), port_suffix) {
        ("http", ":80") | ("https", ":443") => "",
        _ => port_suffix,
    };

    format!("{}://{}{}", scheme, canonical_host, port_suffix)
}

/// Detect attacker-controlled authority smuggling in a redirect target.
///
/// Returns `true` for:
/// - protocol-relative URLs (`//evil.com/x`) — browser resolves against
///   the current origin's scheme but the host is caller-controlled;
/// - `/\evil.com` and similar backslash bypasses — Chrome, Safari, and
///   Edge follow WHATWG authority-state parsing and normalise `\` to `/`.
///
/// Used by [`AuthConfig::is_redirect_target_trusted`] to reject these
/// forms even when origin checks are otherwise disabled.
fn is_authority_smuggling(target: &str) -> bool {
    let trimmed = target.trim_start_matches(|c: char| c.is_whitespace());
    // Any leading backslash is suspect. Browsers normalise `\` to `/` in
    // the authority state, so `\evil.com`, `\\evil.com`, and `\/evil.com`
    // all resolve to different attacker-controllable targets depending on
    // the surrounding context. Reject the whole class up-front rather
    // than enumerating every two-character combination.
    if trimmed.starts_with('\\') {
        return true;
    }
    if trimmed.starts_with("//") {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix('/')
        && (rest.starts_with('/') || rest.starts_with('\\'))
    {
        return true;
    }
    // Percent-encoded `/` and `\` in the authority-start position let a
    // double-decoding proxy (some nginx configurations, some CDNs) see
    // `//evil.com` or `/\evil.com` after the first decode pass while
    // the Rust-side string still looks like a harmless path. Defence in
    // depth: reject the encoded forms too.
    let encoded_bypass = ["/%2f", "/%2F", "/%5c", "/%5C", "%2f", "%2F", "%5c", "%5C"];
    if encoded_bypass.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(trusted: Vec<&str>) -> AuthConfig {
        AuthConfig {
            base_url: "https://app.example.com".into(),
            trusted_origins: trusted.into_iter().map(String::from).collect(),
            ..AuthConfig::default()
        }
    }

    #[test]
    fn redirect_target_allows_relative_path() {
        let cfg = config_with(vec![]);
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        assert!(cfg.is_redirect_target_trusted("/reset-password?token=abc"));
    }

    #[test]
    fn redirect_target_rejects_protocol_relative() {
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("//evil.com/x"));
        assert!(!cfg.is_redirect_target_trusted("//evil.com"));
    }

    #[test]
    fn redirect_target_allows_base_url_origin() {
        let cfg = config_with(vec![]);
        assert!(cfg.is_redirect_target_trusted("https://app.example.com/dashboard"));
    }

    #[test]
    fn redirect_target_allows_trusted_origin() {
        let cfg = config_with(vec!["https://admin.example.com"]);
        assert!(cfg.is_redirect_target_trusted("https://admin.example.com/callback"));
    }

    #[test]
    fn redirect_target_rejects_untrusted_origin() {
        let cfg = config_with(vec!["https://admin.example.com"]);
        assert!(!cfg.is_redirect_target_trusted("https://evil.com/cb"));
    }

    #[test]
    fn redirect_target_rejects_unparseable_absolute() {
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("javascript:alert(1)"));
        assert!(!cfg.is_redirect_target_trusted("data:text/html,x"));
    }

    #[test]
    fn redirect_target_bypass_does_not_cover_authority_smuggling() {
        // `disable_origin_check` is an opt-out of same-origin checks, NOT
        // a licence for the caller to pick the host. Protocol-relative
        // and backslash-bypass forms must still be rejected.
        let mut cfg = config_with(vec![]);
        cfg.advanced.disable_origin_check = true;
        assert!(cfg.is_redirect_target_trusted("https://evil.com/cb"));
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        assert!(!cfg.is_redirect_target_trusted("//evil.com"));
        assert!(!cfg.is_redirect_target_trusted("/\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("\\\\evil.com"));
    }

    #[test]
    fn redirect_target_rejects_backslash_authority_bypass() {
        // Browsers (Chrome, Safari, Edge) normalise `\` to `/` in the
        // authority component, so `Location: /\evil.com` navigates to
        // `//evil.com`. Must be rejected.
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("/\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("/\\\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("\\\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("\\/evil.com"));
        // Whitespace-padded variants browsers may strip.
        assert!(!cfg.is_redirect_target_trusted("  //evil.com"));
        assert!(!cfg.is_redirect_target_trusted("\t/\\evil.com"));
    }

    #[test]
    fn redirect_target_strips_userinfo_when_comparing_origin() {
        // `app.example.com@evil.com` — the real host is `evil.com`; the
        // old hand-rolled parser kept the whole string as the "origin"
        // and would silently compare against `https://app.example.com`.
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("https://app.example.com@evil.com/x"));
    }

    #[test]
    fn redirect_target_allows_same_origin_with_query_and_fragment() {
        // The old hand-rolled `extract_origin` returned the whole URL for
        // these inputs, so legitimate same-origin URLs with `?` or `#`
        // were silently rejected. url::Url::parse fixes this.
        let cfg = config_with(vec![]);
        assert!(cfg.is_redirect_target_trusted("https://app.example.com?retry=1"));
        assert!(cfg.is_redirect_target_trusted("https://app.example.com#/route"));
        assert!(cfg.is_redirect_target_trusted("https://app.example.com/path?x=1#y"));
    }

    #[test]
    fn redirect_target_rejects_non_http_schemes() {
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("javascript:alert(1)"));
        assert!(!cfg.is_redirect_target_trusted("data:text/html,x"));
        assert!(!cfg.is_redirect_target_trusted("file:///etc/passwd"));
        assert!(!cfg.is_redirect_target_trusted("ftp://example.com/"));
    }

    #[test]
    fn redirect_target_preserves_non_default_port_in_origin_match() {
        let cfg = config_with(vec!["https://admin.example.com:8443"]);
        assert!(cfg.is_redirect_target_trusted("https://admin.example.com:8443/x"));
        // Different port → not the same origin.
        assert!(!cfg.is_redirect_target_trusted("https://admin.example.com/x"));
    }

    #[test]
    fn redirect_target_rejects_control_chars_and_quotes() {
        // CR/LF would split a Location header; `"` would break out of
        // an `href="..."` attribute in the rendered email.
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("/path\r\nEvil-Header: x"));
        assert!(!cfg.is_redirect_target_trusted("/path\nEvil: x"));
        assert!(!cfg.is_redirect_target_trusted("/path\"><script>"));
        assert!(!cfg.is_redirect_target_trusted("/path\u{0000}null"));
        assert!(!cfg.is_redirect_target_trusted("https://app.example.com/x\r\n"));
    }

    #[test]
    fn trusted_origins_with_explicit_default_ports_still_match() {
        // `url::Url::origin` strips `:443` / `:80`; `extract_pattern_origin`
        // now does the same so a `trusted_origins` entry that spells out
        // the default port still matches callbacks that don't.
        let cfg = config_with(vec![
            "https://admin.example.com:443",
            "http://legacy.example.com:80",
        ]);
        assert!(cfg.is_origin_trusted("https://admin.example.com"));
        assert!(cfg.is_origin_trusted("http://legacy.example.com"));
        assert!(cfg.is_redirect_target_trusted("https://admin.example.com/cb"));
        assert!(cfg.is_redirect_target_trusted("http://legacy.example.com/cb"));
    }

    #[test]
    fn redirect_target_bypass_still_rejects_dangerous_schemes() {
        // `disable_origin_check = true` opts out of origin comparison
        // but MUST NOT open the gate to `javascript:`, `data:`,
        // `file:`, or other non-http schemes — the rustdoc promises
        // those are always rejected.
        let mut cfg = config_with(vec![]);
        cfg.advanced.disable_origin_check = true;
        assert!(!cfg.is_redirect_target_trusted("javascript:alert(1)"));
        assert!(!cfg.is_redirect_target_trusted("data:text/html,<script>x</script>"));
        assert!(!cfg.is_redirect_target_trusted("file:///etc/passwd"));
        assert!(!cfg.is_redirect_target_trusted("ftp://example.com/"));
        // But well-formed http(s) and relative paths still pass.
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        assert!(cfg.is_redirect_target_trusted("https://evil.com/cb"));
    }

    #[test]
    fn trusted_origins_wildcard_idn_matches_punycode_callback() {
        // A wildcard pattern with a Unicode label should still match a
        // callback origin that `url::Url::parse` canonicalises to
        // punycode. Wildcard labels themselves are preserved verbatim.
        let cfg = config_with(vec!["https://*.bücher.example"]);
        assert!(cfg.is_origin_trusted("https://shop.xn--bcher-kva.example"));
        assert!(cfg.is_redirect_target_trusted("https://shop.xn--bcher-kva.example/path"));
    }

    #[test]
    fn trusted_origins_pattern_lowercases_scheme_and_host() {
        // `url::Url::origin()` lowercases scheme + host; patterns typed
        // with mixed case should still match.
        let cfg = config_with(vec!["HTTPS://APP.Example.COM"]);
        assert!(cfg.is_origin_trusted("https://app.example.com"));
        assert!(cfg.is_redirect_target_trusted("https://app.example.com/x"));
    }

    #[test]
    fn trusted_origins_punycode_idn_matches_punycode_callback() {
        // `url::Url` converts IDN hosts to punycode. A pattern that
        // spells the domain in Unicode should still match a callback
        // URL that the parser normalises to `xn--...`.
        let cfg = config_with(vec!["https://bücher.example"]);
        assert!(cfg.is_origin_trusted("https://xn--bcher-kva.example"));
        assert!(cfg.is_redirect_target_trusted("https://xn--bcher-kva.example/book"));
    }

    #[test]
    fn absolute_trusted_callback_url_rejects_relative_paths() {
        // Relative paths are fine for server-issued 302 Location headers
        // but break when embedded in an email body (mail clients have no
        // base URL) or forwarded to an OAuth provider as `redirect_uri`
        // (spec requires absolute). The stricter helper must reject
        // them even when the origin check would otherwise accept.
        let cfg = config_with(vec!["https://admin.example.com"]);
        // Still accepted by the looser redirect helper…
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        // …but not by the email / OAuth helper.
        assert!(!cfg.is_absolute_trusted_callback_url("/dashboard"));
        assert!(!cfg.is_absolute_trusted_callback_url("/reset?token=x"));
        // Absolute trusted URL passes both.
        assert!(cfg.is_absolute_trusted_callback_url("https://admin.example.com/cb"));
        // Absolute untrusted URL rejected by both.
        assert!(!cfg.is_absolute_trusted_callback_url("https://evil.com/cb"));
        // Non-http schemes rejected by both.
        assert!(!cfg.is_absolute_trusted_callback_url("javascript:alert(1)"));
    }

    #[test]
    fn redirect_target_rejects_percent_encoded_authority_bypass() {
        // Double-decoding proxies can turn `/%2Fevil.com` into
        // `//evil.com` before the next hop sees it; reject the
        // percent-encoded forms so the extra decode pass can't
        // rehydrate an authority smuggler.
        let cfg = config_with(vec![]);
        assert!(!cfg.is_redirect_target_trusted("/%2Fevil.com"));
        assert!(!cfg.is_redirect_target_trusted("/%2fevil.com"));
        assert!(!cfg.is_redirect_target_trusted("/%5Cevil.com"));
        assert!(!cfg.is_redirect_target_trusted("/%5cevil.com"));
        assert!(!cfg.is_redirect_target_trusted("%2Fevil.com"));
    }

    #[test]
    fn redirect_target_rejects_bare_backslash_under_disable_origin_check() {
        // `\evil.com` is normalised by browsers to path-start + "/evil.com"
        // — same-origin in practice, but the authority-smuggling guard's
        // documented contract ("even under disable_origin_check, the
        // caller cannot pick the host") must hold.
        let mut cfg = config_with(vec![]);
        cfg.advanced.disable_origin_check = true;
        assert!(!cfg.is_redirect_target_trusted("\\evil.com"));
        assert!(!cfg.is_redirect_target_trusted("  \\evil.com"));
    }

    #[test]
    fn trusted_origins_supports_port_and_scheme_globs() {
        // Regression for switching extract_origin to url::Url::parse —
        // `http://localhost:*` and similar wildcard patterns must stay
        // usable. Strict URL parsing would reject them.
        let cfg = config_with(vec![
            "http://localhost:*",
            "https://*.example.com",
            "*://api.staging.test",
        ]);
        assert!(cfg.is_origin_trusted("http://localhost:3000"));
        assert!(cfg.is_origin_trusted("http://localhost:8080"));
        assert!(cfg.is_origin_trusted("https://app.example.com"));
        assert!(cfg.is_origin_trusted("http://api.staging.test"));
        assert!(cfg.is_origin_trusted("https://api.staging.test"));
        assert!(!cfg.is_origin_trusted("http://localhost.evil.com"));
    }
}
