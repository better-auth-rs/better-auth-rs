use better_auth_core::utils::cookie_utils::sign_cookie_value_native_raw;
use better_auth_core::{
    AuthContext, AuthResult, AuthSchema, CookieAttributes, FieldValue, SameSite,
};
use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;

/// Browser-cookie input compatible with Playwright's `addCookies` shape.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCookie {
    /// Configured wire cookie name.
    pub name: String,
    /// Raw signed cookie value.
    pub value: String,
    /// Base URL hostname or explicit browser domain override.
    pub domain: String,
    /// Configured cookie path.
    pub path: String,
    /// Whether browser scripts can read the cookie.
    pub http_only: bool,
    /// Whether the browser requires HTTPS.
    pub secure: bool,
    /// Browser API spelling: `Strict`, `Lax`, or `None`.
    pub same_site: &'static str,
    /// Expiry in Unix seconds; absent for a session cookie.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "better_auth_core::wire::serialize_optional_number"
    )]
    pub expires: Option<f64>,
}
fn signed<S: AuthSchema>(
    auth: &AuthContext<S>,
    token: &FieldValue,
) -> AuthResult<(better_auth_core::request_runtime::ResolvedCookie, String)> {
    Ok((
        auth.config.auth_cookie(
            "session_token",
            CookieAttributes {
                max_age: Some(auth.config.session.expires_in().as_seconds_f64()),
                ..Default::default()
            },
        ),
        sign_cookie_value_native_raw(token, &auth.config.secret)?,
    ))
}
pub(super) fn headers<S: AuthSchema>(
    auth: &AuthContext<S>,
    token: &FieldValue,
) -> AuthResult<HashMap<String, String>> {
    let (cookie, value) = signed(auth, token)?;
    Ok([("cookie".into(), format!("{}={value}", cookie.name))].into())
}
pub(super) fn cookies<S: AuthSchema>(
    auth: &AuthContext<S>,
    token: &FieldValue,
    domain: Option<&str>,
) -> AuthResult<Vec<TestCookie>> {
    let (cookie, value) = signed(auth, token)?;
    let attributes = cookie.attributes;
    let domain = domain
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            url::Url::parse(auth.base_url())
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_else(|| "localhost".into())
        });
    Ok(vec![TestCookie {
        name: cookie.name,
        value,
        domain,
        path: attributes
            .path
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "/".into()),
        http_only: attributes.http_only.unwrap_or(true),
        secure: attributes.secure.unwrap_or(false),
        same_site: match attributes.same_site {
            Some(SameSite::Strict) => "Strict",
            Some(SameSite::None) => "None",
            _ => "Lax",
        },
        expires: attributes
            .max_age
            .filter(|value| *value != 0.0 && !value.is_nan())
            .map(|age| Utc::now().timestamp() as f64 + age),
    }])
}
