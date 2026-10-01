use std::{
    borrow::Cow,
    sync::atomic::{AtomicBool, Ordering},
};

use better_auth_core::{AuthContext, AuthResponse, AuthResult, AuthSchema};
use serde::Serialize;
use serde_json::Value;

pub const OAUTH_POPUP_COMPLETE_SCRIPT: &str = include_str!("complete.js");
pub const OAUTH_POPUP_SCRIPT_CSP_HASH: &str = "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=";
static WARNED_MISSING_BEARER: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
pub(super) struct Failure {
    pub(super) code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    #[serde(rename = "type")]
    message_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_origin: Option<Value>,
    nonce: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Failure>,
}

pub(super) fn render(
    response: &mut AuthResponse,
    origin: Option<Value>,
    nonce: Value,
    token: Option<String>,
    redirect: Option<String>,
    error: Option<Failure>,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    if token.is_some()
        && ctx.config.session.bearer.is_none()
        && !WARNED_MISSING_BEARER.swap(true, Ordering::Relaxed)
    {
        better_auth_core::observability::logger::current().warn("OAuth popup returns a session token to its opener. Configure session.bearer to authenticate embedded applications with that token.", &[]);
    }
    let payload = serde_json::to_string(&Message {
        message_type: "better-auth:oauth-popup",
        target_origin: origin,
        nonce,
        token,
        redirect_to: redirect,
        error,
    })?
    .replace('<', "\\u003c")
    .replace('\u{2028}', "\\u2028")
    .replace('\u{2029}', "\\u2029");
    response.replace_returned(better_auth_core::AuthResponse::html(200, format!("<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n<script type=\"application/json\" id=\"better-auth-oauth-popup\">{payload}</script>\n<script>{OAUTH_POPUP_COMPLETE_SCRIPT}</script>\n</body>\n</html>")));
    for (name, value) in [
        ("content-type", "text/html; charset=utf-8".to_owned()),
        (
            "content-security-policy",
            format!(
                "default-src 'none'; script-src '{OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'"
            ),
        ),
        ("cache-control", "no-store".to_owned()),
        ("pragma", "no-cache".to_owned()),
    ] {
        let _ = response.headers.insert(name, value);
    }
    Ok(())
}

pub(super) fn session_token(response: &AuthResponse, name: &str) -> Option<String> {
    response.headers.get_all("set-cookie").find_map(|header| {
        split_cookies(header)
            .into_iter()
            .filter_map(|cookie| {
                let pair = cookie.split(';').next()?.trim();
                let (key, value) = pair.split_once('=')?;
                if key != name {
                    return None;
                }
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                Some(decode_cookie(value).into_owned())
            })
            .next_back()
    })
}

fn split_cookies(header: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, character) in header.char_indices() {
        if character == ','
            && header
                .get(index + 1..)
                .and_then(|tail| tail.split([';', ',']).next())
                .is_some_and(|tail| tail.contains('='))
        {
            if let Some(part) = header.get(start..index) {
                parts.push(part.trim());
            }
            start = index + 1;
        }
    }
    if let Some(part) = header.get(start..) {
        parts.push(part.trim());
    }
    parts
}

fn decode_cookie(value: &str) -> Cow<'_, str> {
    // Upstream preserves the whole value when URI decoding fails.
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                && bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return Cow::Borrowed(value);
        }
    }
    urlencoding::decode(value).unwrap_or(Cow::Borrowed(value))
}
