use std::collections::BTreeMap;

use super::{create_clear_cookie, create_session_like_cookie, get_cookie};
use crate::{AuthConfig, AuthError, AuthRequest, AuthResult};

fn chunk_index(name: &str, cookie_name: &str) -> Option<usize> {
    let suffix = name.strip_prefix(cookie_name)?.strip_prefix('.')?;
    let index: usize = suffix.parse().ok()?;
    (index.to_string() == suffix).then_some(index)
}

fn existing_names(req: &AuthRequest, name: &str) -> Vec<String> {
    req.headers
        .get("cookie")
        .map(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .filter(|cookie| {
                    cookie.name() == name || chunk_index(cookie.name(), name).is_some()
                })
                .map(|cookie| cookie.name().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Read a complete cookie or combine its numbered chunks in numeric order.
pub fn get_chunked_cookie(req: &AuthRequest, name: &str) -> Option<String> {
    if let Some(value) = get_cookie(req, name).filter(|value| !value.is_empty()) {
        return Some(value);
    }
    let mut chunks = BTreeMap::new();
    for cookie in cookie::Cookie::split_parse(req.headers.get("cookie")?).flatten() {
        if let Some(index) = chunk_index(cookie.name(), name) {
            let _ = chunks.insert(index, cookie.value().to_string());
        }
    }
    (!chunks.is_empty()).then(|| chunks.into_values().collect())
}

/// Expire a cookie and every numbered chunk present on the request.
pub fn clear_chunked_cookie(req: &AuthRequest, name: &str, config: &AuthConfig) -> AuthResult<()> {
    for cookie in create_clear_chunked_cookies(req, name, config) {
        req.append_response_header("Set-Cookie", cookie)?;
    }
    Ok(())
}

/// Build expiration headers for a cookie and every numbered chunk on the request.
pub fn create_clear_chunked_cookies(
    req: &AuthRequest,
    name: &str,
    config: &AuthConfig,
) -> Vec<String> {
    let mut cookies = vec![create_clear_cookie(name, config)];
    cookies.extend(
        existing_names(req, name)
            .into_iter()
            .filter(|chunk| chunk != name)
            .map(|chunk| create_clear_cookie(&chunk, config)),
    );
    cookies
}

/// Split an ASCII encoded cookie and expire stale chunks from the request.
pub fn create_chunked_cookies(
    req: &AuthRequest,
    name: &str,
    value: &str,
    max_age: Option<i64>,
    config: &AuthConfig,
) -> AuthResult<Vec<String>> {
    let overhead = create_session_like_cookie(&format!("{name}.99"), "", max_age, config).len();
    let count_and_size = 4050_usize
        .checked_sub(overhead)
        .filter(|size| *size > 0)
        .map(|size| (value.len().div_ceil(size), size));
    let mut cookies: BTreeMap<String, String> = existing_names(req, name)
        .into_iter()
        .map(|name| {
            let cookie = create_clear_cookie(&name, config);
            (name, cookie)
        })
        .collect();
    if let Some((count, chunk_size)) = count_and_size.filter(|(count, _)| *count <= 100) {
        if count <= 1 {
            let _ = cookies.insert(
                name.to_owned(),
                create_session_like_cookie(name, value, max_age, config),
            );
        } else {
            for (index, chunk) in value.as_bytes().chunks(chunk_size).enumerate() {
                let chunk_name = format!("{name}.{index}");
                let value = std::str::from_utf8(chunk).map_err(|error| {
                    AuthError::internal(format!("Encoding cookie chunk: {error}"))
                })?;
                let _ = cookies.insert(
                    chunk_name.to_owned(),
                    create_session_like_cookie(&chunk_name, value, max_age, config),
                );
            }
        }
    } else {
        tracing::warn!(
            cookie = name,
            "Cookie exceeds the 100 chunk limit; cache not stored"
        );
    }
    Ok(cookies.into_values().collect())
}
