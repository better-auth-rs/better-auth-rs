use std::collections::BTreeMap;

use super::{get_cookie, render_cookie, resolved_template, serialize_cookie};
use crate::{AuthError, AuthRequest, AuthResult, request_runtime::ResolvedCookie};

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

fn clear_chunk(name: &str, parent: &ResolvedCookie) -> String {
    let mut cookie = resolved_template(parent);
    cookie.set_name(name.to_owned());
    cookie.set_max_age(cookie::time::Duration::ZERO);
    cookie.unset_expires();
    render_cookie(cookie, parent)
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
pub fn clear_chunked_cookie(req: &AuthRequest, cookie: &ResolvedCookie) -> AuthResult<()> {
    super::remove_set_cookie_entries(req, None, &cookie.name)?;
    for cookie in create_clear_chunked_cookies(req, cookie) {
        req.append_response_header("Set-Cookie", cookie)?;
    }
    Ok(())
}

/// Build expiration headers for a cookie and every numbered chunk on the request.
pub fn create_clear_chunked_cookies(req: &AuthRequest, cookie: &ResolvedCookie) -> Vec<String> {
    let name = &cookie.name;
    let mut cookies = vec![clear_chunk(name, cookie)];
    cookies.extend(
        existing_names(req, name)
            .into_iter()
            .filter(|chunk| chunk != name)
            .map(|chunk| clear_chunk(&chunk, cookie)),
    );
    cookies
}

/// Split an ASCII encoded cookie and expire stale chunks from the request.
pub fn create_chunked_cookies(
    req: &AuthRequest,
    cookie: &ResolvedCookie,
    value: &str,
) -> AuthResult<Vec<String>> {
    let name = &cookie.name;
    let template = resolved_template(cookie);
    let write = |name: String, value: &str| {
        let mut chunk = template.clone();
        chunk.set_name(name);
        serialize_cookie(chunk, value, cookie)
    };
    let overhead = write(format!("{name}.99"), "")?.len();
    let count_and_size = 4050_usize
        .checked_sub(overhead)
        .filter(|size| *size > 0)
        .map(|size| (value.len().div_ceil(size), size));
    let mut cookies: BTreeMap<String, String> = existing_names(req, name)
        .into_iter()
        .map(|chunk| {
            let header = clear_chunk(&chunk, cookie);
            (chunk, header)
        })
        .collect();
    if let Some((count, chunk_size)) = count_and_size.filter(|(count, _)| *count <= 100) {
        if count <= 1 {
            let _ = cookies.insert(name.to_owned(), write(name.to_owned(), value)?);
        } else {
            for (index, chunk) in value.as_bytes().chunks(chunk_size).enumerate() {
                let chunk_name = format!("{name}.{index}");
                let value = std::str::from_utf8(chunk).map_err(|error| {
                    AuthError::internal(format!("Encoding cookie chunk: {error}"))
                })?;
                let _ = cookies.insert(chunk_name.to_owned(), write(chunk_name, value)?);
            }
        }
    } else {
        crate::observability::logger::current().warn(
            "Cookie exceeds the 100 chunk limit; cache not stored",
            &[crate::observability::LogArgument::Value(
                &serde_json::json!(name),
            )],
        );
    }
    Ok(cookies.into_values().collect())
}
