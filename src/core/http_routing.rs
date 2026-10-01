use better_auth_core::{AuthRequest, AuthRoute, HttpMethod};

fn pathname(request: &AuthRequest) -> &str {
    request
        .base_relative_path()
        .unwrap_or_else(|| request.url().map_or(request.path(), |url| url.path()))
}

pub(super) fn disabled_path<'a>(request: &'a AuthRequest, base: &str) -> &'a str {
    let path = pathname(request).trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let base = base.trim_end_matches('/');
    if base.is_empty() || request.base_relative_path().is_some() {
        return path;
    }
    if path == base {
        return "/";
    }
    path.strip_prefix(base)
        .filter(|path| path.starts_with('/'))
        .unwrap_or(path)
}

pub(super) fn route_path<'a>(request: &'a AuthRequest, base: &str) -> Option<&'a str> {
    let path = pathname(request);
    let base = base.trim_end_matches('/');
    let relative = if base.is_empty() || request.base_relative_path().is_some() {
        path
    } else if let Some(relative) = path.strip_prefix(base).filter(|path| path.starts_with('/')) {
        relative
    } else if request.url().is_none() && path != base {
        // In-process HTTP dispatch also accepts a base-relative AuthRequest without a transport URL.
        path
    } else {
        return None;
    };
    (!relative.is_empty() && !relative.contains("//")).then_some(relative)
}

pub(super) fn matched_path(
    route: &AuthRoute,
    method: &HttpMethod,
    path: &str,
    tolerant: bool,
) -> Option<String> {
    let path = if tolerant && path.ends_with('/') != route.path.ends_with('/') {
        if route.path.ends_with('/') {
            format!("{path}/")
        } else {
            path.strip_suffix('/')?.to_owned()
        }
    } else {
        path.to_owned()
    };
    route.matches(method, &path).then_some(path)
}
