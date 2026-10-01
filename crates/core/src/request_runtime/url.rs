use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use url::{Position, Url};

use super::config::{BaseUrl, BaseUrlProtocol, DynamicBaseUrl};
use crate::{AuthRequest, AuthResult};

#[derive(Clone, Copy)]
pub(super) enum Source<'a> {
    Request(&'a AuthRequest),
    Headers(&'a HashMap<String, String>),
}

impl Source<'_> {
    pub(super) fn headers(&self) -> &HashMap<String, String> {
        match self {
            Self::Request(request) => &request.headers,
            Self::Headers(headers) => headers,
        }
    }

    pub(super) fn request(&self) -> Option<&AuthRequest> {
        match self {
            Self::Request(request) => Some(request),
            Self::Headers(_) => None,
        }
    }
}

pub(super) fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

pub(super) fn origin(value: &str) -> Option<String> {
    let origin = Url::parse(value).ok()?.origin().ascii_serialization();
    (origin != "null").then_some(origin)
}

pub(super) fn with_path(value: &str, path: &str) -> Result<String, String> {
    let parsed = Url::parse(value)
        .map_err(|_| format!("Invalid base URL: {value}. Please provide a valid base URL."))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "Invalid base URL: {value}. URL must include 'http://' or 'https://'"
        ));
    }
    if !parsed.path().trim_end_matches('/').is_empty() {
        return Ok(value.to_owned());
    }
    let value = value.trim_end_matches('/');
    Ok(if path.is_empty() || path == "/" {
        value.to_owned()
    } else if path.starts_with('/') {
        format!("{value}{path}")
    } else {
        format!("{value}/{path}")
    })
}

pub(super) fn environment(name: &str) -> AuthResult<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(crate::AuthError::config(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

pub(super) fn environment_base_url() -> AuthResult<Option<String>> {
    for name in [
        "BETTER_AUTH_URL",
        "NEXT_PUBLIC_BETTER_AUTH_URL",
        "PUBLIC_BETTER_AUTH_URL",
        "NUXT_PUBLIC_BETTER_AUTH_URL",
        "NUXT_PUBLIC_AUTH_URL",
        "BASE_URL",
    ] {
        if let Some(value) = environment(name)?
            && !value.is_empty()
            && !(name == "BASE_URL" && value == "/")
        {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

pub(super) fn static_url(
    configured: Option<&str>,
    path: &str,
    request: Option<&AuthRequest>,
    from_environment: Option<&str>,
    trusted_proxy_headers: bool,
) -> Result<Option<String>, String> {
    if let Some(value) = configured
        .filter(|value| !value.is_empty())
        .or(from_environment.filter(|value| !value.is_empty()))
    {
        return with_path(value, path).map(Some);
    }
    if let Some(request) = request {
        if trusted_proxy_headers
            && let Some(host) =
                header(&request.headers, "x-forwarded-host").filter(|host| valid_host(host))
            && let Some(protocol) = header(&request.headers, "x-forwarded-proto")
                .filter(|protocol| valid_protocol(protocol))
        {
            // The pinned static resolver ignores malformed forwarded URL pairs.
            if let Ok(value) = with_path(&format!("{protocol}://{host}"), path) {
                return Ok(Some(value));
            }
        }
        let origin = request
            .url()
            .and_then(|url| origin(url.as_str()))
            .ok_or_else(|| {
                "Could not get origin from request. Please provide a valid base URL.".to_owned()
            })?;
        return with_path(&origin, path).map(Some);
    }
    Ok(None)
}

pub(super) fn dynamic_url(
    configured: &DynamicBaseUrl,
    path: &str,
    source: Option<Source<'_>>,
    trusted_proxy_headers: bool,
) -> Result<String, String> {
    let fallback = configured
        .fallback
        .as_deref()
        .filter(|value| !value.is_empty());
    let Some(source) = source else {
        return fallback
            .map(|value| with_path(value, path))
            .unwrap_or_else(|| {
                Err(
                    "Could not resolve base URL from request. Check your allowedHosts config."
                        .to_owned(),
                )
            });
    };
    let Some(host) = source_host(source, trusted_proxy_headers) else {
        return fallback.map(|value| with_path(value, path)).unwrap_or_else(|| Err(
            "Could not determine host from request headers. Please provide a fallback URL in your baseURL config.".to_owned()
        ));
    };
    if configured
        .allowed_hosts
        .iter()
        .any(|pattern| host_matches(&host, pattern))
    {
        let protocol = source_protocol(source, configured.protocol, trusted_proxy_headers);
        return with_path(&format!("{protocol}://{host}"), path);
    }
    fallback.map(|value| with_path(value, path)).unwrap_or_else(|| Err(format!(
        "Host \"{host}\" is not in the allowed hosts list. Allowed hosts: {}. Add this host to your allowedHosts config or provide a fallback URL.",
        configured.allowed_hosts.join(", ")
    )))
}

fn source_host(source: Source<'_>, trust_proxy: bool) -> Option<String> {
    if trust_proxy
        && let Some(host) =
            header(source.headers(), "x-forwarded-host").filter(|host| valid_host(host))
    {
        return Some(host.to_owned());
    }
    if let Some(host) = header(source.headers(), "host").filter(|host| valid_host(host)) {
        return Some(host.to_owned());
    }
    source
        .request()?
        .url()
        .map(|url| url[Position::BeforeHost..Position::AfterPort].to_owned())
        .filter(|host| !host.is_empty())
}

fn source_protocol(
    source: Source<'_>,
    protocol: Option<BaseUrlProtocol>,
    trust_proxy: bool,
) -> &'static str {
    match protocol {
        Some(BaseUrlProtocol::Http) => return "http",
        Some(BaseUrlProtocol::Https) => return "https",
        Some(BaseUrlProtocol::Auto) | None => {}
    }
    if trust_proxy && let Some(protocol) = header(source.headers(), "x-forwarded-proto") {
        match protocol {
            "http" => return "http",
            "https" => return "https",
            _ => {}
        }
    }
    if let Some(url) = source.request().and_then(AuthRequest::url) {
        match url.scheme() {
            "http" => return "http",
            "https" => return "https",
            _ => {}
        }
    }
    if source_host(source, trust_proxy).is_some_and(|host| development_loopback(&host)) {
        "http"
    } else {
        "https"
    }
}

fn valid_protocol(value: &str) -> bool {
    matches!(value, "http" | "https")
}

#[expect(
    clippy::expect_used,
    reason = "The constant proxy-host expression is valid"
)]
fn valid_host(value: &str) -> bool {
    static HOST: OnceLock<Regex> = OnceLock::new();
    let host = HOST.get_or_init(|| Regex::new(concat!(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?::[0-9]{1,5})?",
        r"|(?:\d{1,3}\.){3}\d{1,3}(?::[0-9]{1,5})?|\[[0-9a-fA-F:]+\](?::[0-9]{1,5})?)$"
    )).expect("constant proxy-host expression"));
    !value.contains("..") && host.is_match(value)
}

fn normalize_host(value: &str) -> String {
    value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

#[expect(
    clippy::expect_used,
    reason = "Host expressions contain only escaped literals and fixed wildcard fragments"
)]
fn host_matches(host: &str, pattern: &str) -> bool {
    let host = normalize_host(host);
    let pattern = normalize_host(pattern);
    if host.is_empty() || pattern.is_empty() {
        return false;
    }
    let mut expression = String::from("^");
    let mut chars = pattern.chars();
    while let Some(character) = chars.next() {
        match character {
            '*' => expression.push_str(r"[^/\\]*?"),
            '?' => expression.push_str(r"[^/\\]"),
            '\\' => {
                if let Some(escaped) = chars.next() {
                    expression.push_str(&regex::escape(&escaped.to_string()));
                }
            }
            literal => expression.push_str(&regex::escape(&literal.to_string())),
        }
    }
    expression.push_str(r"[/\\]*?$");
    Regex::new(&expression)
        .expect("escaped host expression")
        .is_match(&host)
}

fn development_loopback(host: &str) -> bool {
    let without_port = host
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(host, |(host, _)| host);
    let host = without_port
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    host == "localhost" || host.ends_with(".localhost") || host == "::1" || host.starts_with("127.")
}

pub(super) fn trusted_loopback(host: &str) -> bool {
    let host = host.trim();
    let without_port = if host.starts_with('[') {
        host.find(']')
            .and_then(|index| host.get(..=index))
            .unwrap_or(host)
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    let host = without_port
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split('%')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => address.is_loopback(),
        Ok(std::net::IpAddr::V6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_loopback())
        }
        Err(_) => false,
    }
}

pub(super) fn base_origins(configured: &BaseUrl) -> Vec<String> {
    match configured {
        BaseUrl::Dynamic(configured) => {
            let mut values = Vec::new();
            for host in &configured.allowed_hosts {
                if host.contains("://") {
                    values.push(host.clone());
                    continue;
                }
                if configured.protocol != Some(BaseUrlProtocol::Http) {
                    values.push(format!("https://{host}"));
                }
                if matches!(
                    configured.protocol,
                    Some(BaseUrlProtocol::Http | BaseUrlProtocol::Auto)
                ) || trusted_loopback(host)
                {
                    values.push(format!("http://{host}"));
                }
            }
            values.extend(configured.fallback.as_deref().and_then(origin));
            values
        }
        BaseUrl::Static(value) => origin(value).into_iter().collect(),
        BaseUrl::Auto => Vec::new(),
    }
}
