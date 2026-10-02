use std::collections::HashMap;

use crate::{AuthConfig, CookieAttributes, CookieOverride, SameSite};

use super::config::{BaseUrl, BaseUrlProtocol};

/// Cookie policy captured at initialization or an enabled cross-domain rehydration.
#[derive(Debug, Clone)]
pub struct CookieSettings {
    prefix: String,
    secure_prefix: bool,
    domain: Option<String>,
    defaults: CookieAttributes,
    overrides: HashMap<String, CookieOverride>,
}

#[derive(Debug, Clone)]
pub struct ResolvedCookie {
    pub name: String,
    pub attributes: CookieAttributes,
}

impl CookieSettings {
    pub(super) fn from_config(config: &AuthConfig, is_production: bool) -> Self {
        let secure_prefix =
            config
                .advanced
                .use_secure_cookies
                .unwrap_or_else(|| match &config.base_url {
                    BaseUrl::Dynamic(policy) if policy.protocol == Some(BaseUrlProtocol::Http) => {
                        false
                    }
                    BaseUrl::Dynamic(policy) if policy.protocol == Some(BaseUrlProtocol::Https) => {
                        true
                    }
                    BaseUrl::Static(value) if !value.is_empty() => value.starts_with("https://"),
                    BaseUrl::Auto | BaseUrl::Static(_) | BaseUrl::Dynamic(_) => is_production,
                });
        let domain = if config
            .advanced
            .cross_sub_domain_cookies
            .as_ref()
            .is_some_and(|policy| policy.enabled())
        {
            let explicit = config
                .advanced
                .cross_sub_domain_cookies
                .as_ref()
                .and_then(|policy| policy.domain.as_deref())
                .filter(|domain| !domain.is_empty());
            explicit.map(str::to_owned).or_else(|| {
                config
                    .base_url
                    .as_static()
                    .filter(|value| !value.is_empty())
                    .and_then(|value| url::Url::parse(value).ok())
                    .and_then(|url| url.host_str().map(str::to_owned))
            })
        } else {
            None
        };
        Self {
            prefix: config
                .advanced
                .cookie_prefix
                .as_deref()
                .filter(|prefix| !prefix.is_empty())
                .unwrap_or("better-auth")
                .to_owned(),
            secure_prefix,
            domain,
            defaults: config.advanced.default_cookie_attributes.clone(),
            overrides: config.advanced.cookies.clone().unwrap_or_default(),
        }
    }

    pub(crate) fn logical_name<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.overrides
            .iter()
            .find_map(|(logical, _)| {
                (self.get(logical, Default::default()).name == name).then_some(logical.as_str())
            })
            .or_else(|| {
                name.strip_prefix(if self.secure_prefix { "__Secure-" } else { "" })
                    .and_then(|name| name.strip_prefix(&self.prefix))
                    .and_then(|name| name.strip_prefix('.'))
            })
    }

    /// Resolve a logical cookie without signing, writing, or clearing values.
    pub fn get(&self, logical_name: &str, caller: CookieAttributes) -> ResolvedCookie {
        let override_ = self.overrides.get(logical_name);
        let name = override_
            .and_then(|value| value.name.as_deref())
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}.{logical_name}", self.prefix));
        let mut attributes = CookieAttributes {
            secure: Some(self.secure_prefix),
            partitioned: None,
            http_only: Some(true),
            same_site: Some(SameSite::Lax),
            path: Some("/".to_owned()),
            domain: self.domain.clone(),
            max_age: None,
            expires: None,
        };
        overlay(&mut attributes, &self.defaults);
        overlay(&mut attributes, &caller);
        if let Some(override_) = override_ {
            overlay(&mut attributes, &override_.attributes);
        }
        ResolvedCookie {
            name: if self.secure_prefix {
                format!("__Secure-{name}")
            } else {
                name
            },
            attributes,
        }
    }
}

fn overlay(target: &mut CookieAttributes, source: &CookieAttributes) {
    if let Some(value) = source.expires {
        target.expires = Some(value);
    }
    if let Some(value) = source.secure {
        target.secure = Some(value);
    }
    if let Some(value) = source.partitioned {
        target.partitioned = Some(value);
    }
    if let Some(value) = source.http_only {
        target.http_only = Some(value);
    }
    if let Some(value) = &source.same_site {
        target.same_site = Some(value.clone());
    }
    if let Some(value) = &source.path {
        target.path = Some(value.clone());
    }
    if let Some(value) = source.max_age {
        target.max_age = Some(value);
    }
    if let Some(value) = &source.domain {
        target.domain = Some(value.clone());
    }
}

impl AuthConfig {
    /// Resolve a logical cookie with global, caller, and per-cookie attributes.
    pub fn auth_cookie(&self, name: &str, attributes: CookieAttributes) -> ResolvedCookie {
        self.cookie_settings().get(name, attributes)
    }

    pub(crate) fn cookie_settings(&self) -> std::borrow::Cow<'_, CookieSettings> {
        self.resolved_cookies.as_ref().map_or_else(
            || std::borrow::Cow::Owned(CookieSettings::from_config(self, false)),
            std::borrow::Cow::Borrowed,
        )
    }

    pub(crate) fn install_cookie_settings(&mut self, settings: CookieSettings) {
        self.resolved_cookies = Some(settings);
    }
}
