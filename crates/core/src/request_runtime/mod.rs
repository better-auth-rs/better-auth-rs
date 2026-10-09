//! Request-specific URL, trust, and cookie policy.

mod config;
mod cookies;
mod scope;
mod url;

pub use config::{BaseUrl, BaseUrlProtocol, DynamicBaseUrl, TrustedValues, TrustedValuesResolver};
pub use cookies::{CookieSettings, ResolvedCookie};
pub(crate) use scope::{Identity as RuntimeIdentity, spawn as spawn_with_request_context};

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use self::url::Source;
use crate::{
    AuthConfig, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    CookieAttributes, HttpMethod,
};

/// Original native Request and separately supplied endpoint headers.
#[derive(Clone, Copy, Default)]
pub struct NativeRequest<'a> {
    pub request: Option<&'a AuthRequest>,
    pub headers: Option<&'a HashMap<String, String>>,
}

#[derive(Clone, Default)]
pub(crate) struct RequestRuntime {
    identity: scope::Identity,
    initial: Arc<tokio::sync::OnceCell<Initialized>>,
    values: Option<RuntimeValues>,
}

#[derive(Clone)]
struct Initialized {
    config: Arc<AuthConfig>,
    values: RuntimeValues,
}

#[derive(Clone)]
struct RuntimeValues {
    base_url: String,
    trusted_origins: Vec<String>,
    trusted_providers: Vec<String>,
    is_production: bool,
}

impl RequestRuntime {
    /// Run before plugin initialization; plugin contributions merge afterward.
    async fn initialize(config: &mut AuthConfig) -> AuthResult<RuntimeValues> {
        if let BaseUrl::Dynamic(policy) = &config.base_url
            && policy.allowed_hosts.is_empty()
        {
            return Err(AuthError::config(
                "baseURL.allowedHosts cannot be empty. Provide at least one allowed host pattern (e.g., [\"myapp.com\", \"*.vercel.app\"]).",
            ));
        }
        let base_url = match &config.base_url {
            BaseUrl::Dynamic(_) => String::new(),
            BaseUrl::Auto | BaseUrl::Static(_) => {
                let environment = url::environment_base_url()?;
                let value = url::static_url(
                    config.base_url.as_static(),
                    &config.base_path,
                    None,
                    environment.as_deref(),
                    false,
                )
                .map_err(AuthError::config)?
                .unwrap_or_default();
                // An omitted static URL becomes a string, including the empty string.
                config.base_url = BaseUrl::Static(url::origin(&value).unwrap_or_default());
                value
            }
        };
        if config.base_path.is_empty() {
            config.base_path = "/api/auth".to_owned();
        }
        let is_production = url::environment("NODE_ENV")?.as_deref() == Some("production");
        let cookies = CookieSettings::from_config(config, is_production);
        if config
            .advanced
            .cross_sub_domain_cookies
            .as_ref()
            .is_some_and(|policy| {
                policy.enabled() && policy.domain.as_deref().is_none_or(str::is_empty)
            })
            && !matches!(config.base_url, BaseUrl::Dynamic(_))
            && config.base_url.as_static().is_none_or(str::is_empty)
        {
            return Err(AuthError::config(
                "baseURL is required when crossSubdomainCookies are enabled.",
            ));
        }
        config.install_cookie_settings(cookies.clone());
        let trusted_origins = origins(config, &config.base_url, None).await?;
        let trusted_providers = config
            .account
            .account_linking
            .trusted_provider_values()
            .resolve(None)
            .await?;
        Ok(RuntimeValues {
            base_url,
            trusted_origins,
            trusted_providers,
            is_production,
        })
    }
}

impl<S: AuthSchema> AuthContext<S> {
    /// Resolve the context active for this auth instance, if one is in scope.
    pub fn current_request_context(&self) -> Option<Arc<Self>> {
        self.request_runtime.identity.current()
    }

    pub fn is_origin_trusted(&self, origin: &str) -> bool {
        self.trusted_origins().iter().any(|pattern| {
            let pattern = crate::config::extract_origin(pattern).unwrap_or_default();
            glob_match::glob_match(&pattern, origin)
        })
    }

    pub fn is_redirect_target_trusted(&self, target: &str) -> bool {
        crate::config::is_safe_relative_path(target)
            || crate::config::extract_origin(target)
                .is_some_and(|origin| self.is_origin_trusted(&origin))
    }

    /// Full resolved authentication URL, including its effective routing path.
    pub fn base_url(&self) -> &str {
        self.request_runtime.values.as_ref().map_or_else(
            || self.config.base_url.as_static().unwrap_or(""),
            |values| values.base_url.as_str(),
        )
    }

    /// Route prefix from the resolved URL, including a configured URL path.
    pub fn base_path(&self) -> &str {
        let url = self.base_url();
        url.find("://")
            .and_then(|scheme| url.get(scheme + 3..))
            .and_then(|authority| authority.find('/').and_then(|start| authority.get(start..)))
            .map(|path| path.split(['?', '#']).next().unwrap_or("/"))
            .unwrap_or(&self.config.base_path)
    }

    pub fn trusted_origins(&self) -> &[String] {
        self.request_runtime.values.as_ref().map_or_else(
            || {
                self.config
                    .trusted_origin_values()
                    .as_static()
                    .unwrap_or(&[])
            },
            |values| values.trusted_origins.as_slice(),
        )
    }

    pub(crate) fn is_production(&self) -> AuthResult<bool> {
        Ok(self.runtime_values()?.is_production)
    }

    pub fn trusted_providers(&self) -> &[String] {
        self.request_runtime.values.as_ref().map_or_else(
            || {
                self.config
                    .account
                    .account_linking
                    .trusted_provider_values()
                    .as_static()
                    .unwrap_or(&[])
            },
            |values| values.trusted_providers.as_slice(),
        )
    }

    pub fn create_auth_cookie(
        &self,
        name: &str,
        attributes: CookieAttributes,
    ) -> AuthResult<ResolvedCookie> {
        Ok(self.config.auth_cookie(name, attributes))
    }

    /// Initialize options once for this auth instance before plugin setup or native use.
    pub async fn initialize_request_context(&self) -> AuthResult<Arc<Self>> {
        if self.request_runtime.values.is_some() {
            return Ok(Arc::new(self.clone()));
        }
        let initial = self
            .request_runtime
            .initial
            .get_or_try_init(|| async {
                let mut config = (*self.config).clone();
                let values = RequestRuntime::initialize(&mut config).await?;
                Ok::<_, AuthError>(Initialized {
                    config: Arc::new(config),
                    values,
                })
            })
            .await?;
        let mut context = self.clone();
        context.config = initial.config.clone();
        context.request_runtime.values = Some(initial.values.clone());
        Ok(Arc::new(context))
    }

    /// Resolve native URL policy and enter this auth instance's runtime scope.
    pub async fn with_native_context<T, F, Fut>(
        &self,
        input: NativeRequest<'_>,
        operation: F,
    ) -> AuthResult<T>
    where
        F: FnOnce(Arc<AuthContext<S>>) -> Fut + Send,
        Fut: Future<Output = AuthResult<T>> + Send,
        T: Send,
    {
        if let Some(validation) = self.database.schema_validation() {
            validation.check_runtime().await?;
        }
        let context = self.initialize_request_context().await?;
        let resolved = if matches!(context.config.base_url, BaseUrl::Dynamic(_))
            && context.base_url().is_empty()
        {
            let source = input.request.map(Source::Request).or_else(|| {
                input
                    .headers
                    .filter(|headers| {
                        url::header(headers, "host").is_some()
                            || url::header(headers, "x-forwarded-host").is_some()
                    })
                    .map(Source::Headers)
            });
            context.resolve_dynamic(source, true).await?
        } else {
            context
        };
        scope::run(resolved.clone(), async move { operation(resolved).await }).await
    }

    /// Enter the HTTP policy branch before rate limiting, request hooks, and body decoding.
    pub async fn with_http_context<T, F, Fut>(
        &self,
        request: &AuthRequest,
        operation: F,
    ) -> AuthResult<T>
    where
        F: FnOnce(Arc<AuthContext<S>>) -> Fut + Send,
        Fut: Future<Output = AuthResult<T>> + Send,
        T: Send,
    {
        let context = self.initialize_request_context().await?;
        let resolved = if matches!(context.config.base_url, BaseUrl::Dynamic(_)) {
            context
                .resolve_dynamic(Some(Source::Request(request)), false)
                .await?
        } else {
            let mut resolved = (*context).clone();
            if context
                .config
                .base_url
                .as_static()
                .is_none_or(str::is_empty)
            {
                let environment = url::environment_base_url()?;
                let base_url = url::static_url(
                    None,
                    &self.config.base_path,
                    Some(request),
                    environment.as_deref(),
                    self.config.advanced.trusted_proxy_headers,
                )
                .map_err(AuthError::config)?
                .ok_or_else(|| {
                    AuthError::config(
                        "Could not get base URL from request. Please provide a valid base URL.",
                    )
                })?;
                resolved.runtime_values_mut()?.base_url = base_url.clone();
                Arc::make_mut(&mut resolved.config).base_url =
                    BaseUrl::Static(url::origin(&base_url).unwrap_or_default());
            }
            resolved.runtime_values_mut()?.trusted_origins =
                origins(&resolved.config, &resolved.config.base_url, Some(request)).await?;
            resolved.runtime_values_mut()?.trusted_providers = resolved
                .config
                .account
                .account_linking
                .trusted_provider_values()
                .resolve(Some(request))
                .await?;
            Arc::new(resolved)
        };
        scope::run(resolved.clone(), async move { operation(resolved).await }).await
    }

    fn runtime_values(&self) -> AuthResult<&RuntimeValues> {
        self.request_runtime
            .values
            .as_ref()
            .ok_or_else(|| AuthError::internal("Request context is not initialized"))
    }

    fn runtime_values_mut(&mut self) -> AuthResult<&mut RuntimeValues> {
        self.request_runtime
            .values
            .as_mut()
            .ok_or_else(|| AuthError::internal("Request context is not initialized"))
    }

    pub(crate) fn runtime_identity(&self) -> RuntimeIdentity {
        self.request_runtime.identity.clone()
    }

    /// The origin middleware calls functional origins again after HTTP resolution.
    pub async fn csrf_trusted_origins(&self, request: &AuthRequest) -> AuthResult<Vec<String>> {
        let mut values = self.trusted_origins().to_vec();
        if self.config.trusted_origin_values().is_dynamic() {
            values.extend(
                self.config
                    .trusted_origin_values()
                    .resolve(Some(request))
                    .await?,
            );
        }
        Ok(values)
    }

    async fn resolve_dynamic(
        &self,
        source: Option<Source<'_>>,
        native: bool,
    ) -> AuthResult<Arc<Self>> {
        let BaseUrl::Dynamic(policy) = &self.config.base_url else {
            return Err(AuthError::internal(
                "Dynamic context resolution requires a dynamic base URL",
            ));
        };
        if native && source.is_none() && policy.fallback.as_deref().is_none_or(str::is_empty) {
            return Err(native_url_error("Dynamic baseURL could not be resolved for this direct auth.api call. Pass `headers: request.headers` (or `request`) to the call, or add `fallback` to your baseURL config.".to_owned()));
        }
        let base_url = url::dynamic_url(
            policy,
            &self.config.base_path,
            source,
            self.config.advanced.trusted_proxy_headers,
        )
        .map_err(|message| {
            if native {
                native_url_error(message)
            } else {
                AuthError::config(message)
            }
        })?;
        let synthetic;
        let request = match source {
            Some(Source::Request(request)) => Some(request),
            Some(Source::Headers(headers)) => {
                let url = ::url::Url::parse(&base_url)
                    .map_err(|error| AuthError::config(error.to_string()))?;
                synthetic = AuthRequest::new(HttpMethod::Get, url.path())
                    .with_optional_headers(Some(headers.clone()))
                    .with_url(url);
                Some(&synthetic)
            }
            None => None,
        };
        let mut resolved = self.clone();
        resolved.runtime_values_mut()?.base_url = base_url.clone();
        Arc::make_mut(&mut resolved.config).base_url =
            BaseUrl::Static(url::origin(&base_url).unwrap_or_default());
        // The source policy still contributes every allowed host, not only this request's host.
        resolved.runtime_values_mut()?.trusted_origins =
            origins(&resolved.config, &self.config.base_url, request).await?;
        resolved.runtime_values_mut()?.trusted_providers = resolved
            .config
            .account
            .account_linking
            .trusted_provider_values()
            .resolve(request)
            .await?;
        if self
            .config
            .advanced
            .cross_sub_domain_cookies
            .as_ref()
            .is_some_and(|policy| policy.enabled())
        {
            let cookies =
                CookieSettings::from_config(&resolved.config, self.runtime_values()?.is_production);
            Arc::make_mut(&mut resolved.config).install_cookie_settings(cookies);
        }
        Ok(Arc::new(resolved))
    }
}

async fn origins(
    config: &AuthConfig,
    base_url: &BaseUrl,
    request: Option<&AuthRequest>,
) -> AuthResult<Vec<String>> {
    let mut values = url::base_origins(base_url);
    values.extend(config.trusted_origin_values().resolve(request).await?);
    if let Some(environment) = url::environment("BETTER_AUTH_TRUSTED_ORIGINS")? {
        values.extend(environment.split(',').map(str::to_owned));
    }
    values.retain(|value| !value.is_empty());
    Ok(values)
}

fn native_url_error(message: String) -> AuthError {
    match AuthResponse::json(500, &serde_json::json!({ "message": message })) {
        Ok(response) => response.into(),
        Err(error) => error,
    }
}

pub(crate) fn current_logger() -> Option<crate::observability::LoggerConfig> {
    scope::current_logger()
}
