use better_auth_core::{AuthContext, AuthRequest, AuthResult, AuthSchema};
use url::{Origin, Url};

use super::{OAuthProxyConfig, parse_url};

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn vendor_url() -> Option<String> {
    env_value("VERCEL_URL")
        .map(|host| format!("https://{host}"))
        .or_else(|| {
            [
                "NETLIFY_URL",
                "RENDER_URL",
                "AWS_LAMBDA_FUNCTION_NAME",
                "GOOGLE_CLOUD_FUNCTION_NAME",
                "AZURE_FUNCTION_NAME",
            ]
            .into_iter()
            .find_map(env_value)
        })
}

fn origin(value: &str) -> Option<Origin> {
    Url::parse(value)
        .ok()
        .map(|url| url.origin())
        .filter(|origin| matches!(origin, Origin::Tuple(..)))
}

fn request_url<S: AuthSchema>(req: &AuthRequest, ctx: &AuthContext<S>) -> Option<String> {
    let scheme = Url::parse(&ctx.config.base_url).ok()?;
    req.headers
        .get("host")
        .map(|host| format!("{}://{host}", scheme.scheme()))
}

impl OAuthProxyConfig {
    pub(super) fn resolve_current_url<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Url> {
        if let Some(url) = self.current_url.as_deref().filter(|url| !url.is_empty()) {
            return parse_url(url);
        }
        if let Some(url) = request_url(req, ctx)
            && let Some(origin) = origin(&url)
            && ctx
                .config
                .is_redirect_target_trusted(&origin.ascii_serialization())
        {
            return parse_url(&url);
        }
        // Upstream selects the first nonempty vendor value before validating its origin.
        let vendor = vendor_url().filter(|url| origin(url).is_some());
        parse_url(vendor.as_deref().unwrap_or(&ctx.config.base_url))
    }

    pub(super) fn skip_proxy<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> bool {
        if req
            .headers
            .get("x-skip-oauth-proxy")
            .is_some_and(|value| !value.is_empty())
        {
            return true;
        }
        let production_env = env_value("BETTER_AUTH_URL");
        let production = self
            .production_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .or(production_env.as_deref())
            .unwrap_or(&ctx.config.base_url);
        let current = self
            .current_url
            .clone()
            .filter(|url| !url.is_empty())
            .or_else(|| request_url(req, ctx))
            .or_else(vendor_url);
        current.is_some_and(|current| origin(production) == origin(&current))
    }
}
