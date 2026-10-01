//! Instance-specific schema generation and the upstream Scalar reference page.

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod, OpenApiSpec, openapi::OpenApiRegistry,
};

#[derive(better_auth_core::PluginConfig)]
#[plugin(name = "OpenApiPlugin")]
pub struct OpenApiConfig {
    /// HTTP path for the Scalar reference page.
    #[config(default = "/reference".to_owned())]
    pub path: String,
    /// Keep the reference endpoint registered but return an empty 404 response.
    #[config(default = false)]
    pub disable_default_reference: bool,
    /// Scalar theme. An empty value selects the upstream default.
    #[config(default = None)]
    pub theme: Option<String>,
    /// Nonce applied to the two executable scripts.
    #[config(default = None)]
    pub nonce: Option<String>,
}

pub struct OpenApiPlugin {
    config: OpenApiConfig,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OpenApiPlugin {
    fn name(&self) -> &'static str {
        "open-api"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/open-api/generate-schema", "generateOpenAPISchema"),
            AuthRoute::get(&self.config.path, "openAPIReference"),
        ]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.method() != &HttpMethod::Get {
            return Ok(None);
        }
        if request.path() == "/open-api/generate-schema" {
            let mut response =
                AuthResponse::new(200).with_header("content-type", "application/json");
            response.body =
                better_auth_core::utils::json::stringify(&schema(context)?.to_value()?)?
                    .into_bytes();
            return Ok(Some(response));
        }
        if request.path() != self.config.path {
            return Ok(None);
        }
        if self.config.disable_default_reference {
            return Err(AuthResponse::new(404)
                .with_header("content-type", "application/json")
                .into());
        }
        let html = reference_html(&schema(context)?, &self.config)?;
        let mut response = AuthResponse::html(200, html);
        let _ = response.headers.insert("content-type", "text/html");
        Ok(Some(response))
    }
}

fn schema(context: &AuthContext<impl AuthSchema>) -> AuthResult<OpenApiSpec> {
    context
        .extensions
        .get::<OpenApiRegistry>()
        .map(|registry| registry.generate(context.base_url()))
        .ok_or_else(|| AuthError::config("OpenAPI registry is not initialized"))
}

fn reference_html(spec: &OpenApiSpec, config: &OpenApiConfig) -> AuthResult<String> {
    let nonce = config
        .nonce
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| format!("nonce=\"{value}\""))
        .unwrap_or_default();
    let theme = config
        .theme
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("default");
    // Upstream treats theme and nonce as trusted application configuration.
    Ok(format!(
        include_str!("reference.html"),
        schema = better_auth_core::utils::json::stringify(&spec.to_value()?)?,
        // Preserve the upstream template's mixed indentation in the response bytes.
        favicon_indent = "\t  \t",
        theme_indent = "\t   \t",
        theme = theme,
        nonce = nonce,
    ))
}
