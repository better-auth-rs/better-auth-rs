use serde::{Deserialize, Serialize};

use crate::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};

/// Error policy for HTTP endpoint invocation and the default error page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiErrorConfig {
    /// Rethrow ordinary errors before invoking the optional error callback.
    #[serde(rename = "throw", skip_serializing_if = "Option::is_none")]
    pub throw_errors: Option<bool>,
    /// Error-page redirect and OAuth's default error destination.
    #[serde(rename = "errorURL")]
    pub error_url: Option<String>,
    /// An explicit empty customization also enables the HTML page in production.
    pub customize_default_error_page: Option<ErrorPageCustomization>,
}

/// Trusted application-provided CSS values for the default error page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ErrorPageCustomization {
    pub colors: ErrorPageColors,
    pub size: ErrorPageSize,
    pub font: ErrorPageFont,
    pub disable_title_border: bool,
    pub disable_corner_decorations: bool,
    pub disable_background_grid: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ErrorPageColors {
    pub background: Option<String>,
    pub foreground: Option<String>,
    pub primary: Option<String>,
    pub primary_foreground: Option<String>,
    pub muted_foreground: Option<String>,
    pub border: Option<String>,
    pub destructive: Option<String>,
    pub title_border: Option<String>,
    pub title_color: Option<String>,
    pub grid_color: Option<String>,
    pub card_background: Option<String>,
    pub corner_border: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ErrorPageSize {
    pub radius_sm: Option<String>,
    /// Accepted by upstream but unused by its current error-page renderer.
    pub radius_md: Option<String>,
    /// Accepted by upstream but unused by its current error-page renderer.
    pub radius_lg: Option<String>,
    pub text_sm: Option<String>,
    pub text2xl: Option<String>,
    pub text4xl: Option<String>,
    pub text6xl: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ErrorPageFont {
    pub default_family: Option<String>,
    pub mono_family: Option<String>,
}

impl<S: AuthSchema> AuthContext<S> {
    /// Render `/error` from the original Request URL, including duplicate-query ordering.
    pub fn error_page_response(&self, request: &AuthRequest) -> AuthResult<AuthResponse> {
        let http =
            crate::hooks::current_request_hook_context().is_some_and(|context| context.is_http);
        let original = if http {
            Some(request)
        } else {
            request.original_request()
        };
        let url = original
            .and_then(AuthRequest::url)
            .ok_or_else(|| AuthError::internal("Invalid URL"))?;
        let code = url
            .query_pairs()
            .find(|(name, _)| name == "error")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default();
        let code = if super::error_page::valid_error_code(&code) {
            &code
        } else {
            "UNKNOWN"
        };
        let description = url
            .query_pairs()
            .find(|(name, _)| name == "error_description")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty());
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let _ = params.append_pair("error", code);
        if let Some(description) = &description {
            let _ = params.append_pair("error_description", description);
        }
        let params = params.finish();
        let policy = &self.config.api_error;
        if let Some(target) = policy
            .error_url
            .as_deref()
            .filter(|target| !target.is_empty())
        {
            return Ok(AuthResponse::new(302).with_header(
                "location",
                crate::utils::url::append_query_params(target, &params)?,
            ));
        }
        if self.is_production()? && policy.customize_default_error_page.is_none() {
            return Ok(AuthResponse::new(302).with_header("location", format!("/?{params}")));
        }
        Ok(AuthResponse::html(
            200,
            super::error_page::render(
                code,
                description.as_deref(),
                policy.customize_default_error_page.as_ref(),
            ),
        )
        .with_header("content-type", "text/html"))
    }
}
