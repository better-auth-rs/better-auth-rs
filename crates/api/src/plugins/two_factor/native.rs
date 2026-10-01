use super::{TwoFactorConfig, TwoFactorPlugin, request};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, HttpMethod, NativeRequest,
};
use serde_json::Value;

/// Server-only Two Factor endpoints bound to this instance's registered options.
/// These operations have no public HTTP routes.
pub struct TwoFactorApi<'a, S: AuthSchema> {
    plugin: TwoFactorPlugin,
    context: &'a AuthContext<S>,
    source: NativeRequest<'a>,
}
impl<'a, S: AuthSchema> TwoFactorApi<'a, S> {
    /// Bind to the plugin configuration installed on this auth instance.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let config = context
            .extensions
            .get::<TwoFactorConfig>()
            .ok_or_else(|| AuthError::config("TwoFactorPlugin is not registered"))?;
        Ok(Self {
            plugin: TwoFactorPlugin::with_config(config.clone()),
            context,
            source: NativeRequest::default(),
        })
    }
    /// Preserve an explicit native Request for dynamic runtime resolution.
    pub fn with_request(mut self, source: NativeRequest<'a>) -> Self {
        self.source = source;
        self
    }
    fn request(&self, path: &str, body: Option<Value>) -> AuthResult<AuthRequest> {
        let mut request = AuthRequest::new(HttpMethod::Post, path)
            .with_optional_headers(self.source.headers.cloned());
        if let Some(original) = self.source.request {
            request = request.with_original_request(original.clone());
        }
        request.body = body.map(|body| serde_json::to_vec(&body)).transpose()?;
        Ok(request)
    }
    /// Validate a native body and generate a TOTP using the registered digit and period options.
    pub async fn generate_totp(&self, body: Option<Value>) -> AuthResult<String> {
        self.context
            .with_native_context(self.source, |_| async move {
                let request = self.request("generateTOTP", body)?;
                let body: request::GenerateTotpRequest = request::read(&request, false)?;
                self.plugin.generate_totp(&body.secret)
            })
            .await
    }
    /// Validate and coerce the supplied user ID, then read the stored backup codes.
    pub async fn view_backup_codes(&self, body: Option<Value>) -> AuthResult<Vec<String>> {
        self.context
            .with_native_context(self.source, |context| async move {
                let request = self.request("viewBackupCodes", body)?;
                let body: request::ViewBackupCodesRequest = request::read(&request, false)?;
                self.plugin.view_backup_codes(&body.user_id, &context).await
            })
            .await
    }
}
