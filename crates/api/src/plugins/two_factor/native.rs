use super::{TwoFactorConfig, TwoFactorPlugin, request};
use better_auth_core::{
    AuthContext, AuthError, AuthResponse, AuthResult, AuthRoute, AuthSchema, HttpMethod,
    NativeRequest,
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
    /// Validate a native body and generate a TOTP using the registered digit and period options.
    pub async fn generate_totp(&self, body: Option<Value>) -> AuthResult<String> {
        let route = AuthRoute::server_only(HttpMethod::Post, "generateTOTP")
            .body_validator(|request| request::validate_native(request, "generateTOTP"));
        let response = self
            .context
            .dispatch_native(self.source, route, body, None, |request, _| async move {
                let body = request
                    .validated_body::<request::GenerateTotpRequest>()
                    .ok_or_else(|| AuthError::internal("Missing validated TOTP input"))?;
                AuthResponse::json(
                    200,
                    &serde_json::json!({"code":self.plugin.generate_totp(&body.secret)?}),
                )
                .map_err(Into::into)
            })
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            code: String,
        }
        Ok(serde_json::from_slice::<Result>(&response.body.bytes()?)?.code)
    }
    /// Validate and coerce the supplied user ID, then read the stored backup codes.
    pub async fn view_backup_codes(&self, body: Option<Value>) -> AuthResult<Vec<String>> {
        let route = AuthRoute::server_only(HttpMethod::Post, "viewBackupCodes")
            .body_validator(|request| request::validate_native(request, "viewBackupCodes"));
        let response = self
            .context
            .dispatch_native(
                self.source,
                route,
                body,
                None,
                |request, context| async move {
                    let body = request
                        .validated_body::<request::ViewBackupCodesRequest>()
                        .ok_or_else(|| {
                            AuthError::internal("Missing validated backup code input")
                        })?;
                    let codes = self
                        .plugin
                        .view_backup_codes(&body.user_id, &context)
                        .await?;
                    AuthResponse::json(200, &serde_json::json!({"status":true,"backupCodes":codes}))
                        .map_err(Into::into)
                },
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Result {
            #[serde(rename = "backupCodes")]
            backup_codes: Vec<String>,
        }
        Ok(serde_json::from_slice::<Result>(&response.body.bytes()?)?.backup_codes)
    }
}
