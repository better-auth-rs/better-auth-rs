use async_trait::async_trait;

use crate::core::{AuthPlugin, AuthRoute, AuthContext, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use crate::error::AuthResult;

/// Two-factor authentication plugin
pub struct TwoFactorPlugin {
    // TODO: Add 2FA configuration
}

impl TwoFactorPlugin {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for TwoFactorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthPlugin for TwoFactorPlugin {
    fn name(&self) -> &'static str {
        "two-factor"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/2fa/setup", "setup_2fa"),
            AuthRoute::post("/2fa/verify", "verify_2fa"),
            AuthRoute::post("/2fa/disable", "disable_2fa"),
        ]
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_database: true,
            ..PluginCapabilities::default()
        }
    }
    
    async fn on_request(&self, req: &AuthRequest, _ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, path) if path.starts_with("/2fa/") => {
                // TODO: Implement 2FA flows
                Ok(Some(AuthResponse::json(501, &serde_json::json!({
                    "error": "Not implemented", 
                    "message": "Two-factor authentication plugin not yet implemented"
                }))?))
            },
            _ => Ok(None),
        }
    }
} 
