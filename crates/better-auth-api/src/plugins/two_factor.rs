use async_trait::async_trait;

use better_auth_core::DatabaseAdapter;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

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
impl<DB: DatabaseAdapter> AuthPlugin<DB> for TwoFactorPlugin {
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

    async fn on_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, path) if path.starts_with("/2fa/") => Err(
                AuthError::not_implemented("Two-factor authentication plugin not yet implemented"),
            ),
            _ => Ok(None),
        }
    }
}
