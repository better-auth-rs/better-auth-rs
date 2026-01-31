use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::{AuthPlugin, AuthRoute, AuthContext, SessionManager};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod, User, Session, Account};
use better_auth_core::{AuthError, AuthResult};

/// Account management plugin for listing and unlinking user accounts.
pub struct AccountManagementPlugin {
    config: AccountManagementConfig,
}

#[derive(Debug, Clone)]
pub struct AccountManagementConfig {
    pub require_authentication: bool,
}

#[derive(Debug, Deserialize, Validate)]
struct UnlinkAccountRequest {
    #[serde(rename = "providerId")]
    #[validate(length(min = 1, message = "Provider ID is required"))]
    provider_id: String,
}

#[derive(Debug, Serialize)]
struct AccountResponse {
    id: String,
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

impl AccountManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: AccountManagementConfig::default(),
        }
    }

    pub fn with_config(config: AccountManagementConfig) -> Self {
        Self { config }
    }

    pub fn require_authentication(mut self, require: bool) -> Self {
        self.config.require_authentication = require;
        self
    }
}

impl Default for AccountManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AccountManagementConfig {
    fn default() -> Self {
        Self {
            require_authentication: true,
        }
    }
}

#[async_trait]
impl AuthPlugin for AccountManagementPlugin {
    fn name(&self) -> &'static str {
        "account-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/list-accounts", "list_accounts"),
            AuthRoute::post("/unlink-account", "unlink_account"),
        ]
    }

    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/list-accounts") => {
                Ok(Some(self.handle_list_accounts(req, ctx).await?))
            },
            (HttpMethod::Post, "/unlink-account") => {
                Ok(Some(self.handle_unlink_account(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

impl AccountManagementPlugin {
    async fn require_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<(User, Session)> {
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());

        if let Some(token) = session_manager.extract_session_token(req) {
            if let Some(session) = session_manager.get_session(&token).await? {
                if let Some(user) = ctx.database.get_user_by_id(&session.user_id).await? {
                    return Ok((user, session));
                }
            }
        }

        Err(AuthError::Unauthenticated)
    }

    async fn handle_list_accounts(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;

        let accounts = ctx.database.get_user_accounts(&user.id).await?;

        // Filter sensitive fields (password, tokens)
        let filtered: Vec<AccountResponse> = accounts.iter().map(|acc| AccountResponse {
            id: acc.id.clone(),
            account_id: acc.account_id.clone(),
            provider_id: acc.provider_id.clone(),
            user_id: acc.user_id.clone(),
            created_at: acc.created_at.to_rfc3339(),
            updated_at: acc.updated_at.to_rfc3339(),
            scope: acc.scope.clone(),
        }).collect();

        Ok(AuthResponse::json(200, &filtered)?)
    }

    async fn handle_unlink_account(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let (user, _session) = self.require_session(req, ctx).await?;

        let unlink_req: UnlinkAccountRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let accounts = ctx.database.get_user_accounts(&user.id).await?;

        // Check if user has a password (credential provider)
        let has_password = user.metadata.get("password_hash")
            .and_then(|v| v.as_str())
            .is_some();

        // Count remaining credentials after unlinking
        let remaining_accounts = accounts.iter()
            .filter(|acc| acc.provider_id != unlink_req.provider_id)
            .count();

        // Prevent unlinking the last credential
        if !has_password && remaining_accounts == 0 {
            return Err(AuthError::bad_request(
                "Cannot unlink the last account. You must have at least one authentication method."
            ));
        }

        // Find and delete the account
        let account_to_remove = accounts.iter()
            .find(|acc| acc.provider_id == unlink_req.provider_id)
            .ok_or_else(|| AuthError::not_found("No account found with this provider"))?;

        ctx.database.delete_account(&account_to_remove.id).await?;

        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
}
