use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::entity::{AuthAccount, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use crate::plugins::helpers::user_has_password;

use super::StatusResponse;

/// Account management plugin for listing and unlinking user accounts.
pub struct AccountManagementPlugin {
    config: AccountManagementConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "AccountManagementPlugin")]
pub struct AccountManagementConfig {
    #[config(default = true)]
    pub require_authentication: bool,
}

#[derive(Debug, Deserialize, Validate)]
struct UnlinkAccountRequest {
    #[serde(rename = "providerId")]
    #[validate(length(min = 1, message = "Provider ID is required"))]
    provider_id: String,
    #[serde(rename = "accountId")]
    account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountResponse {
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
    scopes: Vec<String>,
}

better_auth_core::impl_auth_plugin! {
    AccountManagementPlugin, "account-management";
    routes {
        get "/list-accounts" => handle_list_accounts, "list_accounts";
        post "/unlink-account" => handle_unlink_account, "unlink_account";
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn list_accounts_core(
    user: &better_auth_core::User,
    ctx: &AuthContext,
) -> AuthResult<Vec<AccountResponse>> {
    let accounts = ctx.database.get_user_accounts(user.id()).await?;

    let filtered: Vec<AccountResponse> = accounts
        .iter()
        .map(|acc| AccountResponse {
            id: acc.id().to_string(),
            account_id: acc.account_id().to_string(),
            provider_id: acc.provider_id().to_string(),
            user_id: acc.user_id().to_string(),
            created_at: acc.created_at().to_rfc3339(),
            updated_at: acc.updated_at().to_rfc3339(),
            scopes: acc
                .scope()
                .map(|s| {
                    s.split([' ', ','])
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    let mut filtered = filtered;
    filtered.sort_by(|left, right| left.created_at.cmp(&right.created_at));

    Ok(filtered)
}

pub(crate) async fn unlink_account_core(
    user: &better_auth_core::User,
    provider_id: &str,
    account_id: Option<&str>,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    let accounts = ctx.database.get_user_accounts(user.id()).await?;

    let allow_unlinking_all = ctx.config.account.account_linking.allow_unlinking_all;

    // Check if user has a password (credential provider)
    let has_password = user_has_password(ctx, user).await?;

    // Count remaining credentials after unlinking
    let remaining_accounts = accounts
        .iter()
        .filter(|acc| {
            if acc.provider_id() != provider_id {
                return true;
            }
            match account_id {
                Some(account_id) => acc.account_id() != account_id,
                None => false,
            }
        })
        .count();

    // Prevent unlinking the last credential (unless allow_unlinking_all is true)
    if !allow_unlinking_all && !has_password && remaining_accounts == 0 {
        return Err(AuthError::bad_request(
            "Cannot unlink the last account. You must have at least one authentication method.",
        ));
    }

    // Find and delete the account
    let account_to_remove = accounts
        .iter()
        .find(|acc| {
            if acc.provider_id() != provider_id {
                return false;
            }
            match account_id {
                Some(account_id) => acc.account_id() == account_id,
                None => true,
            }
        })
        .ok_or_else(|| AuthError::not_found("No account found with this provider"))?;

    ctx.database.delete_account(account_to_remove.id()).await?;

    Ok(StatusResponse { status: true })
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl AccountManagementPlugin {
    async fn handle_list_accounts(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let filtered = list_accounts_core(&user, ctx).await?;
        Ok(AuthResponse::json(200, &filtered)?)
    }

    async fn handle_unlink_account(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;

        let unlink_req: UnlinkAccountRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = unlink_account_core(
            &user,
            &unlink_req.provider_id,
            unlink_req.account_id.as_deref(),
            ctx,
        )
        .await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;

    use axum::Json;
    use axum::extract::State;
    use better_auth_core::{AuthState, CurrentSession, ValidatedJson};

    async fn handle_list_accounts(
        State(state): State<AuthState>,
        CurrentSession { user, .. }: CurrentSession,
    ) -> Result<Json<Vec<AccountResponse>>, AuthError> {
        let ctx = state.to_context();
        let accounts = list_accounts_core(&user, &ctx).await?;
        Ok(Json(accounts))
    }

    async fn handle_unlink_account(
        State(state): State<AuthState>,
        CurrentSession { user, .. }: CurrentSession,
        ValidatedJson(body): ValidatedJson<UnlinkAccountRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let response =
            unlink_account_core(&user, &body.provider_id, body.account_id.as_deref(), &ctx).await?;
        Ok(Json(response))
    }

    impl better_auth_core::AxumPlugin for AccountManagementPlugin {
        fn name(&self) -> &'static str {
            "account-management"
        }

        fn router(&self) -> axum::Router<AuthState> {
            use axum::routing::{get, post};

            axum::Router::new()
                .route("/list-accounts", get(handle_list_accounts))
                .route("/unlink-account", post(handle_unlink_account))
        }
    }
}
