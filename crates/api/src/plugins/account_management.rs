use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::entity::{AuthAccount, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

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
    #[serde(rename = "accountId")]
    account_id: String,
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
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<AccountResponse>> {
    let accounts = ctx.database.get_user_accounts(&user.id()).await?;

    let filtered: Vec<AccountResponse> = accounts
        .iter()
        .map(|acc| AccountResponse {
            id: acc.id().to_string(),
            account_id: acc.account_id().to_string(),
            provider_id: acc.provider_id().to_string(),
            user_id: acc.user_id().to_string(),
            created_at: acc
                .created_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            updated_at: acc
                .updated_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
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
    user: &impl AuthUser,
    account_id: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let accounts = ctx.database.get_user_accounts(&user.id()).await?;
    if accounts.len() == 1 && !ctx.config.account.account_linking.allow_unlinking_all {
        return Err(AuthError::bad_request("You can't unlink your last account"));
    }
    let account = accounts
        .iter()
        .find(|account| account.id() == account_id)
        .ok_or_else(|| AuthError::bad_request("Account not found"))?;
    ctx.database.delete_account(&account.id()).await?;
    Ok(StatusResponse { status: true })
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl AccountManagementPlugin {
    async fn handle_list_accounts(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let filtered = list_accounts_core(&user, ctx).await?;
        Ok(AuthResponse::json(200, &filtered)?)
    }

    async fn handle_unlink_account(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_fresh_session(req).await?;

        let unlink_req: UnlinkAccountRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = unlink_account_core(&user, &unlink_req.account_id, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}
