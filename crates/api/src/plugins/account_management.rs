use serde::Deserialize;

use better_auth_core::{AuthContext, AuthError, AuthResult, FieldValue};
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

#[derive(Debug, Clone, Deserialize)]
struct UnlinkAccountRequest {
    #[serde(rename = "accountId")]
    account_id: String,
}

fn unlink_account_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (typed, projection) =
        super::json_body::string_input::<UnlinkAccountRequest>(req, &[("accountId", true)])?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        typed,
    ))
}

pub(crate) type AccountResponse = better_auth_core::FieldMap;

better_auth_core::impl_auth_plugin! {
    AccountManagementPlugin, "account-management";
    routes {
        get "/list-accounts" => handle_list_accounts, "listUserAccounts";
        post "/unlink-account" => handle_unlink_account, "unlinkAccount", body = unlink_account_body;
    }
    extra {
        fn telemetry_plugin_id(&self) -> Option<&'static str> {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn list_accounts_core(
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<AccountResponse>> {
    let accounts = ctx.database.get_user_accounts_value(user_id).await?;

    accounts
        .into_iter()
        .map(|account| {
            let mut fields = better_auth_core::StructuredCloneContext::new()
                .clone_map(&account.internal_fields()?)?;
            ctx.config
                .account
                .field_schema()
                .filter_returned_fields(&mut fields);
            let scopes = match fields.remove("scope") {
                Some(value) if better_auth_core::user_fields::is_truthy(&value) => {
                    let scope = value.as_str().ok_or_else(|| {
                        AuthError::internal("account.scope.split is not a function")
                    })?;
                    super::helpers::parse_stored_scopes(Some(scope))
                }
                _ => Vec::new(),
            };
            // The public account endpoint removes credentials even when a replacement schema enables returned.
            for name in [
                "accessToken",
                "refreshToken",
                "idToken",
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
                "password",
                "scope",
            ] {
                let _ = fields.remove(name);
            }
            let _ = fields.insert(
                "scopes".into(),
                scopes
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<better_auth_core::FieldValue>>()
                    .into(),
            );
            Ok(fields)
        })
        .collect()
}

pub(crate) async fn unlink_account_core(
    user_id: &FieldValue,
    account_id: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let accounts = ctx.database.get_user_accounts_value(user_id).await?;
    if accounts.len() == 1 && !ctx.config.account.account_linking.allow_unlinking_all() {
        return Err(AuthError::bad_request("You can't unlink your last account"));
    }
    let account = accounts
        .iter()
        .find(|account| account.id.field_value().strict_equals(&account_id.into()))
        .ok_or_else(|| AuthError::bad_request("Account not found"))?;
    ctx.database
        .delete_account_value(&account.id.field_value())
        .await?;
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
        let data = ctx.require_native_session(req).await?;
        let filtered = list_accounts_core(data.user_field("id"), ctx).await?;
        Ok(AuthResponse::native(
            None,
            filtered
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    }

    async fn handle_unlink_account(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let data = ctx.require_native_session(req).await?;
        if !crate::plugins::helpers::session_is_fresh(&data.session, &ctx.config)? {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_NOT_FRESH",
                message: "Session is not fresh",
            });
        }

        let unlink_req: UnlinkAccountRequest = match req.validated_body::<UnlinkAccountRequest>() {
            Some(body) => body.clone(),
            None => super::json_body::string_input(req, &[("accountId", true)])?.0,
        };

        let response =
            unlink_account_core(data.user_field("id"), &unlink_req.account_id, ctx).await?;
        AuthResponse::json(None, &response)
    }
}
