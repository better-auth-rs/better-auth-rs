use better_auth_core::entity::AuthAccount;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, UpdateAccount,
};
use chrono::Utc;

use super::encryption::{encrypt_token_set, maybe_decrypt};
use super::handlers::{
    create_account_cookie_header, decode_account_cookie, fetch_user_info_from_provider,
    refresh_tokens_via_provider,
};
use super::providers::{OAuthTokenSet, OAuthUserInfoRequest};
use super::resolved::ResolvedOAuthConfig as OAuthConfig;
use super::state::AccountCookiePayload;
use super::types::{
    AccessTokenResponse, AccountInfoAccount, AccountInfoResponse, AccountInfoUser,
    RefreshTokenResponse,
};

enum AccountSelection {
    Id(String),
    Cookie,
}

fn invalid_selection(location: &str, message: String) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(
        400,
        &better_auth_core::ErrorCodeMessageResponse {
            code: Some("VALIDATION_ERROR".into()),
            message: format!("[{location}] {message}"),
        },
    )?)
}

impl AccountSelection {
    fn from_body(req: &AuthRequest) -> Result<Self, String> {
        let value = req.body_as_json().map_err(|_| "Invalid input".to_owned())?;
        Self::from_value(value)
    }

    fn from_query(req: &AuthRequest) -> Result<Self, String> {
        Self::from_value(serde_json::Value::Object(
            req.query
                .iter()
                .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
                .collect(),
        ))
    }

    fn from_value(value: serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "Invalid input".to_owned())?;
        if object.get("userId").is_some_and(|value| !value.is_string()) {
            return Err("Invalid input".into());
        }
        let account_id = object.get("accountId").and_then(serde_json::Value::as_str);
        let use_cookie = object
            .get("useAccountCookie")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let (selection, field) = match (account_id, use_cookie) {
            (Some(id), false) => (Self::Id(id.to_owned()), "accountId"),
            (None, true) => (Self::Cookie, "useAccountCookie"),
            _ => return Err("Invalid input".into()),
        };
        let unknown: Vec<_> = object
            .keys()
            .filter(|key| key.as_str() != field && key.as_str() != "userId")
            .collect();
        if !unknown.is_empty() {
            let suffix = if unknown.len() == 1 { "" } else { "s" };
            let names = unknown
                .into_iter()
                .map(|key| serde_json::Value::String(key.clone()).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!("Unrecognized key{suffix}: {names}"));
        }
        Ok(selection)
    }

    async fn resolve(
        &self,
        req: &AuthRequest,
        user_id: &str,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AccountCookiePayload> {
        let account = match self {
            Self::Id(account_id) => ctx
                .database
                .get_user_accounts(user_id)
                .await?
                .iter()
                .find(|account| account.id().as_ref() == account_id.as_str())
                .map(AccountCookiePayload::from_account),
            Self::Cookie if ctx.config.account.store_account_cookie => {
                decode_account_cookie(req, &ctx.config, &ctx.config.secret)?
                    .filter(|account| account.user_id == user_id)
            }
            Self::Cookie => None,
        };
        account.ok_or_else(|| AuthError::bad_request("Account not found"))
    }
}

fn scopes(account: &AccountCookiePayload) -> Vec<String> {
    account
        .scope
        .as_deref()
        .unwrap_or_default()
        .split([' ', ','])
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn persist_tokens(
    account: &mut AccountCookiePayload,
    tokens: &OAuthTokenSet,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    let encrypted = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )?;
    let update = UpdateAccount {
        access_token: encrypted
            .access_token
            .or_else(|| account.access_token.clone()),
        refresh_token: encrypted
            .refresh_token
            .or_else(|| account.refresh_token.clone()),
        id_token: encrypted.id_token.or_else(|| account.id_token.clone()),
        access_token_expires_at: tokens
            .access_token_expires_at
            .or(account.access_token_expires_at),
        refresh_token_expires_at: tokens
            .refresh_token_expires_at
            .or(account.refresh_token_expires_at),
        ..Default::default()
    };
    if let Some(id) = account.id.as_deref() {
        *account =
            AccountCookiePayload::from_account(&ctx.database.update_account(id, update).await?);
    } else {
        account.access_token = update.access_token;
        account.refresh_token = update.refresh_token;
        account.id_token = update.id_token;
        account.access_token_expires_at = update.access_token_expires_at;
        account.refresh_token_expires_at = update.refresh_token_expires_at;
    }
    Ok(())
}

async fn valid_access_token(
    account: &mut AccountCookiePayload,
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(AccessTokenResponse, bool)> {
    let provider = config.providers.get(&account.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!(
            "Provider {} is not supported.",
            account.provider_id
        ))
    })?;
    let encrypted = ctx.config.account.encrypt_oauth_tokens;
    let refresh_token = maybe_decrypt(
        account.refresh_token.as_deref(),
        encrypted,
        &ctx.config.secret,
    )?;
    let expired = account.access_token_expires_at.is_some_and(|expires_at| {
        expires_at.timestamp_millis() - Utc::now().timestamp_millis() < 5_000
    });
    let refreshed = if expired && let Some(refresh_token) = refresh_token {
        let tokens = refresh_tokens_via_provider(provider, &refresh_token, req)
            .await
            .map_err(|_| AuthError::bad_request("Failed to get a valid access token"))?;
        persist_tokens(account, &tokens, ctx).await?;
        true
    } else {
        false
    };
    Ok((
        AccessTokenResponse {
            access_token: Some(
                maybe_decrypt(
                    account.access_token.as_deref(),
                    encrypted,
                    &ctx.config.secret,
                )?
                .unwrap_or_default(),
            ),
            access_token_expires_at: account
                .access_token_expires_at
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            scopes: scopes(account),
            id_token: maybe_decrypt(account.id_token.as_deref(), encrypted, &ctx.config.secret)?,
        },
        refreshed,
    ))
}

fn token_response(
    value: &impl serde::Serialize,
    account: &AccountCookiePayload,
    set_cookie: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let mut response = AuthResponse::json(200, value)?;
    if set_cookie && ctx.config.account.store_account_cookie {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account)?,
        );
    }
    Ok(response)
}

pub(super) async fn handle_get_access_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", message),
    };
    let (_, session) = ctx.require_authoritative_session(req).await?;
    let mut account = selection.resolve(req, &session.user_id, ctx).await?;
    let (response, refreshed) = valid_access_token(&mut account, config, req, ctx).await?;
    token_response(&response, &account, refreshed, ctx)
}

pub(super) async fn handle_refresh_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", message),
    };
    let (_, session) = ctx.require_authoritative_session(req).await?;
    let mut account = selection.resolve(req, &session.user_id, ctx).await?;
    let provider = config.providers.get(&account.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!(
            "Provider {} is not supported.",
            account.provider_id
        ))
    })?;
    let refresh_token = maybe_decrypt(
        account.refresh_token.as_deref(),
        ctx.config.account.encrypt_oauth_tokens,
        &ctx.config.secret,
    )?
    .ok_or_else(|| AuthError::bad_request("Refresh token not found"))?;
    let tokens = refresh_tokens_via_provider(provider, &refresh_token, req)
        .await
        .map_err(|_| AuthError::bad_request("Failed to refresh access token"))?;
    persist_tokens(&mut account, &tokens, ctx).await?;
    let response = RefreshTokenResponse {
        access_token: tokens.access_token,
        access_token_expires_at: tokens
            .access_token_expires_at
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        refresh_token: Some(tokens.refresh_token.unwrap_or(refresh_token)),
        refresh_token_expires_at: account
            .refresh_token_expires_at
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        scope: account.scope.clone(),
        id_token: maybe_decrypt(
            account.id_token.as_deref(),
            ctx.config.account.encrypt_oauth_tokens,
            &ctx.config.secret,
        )?,
        provider_id: account.provider_id.clone(),
        account_id: account.id.clone(),
    };
    token_response(
        &response,
        &account,
        matches!(selection, AccountSelection::Cookie),
        ctx,
    )
}

pub(super) async fn handle_account_info(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_query(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("query", message),
    };
    let (_, session) = ctx.require_authoritative_session(req).await?;
    let mut account = selection.resolve(req, &session.user_id, ctx).await?;
    let provider = config
        .providers
        .get(&account.provider_id)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "PROVIDER_NOT_CONFIGURED",
            message: "Account is not associated with a configured social provider.",
        })?;
    let (tokens, refreshed) = valid_access_token(&mut account, config, req, ctx).await?;
    let access_token = tokens
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::bad_request("Access token not found"))?;
    let request = OAuthUserInfoRequest {
        access_token: Some(access_token),
        access_token_expires_at: account.access_token_expires_at,
        scopes: tokens.scopes,
        id_token: tokens.id_token,
        ..Default::default()
    };
    let (user, data) = if let Some(generic) = &provider.generic {
        let info = super::generic_profile::fetch_profile(generic, &request, None)
            .await
            .map_err(|_| AuthError::Upstream {
                status: 401,
                code: "FAILED_TO_GET_USER_INFO",
                message: "Failed to get user info",
            })?;
        (info.user, info.data)
    } else {
        let info = fetch_user_info_from_provider(provider, request, None).await?;
        (
            AccountInfoUser {
                name: info.user.name,
                email: info.user.email,
                image: info.user.image,
                email_verified: info.user.email_verified,
            },
            info.data,
        )
    };
    let response = AccountInfoResponse {
        user,
        data,
        account: AccountInfoAccount {
            id: account.id.clone(),
            provider_id: account.provider_id.clone(),
            account_id: account.account_id.clone(),
        },
    };
    token_response(&response, &account, refreshed, ctx)
}
