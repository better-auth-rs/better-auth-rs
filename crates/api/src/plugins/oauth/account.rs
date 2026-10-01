use better_auth_core::entity::AuthAccount;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, UpdateAccount,
};
use chrono::Utc;

use super::encryption::{encrypt_token_set, maybe_decrypt};
use super::handlers::{
    create_account_cookie_headers, decode_account_cookie, fetch_user_info_from_provider,
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
            Self::Cookie if ctx.config.account.store_account_cookie() => {
                decode_account_cookie(req, &ctx.config)?.filter(|account| {
                    !ctx.store_capabilities().database || account.user_id == user_id
                })
            }
            Self::Cookie => None,
        };
        account.ok_or_else(|| AuthError::bad_request("Account not found"))
    }
}

async fn persist_tokens(
    account: &mut AccountCookiePayload,
    tokens: &OAuthTokenSet,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    let encrypted = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens
            .refresh_token
            .clone()
            .filter(|token| !token.is_empty()),
        tokens.id_token.clone().filter(|token| !token.is_empty()),
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
    if let Some(id) = account.id.as_deref()
        && let Some(updated) = ctx
            .database
            .update_account_optional(id, update.clone())
            .await?
    {
        *account = AccountCookiePayload::from_account(&updated);
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
) -> AuthResult<(AccessTokenResponse, Vec<String>)> {
    let provider = config.providers.get(&account.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!(
            "Provider {} is not supported.",
            account.provider_id
        ))
    })?;
    async {
        let encrypted = ctx.config.account.encrypt_oauth_tokens;
        let expired = account.access_token_expires_at.is_some_and(|expires_at| {
            expires_at.timestamp_millis() - Utc::now().timestamp_millis() < 5_000
        });
        let mut cookies = Vec::new();
        let new_tokens = if expired
            && account
                .refresh_token
                .as_ref()
                .is_some_and(|token| !token.is_empty())
        {
            let refresh_token = maybe_decrypt(
                account.refresh_token.as_deref(),
                encrypted,
                ctx.config.encryption_secret(),
            )?
            .unwrap_or_default();
            let tokens = refresh_tokens_via_provider(provider, &refresh_token, req).await?;
            persist_tokens(account, &tokens, ctx).await?;
            if ctx.config.account.store_account_cookie() {
                cookies = create_account_cookie_headers(req, &ctx.config, account)?;
            }
            Some(tokens)
        } else {
            None
        };
        let access_token = match new_tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.clone())
        {
            Some(token) => token,
            None => maybe_decrypt(
                account.access_token.as_deref(),
                encrypted,
                ctx.config.encryption_secret(),
            )?
            .unwrap_or_default(),
        };
        Ok((
            AccessTokenResponse {
                access_token: Some(access_token),
                access_token_expires_at: account
                    .access_token_expires_at
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                scopes: crate::plugins::helpers::parse_stored_scopes(account.scope.as_deref()),
                id_token: new_tokens
                    .and_then(|tokens| tokens.id_token)
                    .or_else(|| account.id_token.clone()),
            },
            cookies,
        ))
    }
    .await
    .map_err(|_: AuthError| AuthError::bad_request("Failed to get a valid access token"))
}

fn token_response(value: &impl serde::Serialize, cookies: Vec<String>) -> AuthResult<AuthResponse> {
    let mut response = AuthResponse::json(200, value)?;
    for cookie in cookies {
        response = response.with_appended_header("Set-Cookie", cookie);
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
    let (response, cookies) = valid_access_token(&mut account, config, req, ctx).await?;
    token_response(&response, cookies)
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
    let refresh_token = account
        .refresh_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AuthError::bad_request("Refresh token not found"))?;
    async {
        let refresh_token = maybe_decrypt(
            Some(&refresh_token),
            ctx.config.account.encrypt_oauth_tokens,
            ctx.config.encryption_secret(),
        )?
        .unwrap_or_default();
        let tokens = refresh_tokens_via_provider(provider, &refresh_token, req).await?;
        persist_tokens(&mut account, &tokens, ctx).await?;
        let response = RefreshTokenResponse {
            access_token: tokens.access_token,
            access_token_expires_at: tokens
                .access_token_expires_at
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            refresh_token: Some(tokens.refresh_token.unwrap_or(refresh_token)),
            refresh_token_expires_at: account.optional(
                "refreshTokenExpiresAt",
                account
                    .refresh_token_expires_at
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            ),
            scope: account.optional("scope", account.scope.clone()),
            id_token: account.optional("idToken", account.id_token.clone()),
            provider_id: account.provider_id.clone(),
            account_id: account.id.clone(),
        };
        let cookies = if matches!(selection, AccountSelection::Cookie)
            && ctx.config.account.store_account_cookie()
        {
            create_account_cookie_headers(req, &ctx.config, &account)?
        } else {
            Vec::new()
        };
        token_response(&response, cookies)
    }
    .await
    .map_err(|_: AuthError| AuthError::bad_request("Failed to refresh access token"))
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
    let (tokens, cookies) = valid_access_token(&mut account, config, req, ctx).await?;
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
                id: Some(info.user.id),
                name: info.user.name,
                email: info.user.email,
                image: info.user.image,
                email_verified: info.user.email_verified,
                additional_fields: info.user.additional_fields,
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
    token_response(&response, cookies)
}
