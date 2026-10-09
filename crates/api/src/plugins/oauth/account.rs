use better_auth_core::SchemaValue;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, FieldValue, UpdateAccount,
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

#[derive(Clone)]
enum AccountSource {
    Id(String),
    Cookie,
}

#[derive(Clone)]
struct AccountSelection {
    source: AccountSource,
    user_id: Option<String>,
}

pub(super) fn account_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let projection = req.input_body()?;
    let selection =
        AccountSelection::from_value(projection.clone().unwrap_or(serde_json::Value::Null))
            .map_err(|message| {
                AuthError::from(crate::plugins::json_body::validation_error(&format!(
                    "[body] {message}"
                )))
            })?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        projection, selection,
    ))
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
        if let Some(selection) = req.validated_body::<Self>() {
            return Ok(selection.clone());
        }
        let value = req.body_as_json().map_err(|_| "Invalid input".to_owned())?;
        Self::from_value(value)
    }

    fn from_query(req: &AuthRequest) -> Result<Self, String> {
        Self::from_value(req.query.clone().unwrap_or(serde_json::Value::Null))
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
            (Some(id), false) => (AccountSource::Id(id.to_owned()), "accountId"),
            (None, true) => (AccountSource::Cookie, "useAccountCookie"),
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
        Ok(Self {
            source: selection,
            user_id: object
                .get("userId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }

    async fn resolve_user_id(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<FieldValue> {
        let read = if ctx.store_capabilities().server_sessions() {
            better_auth_core::session::SessionRead::CookieBypass
        } else {
            better_auth_core::session::SessionRead::Cached
        };
        let session = ctx.native_session(req, read).await?;
        let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
            Some(req),
            FieldValue::Undefined,
            ctx,
        );
        if session.is_none() && (endpoint.request.is_some() || endpoint.headers().is_some()) {
            return Err(AuthError::Unauthenticated);
        }
        session
            .as_ref()
            .map(|data| data.user_field("id").clone())
            .filter(FieldValue::is_truthy)
            .or_else(|| {
                self.user_id
                    .as_deref()
                    .map(FieldValue::from)
                    .filter(FieldValue::is_truthy)
            })
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "USER_ID_OR_SESSION_REQUIRED",
                message: "Either userId or session is required",
            })
    }

    fn matches(
        &self,
        account: &AccountCookiePayload,
        user_id: &FieldValue,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> bool {
        (!ctx.store_capabilities().database || account.user_id.field_value().strict_equals(user_id))
            && match &self.source {
                AccountSource::Id(id) => {
                    account.id.field_value().strict_equals(&id.as_str().into())
                }
                AccountSource::Cookie => true,
            }
    }

    async fn resolve(
        &self,
        req: &AuthRequest,
        user_id: &FieldValue,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AccountCookiePayload> {
        let account = match &self.source {
            AccountSource::Id(account_id) => ctx
                .database
                .get_user_accounts_value(user_id)
                .await?
                .iter()
                .find(|account| {
                    account
                        .id
                        .field_value()
                        .strict_equals(&account_id.as_str().into())
                })
                .cloned(),
            AccountSource::Cookie if ctx.config.account.store_account_cookie() => {
                decode_account_cookie(req, &ctx.config)?
                    .filter(|account| self.matches(account, user_id, ctx))
            }
            AccountSource::Cookie => None,
        };
        account.ok_or_else(|| AuthError::bad_request("Account not found"))
    }
}

fn provider_for<'a>(
    config: &'a OAuthConfig,
    account: &AccountCookiePayload,
) -> AuthResult<&'a super::resolved::ResolvedProvider> {
    if let Some((_, provider)) = config
        .providers
        .iter()
        .find(|(name, _)| account.provider_id == name.as_str())
    {
        return Ok(provider);
    }
    Err(AuthError::bad_request(format!(
        "Provider {} is not supported.",
        account.provider_id.display_string()?
    )))
}

fn parse_scopes(scope: &SchemaValue<Option<String>>) -> AuthResult<Vec<String>> {
    if !scope.is_truthy()? {
        return Ok(Vec::new());
    }
    let value = scope
        .typed()?
        .as_deref()
        .ok_or_else(|| AuthError::internal("account.scope.split is not a function"))?;
    Ok(crate::plugins::helpers::parse_stored_scopes(Some(value)))
}

fn date_value(
    value: &SchemaValue<Option<better_auth_core::FieldDate>>,
) -> AuthResult<SchemaValue<better_auth_core::FieldDate>> {
    Ok(SchemaValue::from_field(value.field_value()))
}

fn decrypt_value(
    value: &SchemaValue<Option<String>>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SchemaValue<Option<String>>> {
    if !ctx.config.account.encrypt_oauth_tokens() || !value.is_truthy()? {
        return Ok(value.clone());
    }
    Ok(maybe_decrypt(
        value.typed()?.as_deref(),
        true,
        ctx.config.encryption_secret(),
    )?
    .into())
}

fn overlay_account(target: &mut AccountCookiePayload, source: AccountCookiePayload) {
    if !source.id.is_undefined() {
        target.id = source.id;
    }
    if !source.account_id.is_undefined() {
        target.account_id = source.account_id;
    }
    if !source.provider_id.is_undefined() {
        target.provider_id = source.provider_id;
    }
    if !source.user_id.is_undefined() {
        target.user_id = source.user_id;
    }
    if !source.access_token.is_undefined() {
        target.access_token = source.access_token;
    }
    if !source.refresh_token.is_undefined() {
        target.refresh_token = source.refresh_token;
    }
    if !source.id_token.is_undefined() {
        target.id_token = source.id_token;
    }
    if !source.access_token_expires_at.is_undefined() {
        target.access_token_expires_at = source.access_token_expires_at;
    }
    if !source.refresh_token_expires_at.is_undefined() {
        target.refresh_token_expires_at = source.refresh_token_expires_at;
    }
    if !source.scope.is_undefined() {
        target.scope = source.scope;
    }
    if !source.password.is_undefined() {
        target.password = source.password;
    }
    if !source.created_at.is_undefined() {
        target.created_at = source.created_at;
    }
    if !source.updated_at.is_undefined() {
        target.updated_at = source.updated_at;
    }
    target.additional_fields.extend(source.additional_fields);
}

async fn persist_tokens(
    account: &AccountCookiePayload,
    tokens: &OAuthTokenSet,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AccountCookiePayload> {
    let encrypted = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens
            .refresh_token
            .clone()
            .filter(|token| !token.is_empty()),
        None,
    )?;
    let mut update = UpdateAccount {
        access_token: encrypted
            .access_token
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_default(),
        refresh_token: encrypted
            .refresh_token
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_else(|| account.refresh_token.clone()),
        id_token: tokens
            .id_token
            .clone()
            .filter(|value| !value.is_empty())
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_else(|| account.id_token.clone()),
        access_token_expires_at: tokens
            .access_token_expires_at
            .clone()
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_default(),
        refresh_token_expires_at: tokens
            .refresh_token_expires_at
            .clone()
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_else(|| account.refresh_token_expires_at.clone()),
        ..Default::default()
    };
    if tokens.access_token_expires_at.is_none() {
        // The refresh input owns this undefined key before the adapter removes absent writes.
        let _ = update.additional_fields.insert(
            "accessTokenExpiresAt".into(),
            better_auth_core::FieldValue::Undefined,
        );
    }
    let updated = if account.id.is_truthy()? {
        ctx.database
            .update_account_by_id_value(&account.id.field_value(), update.clone())
            .await?
    } else {
        None
    };
    let mut cookie = account.clone();
    if let Some(updated) = updated {
        overlay_account(&mut cookie, updated);
    } else {
        cookie.access_token = update.access_token;
        cookie.refresh_token = update.refresh_token;
        cookie.id_token = update.id_token;
        cookie.access_token_expires_at = update.access_token_expires_at;
        cookie.refresh_token_expires_at = update.refresh_token_expires_at;
    }
    Ok(cookie)
}

async fn valid_access_token(
    account: &AccountCookiePayload,
    selection: &AccountSelection,
    user_id: &FieldValue,
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(AccessTokenResponse, Vec<String>)> {
    if !selection.matches(account, user_id, ctx) {
        return Err(AuthError::bad_request("Account not found"));
    }
    let provider = provider_for(config, account)?;
    async {
        let expired = account.access_token_expires_at.is_truthy()?
            && date_value(&account.access_token_expires_at)?
                .converted_date()?
                .is_before(Utc::now() + chrono::Duration::seconds(5))?;
        let mut cookies = Vec::new();
        let new_tokens = if expired
            && account.refresh_token.is_truthy()?
            && provider.config.supports_refresh()
        {
            let value = decrypt_value(&account.refresh_token, ctx)?;
            let refresh = value
                .typed()?
                .as_deref()
                .ok_or_else(|| AuthError::internal("Refresh token is null"))?;
            let tokens = refresh_tokens_via_provider(provider, refresh, req).await?;
            let updated = persist_tokens(account, &tokens, ctx).await?;
            if ctx.config.account.store_account_cookie() {
                cookies = create_account_cookie_headers(req, &ctx.config, &updated)?;
            }
            Some(tokens)
        } else {
            None
        };
        let access_token = match new_tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.clone())
        {
            Some(token) => SchemaValue::Typed(Some(token)),
            None => {
                let value = if account.access_token.is_absent() {
                    SchemaValue::Typed(Some(String::new()))
                } else {
                    account.access_token.clone()
                };
                decrypt_value(&value, ctx)?
            }
        };
        let access_token_expires_at = if let Some(value) = new_tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token_expires_at.clone())
        {
            SchemaValue::Typed(Some(value))
        } else if account.access_token_expires_at.is_truthy()? {
            // getValidAccessToken converts strings but preserves other replacement output types.
            if account.access_token_expires_at.field_value().is_string() {
                date_value(&account.access_token_expires_at)?
                    .converted_date()?
                    .map(Some)
            } else {
                account.access_token_expires_at.clone()
            }
        } else {
            SchemaValue::Undefined
        };
        let id_token = new_tokens
            .and_then(|tokens| tokens.id_token)
            .map(|value| SchemaValue::Typed(Some(value)))
            .unwrap_or_else(|| {
                if account.id_token.is_absent() {
                    SchemaValue::Undefined
                } else {
                    account.id_token.clone()
                }
            });
        Ok((
            AccessTokenResponse {
                access_token,
                access_token_expires_at,
                scopes: parse_scopes(&account.scope)?,
                id_token,
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
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let (response, cookies) =
        valid_access_token(&account, &selection, &user_id, config, req, ctx).await?;
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
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let provider = provider_for(config, &account)?;
    if !provider.config.supports_refresh() {
        return Err(AuthResponse::json(
            400,
            &serde_json::json!({
                "code": "TOKEN_REFRESH_NOT_SUPPORTED",
                "message": format!(
                    "Provider {} does not support token refreshing.",
                    account.provider_id.display_string()?
                ),
            }),
        )?
        .into());
    }
    if !account.refresh_token.is_truthy()? {
        return Err(AuthError::bad_request("Refresh token not found"));
    }
    async {
        let decrypted = decrypt_value(&account.refresh_token, ctx)?;
        let refresh_token = decrypted
            .typed()?
            .as_deref()
            .ok_or_else(|| AuthError::internal("Refresh token is null"))?;
        let tokens = refresh_tokens_via_provider(provider, refresh_token, req).await?;
        let updated = persist_tokens(&account, &tokens, ctx).await?;
        let response = RefreshTokenResponse {
            access_token: tokens.access_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token: tokens
                .refresh_token
                .unwrap_or_else(|| refresh_token.to_owned()),
            refresh_token_expires_at: tokens
                .refresh_token_expires_at
                .map(|value| SchemaValue::Typed(Some(value)))
                .unwrap_or_else(|| account.refresh_token_expires_at.clone()),
            scope: if updated.scope.is_absent() {
                account.scope.clone()
            } else {
                updated.scope.clone()
            },
            id_token: tokens
                .id_token
                .filter(|token| !token.is_empty())
                .map(|value| SchemaValue::Typed(Some(value)))
                .unwrap_or_else(|| account.id_token.clone()),
            provider_id: account.provider_id.clone(),
            account_id: account.id.clone(),
        };
        let cookies = if matches!(selection.source, AccountSource::Cookie)
            && ctx.config.account.store_account_cookie()
        {
            create_account_cookie_headers(req, &ctx.config, &updated)?
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
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let provider = config
        .providers
        .iter()
        .find(|(name, _)| account.provider_id == name.as_str())
        .map(|(_, provider)| provider)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "PROVIDER_NOT_CONFIGURED",
            message: "Account is not associated with a configured social provider.",
        })?;
    let (tokens, cookies) =
        valid_access_token(&account, &selection, &user_id, config, req, ctx).await?;
    if !tokens.access_token.is_truthy()? {
        return Err(AuthError::bad_request("Access token not found"));
    }
    let access_token = tokens
        .access_token
        .typed()?
        .clone()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::bad_request("Access token not found"))?;
    let request = OAuthUserInfoRequest {
        access_token: Some(access_token),
        access_token_expires_at: if account.access_token_expires_at.is_absent() {
            None
        } else {
            account.access_token_expires_at.typed()?.clone()
        },
        scopes: tokens.scopes,
        id_token: if tokens.id_token.is_absent() {
            None
        } else {
            tokens.id_token.typed()?.clone()
        },
        ..Default::default()
    };
    let (user, data) = if let Some(generic) = &provider.generic {
        let info = super::generic_profile::fetch_profile(generic, &request, None, None)
            .await
            .map_err(super::generic_profile::GenericProfileError::into_auth_error)?
            .ok_or_else(super::social_profile::missing_profile)?;
        (info.user, info.data)
    } else {
        let info = fetch_user_info_from_provider(provider, request, None)
            .await?
            .ok_or_else(super::social_profile::missing_profile)?;
        (
            AccountInfoUser {
                id: provider
                    .config
                    .account_info_includes_id()
                    .then_some(info.user.id),
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
