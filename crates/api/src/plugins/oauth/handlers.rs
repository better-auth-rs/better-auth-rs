use base64::Engine;
use chrono::{Duration, Utc};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};

use super::encryption::{encrypt_token_set, maybe_decrypt};
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthConfig, OAuthProvider, OAuthTokenSet,
    OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, account_cookie_name,
    create_account_cookie_value, create_cookie_state_value, create_database_state_cookie_value,
    decode_account_cookie_value, decode_cookie_state_value, decode_database_state_cookie_value,
    filter_additional_state_data, get_cookie, state_cookie_name,
};
use super::types::{
    AccessTokenResponse, GetAccessTokenRequest, LinkSocialRequest, OAuthIdTokenRequest,
    RefreshTokenRequest, RefreshTokenResponse, SocialSignInRequest, SocialSignInResponse,
};

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

/// Authenticate the current request and return the validated session.
async fn require_session(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> Result<better_auth_core::Session, AuthError> {
    let session_manager = ctx.session_manager();
    let token = session_manager
        .extract_session_token(req)
        .ok_or(AuthError::Unauthenticated)?;
    session_manager
        .get_session(&token)
        .await?
        .ok_or(AuthError::Unauthenticated)
}

/// Find the account for a specific provider among a user's linked accounts.
fn find_account_for_provider<'a, A: AuthAccount>(
    accounts: &'a [A],
    provider_id: &str,
    account_id: Option<&str>,
) -> Result<&'a A, AuthError> {
    accounts
        .iter()
        .find(|account| {
            if account.provider_id() != provider_id {
                return false;
            }
            match account_id {
                Some(account_id) => account.id() == account_id,
                None => true,
            }
        })
        .ok_or_else(|| AuthError::bad_request("Account not found"))
}

fn generate_pkce() -> (String, String) {
    let verifier: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(43)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn build_authorization_url(
    provider: &OAuthProvider,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    login_hint: Option<&str>,
) -> AuthResult<String> {
    let effective_scopes: Vec<&str> = scopes
        .map(|s| s.iter().map(|s| s.as_str()).collect())
        .unwrap_or_else(|| provider.scopes.iter().map(|s| s.as_str()).collect());
    let scope_str = effective_scopes.join(" ");

    let mut url = url::Url::parse(&provider.auth_url)
        .map_err(|error| AuthError::internal(format!("Invalid auth URL: {error}")))?;
    let _ = url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("state", state)
        .append_pair("scope", &scope_str)
        .append_pair("redirect_uri", callback_url)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", code_challenge);
    if let Some(login_hint) = login_hint {
        let _ = url.query_pairs_mut().append_pair("login_hint", login_hint);
    }
    for (key, value) in &provider.authorization_params {
        let _ = url.query_pairs_mut().append_pair(key, value);
    }
    Ok(url.to_string())
}

async fn refresh_tokens_via_provider(
    provider: &OAuthProvider,
    refresh_token: &str,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.refresh_access_token {
        return handler
            .refresh_access_token(refresh_token)
            .await
            .map_err(AuthError::internal);
    }

    let client = reqwest::Client::new();
    let token_resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
        ])
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token refresh failed: {}", e)))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "Token refresh returned error: {}",
            error_body
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse refresh response: {}", e)))?;

    parse_token_response(token_data)
}

fn parse_token_response(token_data: serde_json::Value) -> AuthResult<OAuthTokenSet> {
    let access_token = token_data
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::internal("Missing access_token in token response"))?
        .to_string();
    let refresh_token = token_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let id_token = token_data
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let access_token_expires_at = token_data
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .map(|secs| Utc::now() + Duration::seconds(secs));
    let refresh_token_expires_at = token_data
        .get("refresh_token_expires_in")
        .and_then(|v| v.as_i64())
        .map(|secs| Utc::now() + Duration::seconds(secs));
    let scopes = token_data
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|scope| {
            scope
                .split([',', ' '])
                .filter(|value| !value.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    Ok(OAuthTokenSet {
        token_type: token_data
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        access_token: Some(access_token),
        refresh_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        id_token,
        raw: Some(token_data),
    })
}

async fn validate_authorization_code_via_provider(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &provider.client_id),
        ("client_secret", &provider.client_secret),
    ];
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier));
    }
    if let Some(device_id) = device_id {
        form.push(("device_id", device_id));
    }

    let client = reqwest::Client::new();
    let token_resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token exchange failed: {}", e)))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "Token exchange returned error: {}",
            error_body
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse token response: {}", e)))?;
    parse_token_response(token_data)
}

async fn fetch_user_info_from_provider(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(handler) = &provider.get_user_info {
        return handler
            .get_user_info(request)
            .await
            .map_err(AuthError::internal);
    }

    let user_info_url = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .map_user_info
        .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;

    let client = reqwest::Client::new();
    let user_info_resp = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to fetch user info: {}", e)))?;

    if !user_info_resp.status().is_success() {
        let error_body = user_info_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "User info request failed: {}",
            error_body
        )));
    }

    let user_info_json: serde_json::Value = user_info_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse user info: {}", e)))?;

    let user = mapper(user_info_json.clone())
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {}", e)))?;

    Ok(OAuthUserInfoResponse {
        user,
        data: user_info_json,
    })
}

fn parse_callback_user_payload(user_data: Option<&str>) -> Option<OAuthCallbackUserPayload> {
    let value: serde_json::Value = serde_json::from_str(user_data?).ok()?;
    Some(OAuthCallbackUserPayload {
        name: value
            .get("name")
            .and_then(|value| value.as_object())
            .map(|name| OAuthCallbackUserName {
                first_name: name
                    .get("firstName")
                    .and_then(|value| value.as_str())
                    .map(String::from),
                last_name: name
                    .get("lastName")
                    .and_then(|value| value.as_str())
                    .map(String::from),
            }),
        email: value
            .get("email")
            .and_then(|value| value.as_str())
            .map(String::from),
    })
}

fn redirect_response(location: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", location)
}

fn account_cookie_max_age(config: &better_auth_core::AuthConfig) -> Duration {
    config
        .session
        .cookie_cache
        .as_ref()
        .map(|cache| cache.max_age)
        .unwrap_or_else(|| Duration::minutes(5))
}

fn create_account_cookie_header(
    config: &better_auth_core::AuthConfig,
    secret: &str,
    payload: &AccountCookiePayload,
) -> AuthResult<String> {
    let max_age = account_cookie_max_age(config);
    let value = create_account_cookie_value(secret, payload, max_age)?;
    Ok(better_auth_core::utils::cookie_utils::create_cookie(
        &account_cookie_name(config),
        &value,
        max_age.num_seconds(),
        config,
    ))
}

fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    secret: &str,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = get_cookie(req, &account_cookie_name(config)) else {
        return Ok(None);
    };
    decode_account_cookie_value(secret, &value).map(Some)
}

async fn persist_refreshed_cookie_account(
    cookie_account: Option<&AccountCookiePayload>,
    provider_id: &str,
    req: &AuthRequest,
    ctx: &AuthContext,
    update: UpdateAccount,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(account) = cookie_account else {
        return Ok(None);
    };

    let Some(account_id) = account.id.as_deref() else {
        return Ok(None);
    };

    let updated_account = ctx.database.update_account(account_id, update).await?;
    let payload = AccountCookiePayload::from_account(&updated_account);

    if ctx.config.account.store_account_cookie
        && let Some(request_account_cookie) =
            decode_account_cookie(req, &ctx.config, &ctx.config.secret)?
        && request_account_cookie.provider_id == provider_id
    {
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

fn attach_state_cookie(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    secret: &str,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(secret, state)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        ),
    ))
}

fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    secret: &str,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(secret, payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        ),
    ))
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext,
    error_message: &str,
) -> AuthResult<()> {
    if !target.starts_with("//") && url::Url::parse(target).is_err() {
        return Ok(());
    }

    let origin = better_auth_core::extract_origin(target)
        .ok_or_else(|| AuthError::forbidden(error_message.to_string()))?;
    if ctx.config.is_origin_trusted(&origin) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_string()))
    }
}

fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = url::Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {error}")))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            let _ = pairs.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

fn auth_base_url(ctx: &AuthContext) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

struct ProcessOAuthUserResult {
    session: better_auth_core::Session,
    user: better_auth_core::User,
    is_register: bool,
    account_cookie: Option<AccountCookiePayload>,
}

pub(crate) struct AccessTokenCoreResult {
    response: AccessTokenResponse,
    account_cookie: Option<AccountCookiePayload>,
}

pub(crate) struct RefreshTokenCoreResult {
    response: RefreshTokenResponse,
    account_cookie: Option<AccountCookiePayload>,
}

struct InitiatedOAuthFlow {
    response: SocialSignInResponse,
    state: String,
    payload: OAuthStatePayload,
}

struct FlowStartRequest<'a> {
    provider_name: &'a str,
    provider: &'a OAuthProvider,
    callback_url: &'a str,
    new_user_callback_url: Option<String>,
    error_callback_url: Option<String>,
    scopes: Option<&'a [String]>,
    login_hint: Option<&'a str>,
    request_sign_up: Option<bool>,
    additional_data: serde_json::Map<String, serde_json::Value>,
    link: Option<OAuthStateLink>,
    disable_redirect: bool,
}

async fn process_oauth_sign_in(
    provider_name: &str,
    provider: &OAuthProvider,
    user_info: &OAuthUserInfo,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext,
) -> Result<ProcessOAuthUserResult, String> {
    if user_info.email.is_empty() {
        return Err("email not found".to_string());
    }

    let linked_account = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(|error| error.to_string())?;

    let token_bundle = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )
    .map_err(|error| error.to_string())?;

    if let Some(existing_account) = linked_account {
        if ctx.config.account.update_account_on_sign_in {
            let _ = ctx
                .database
                .update_account(
                    existing_account.id(),
                    UpdateAccount {
                        access_token: token_bundle.access_token.clone(),
                        refresh_token: token_bundle.refresh_token.clone(),
                        id_token: token_bundle.id_token.clone(),
                        access_token_expires_at: tokens.access_token_expires_at,
                        refresh_token_expires_at: tokens.refresh_token_expires_at,
                        scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let mut user = ctx
            .database
            .get_user_by_id(existing_account.user_id())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "user not found".to_string())?;

        if user_info.email_verified
            && !user.email_verified()
            && user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            user = ctx
                .database
                .update_user(
                    user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        if provider.override_user_info_on_sign_in {
            user = ctx
                .database
                .update_user(
                    user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        email_verified: Some(
                            user.email()
                                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
                                && (user.email_verified() || user_info.email_verified),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let session = ctx
            .session_manager()
            .create_session(&user, meta.ip_address.clone(), meta.user_agent.clone())
            .await
            .map_err(|error| error.to_string())?;
        let account_cookie =
            ctx.config
                .account
                .store_account_cookie
                .then(|| AccountCookiePayload {
                    id: Some(existing_account.id().to_string()),
                    provider_id: provider_name.to_string(),
                    account_id: existing_account.account_id().to_string(),
                    access_token: token_bundle
                        .access_token
                        .or_else(|| existing_account.access_token().map(str::to_string)),
                    refresh_token: token_bundle
                        .refresh_token
                        .or_else(|| existing_account.refresh_token().map(str::to_string)),
                    id_token: token_bundle
                        .id_token
                        .or_else(|| existing_account.id_token().map(str::to_string)),
                    access_token_expires_at: tokens
                        .access_token_expires_at
                        .or_else(|| existing_account.access_token_expires_at()),
                    refresh_token_expires_at: tokens
                        .refresh_token_expires_at
                        .or_else(|| existing_account.refresh_token_expires_at()),
                    scope: (!tokens.scopes.is_empty())
                        .then(|| tokens.scopes.join(","))
                        .or_else(|| existing_account.scope().map(str::to_string)),
                });

        return Ok(ProcessOAuthUserResult {
            session,
            user,
            is_register: false,
            account_cookie,
        });
    }

    let existing_user = ctx
        .database
        .get_user_by_email(&user_info.email.to_lowercase())
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_user) = existing_user {
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = linking
            .trusted_providers
            .iter()
            .any(|trusted| trusted == provider_name);

        if !linking.enabled
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
        {
            return Err("account not linked".to_string());
        }

        let mut linked_user = existing_user;
        let created_account = ctx
            .database
            .create_account(CreateAccount {
                user_id: linked_user.id().to_string(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_string(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_| "unable to link account".to_string())?;

        if user_info.email_verified
            && !linked_user.email_verified()
            && linked_user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            linked_user = ctx
                .database
                .update_user(
                    linked_user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        if provider.override_user_info_on_sign_in {
            linked_user =
                ctx.database
                    .update_user(
                        linked_user.id(),
                        UpdateUser {
                            name: user_info.name.clone(),
                            image: user_info.image.clone(),
                            email: Some(user_info.email.to_lowercase()),
                            email_verified: Some(
                                linked_user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && (linked_user.email_verified() || user_info.email_verified),
                            ),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
        }

        let session = ctx
            .session_manager()
            .create_session(
                &linked_user,
                meta.ip_address.clone(),
                meta.user_agent.clone(),
            )
            .await
            .map_err(|error| error.to_string())?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session,
            user: linked_user,
            is_register: false,
            account_cookie,
        })
    } else {
        if disable_sign_up {
            return Err("signup disabled".to_string());
        }

        let mut create_user = CreateUser::new()
            .with_email(user_info.email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or(&user_info.email))
            .with_email_verified(user_info.email_verified);
        create_user.image = user_info.image.clone();

        let created_user = ctx
            .database
            .create_user(create_user)
            .await
            .map_err(|_| "unable to create user".to_string())?;

        let created_account = ctx
            .database
            .create_account(CreateAccount {
                user_id: created_user.id().to_string(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_string(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_| "unable to create user".to_string())?;

        let session = ctx
            .session_manager()
            .create_session(
                &created_user,
                meta.ip_address.clone(),
                meta.user_agent.clone(),
            )
            .await
            .map_err(|error| error.to_string())?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session,
            user: created_user,
            is_register: true,
            account_cookie,
        })
    }
}

async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext,
) -> Result<(), String> {
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == provider_name);

    if !linking.enabled || (!trusted_provider && !user_info.email_verified) {
        return Err("unable_to_link_account".to_string());
    }

    if !linking.allow_different_emails && !user_info.email.eq_ignore_ascii_case(&link.email) {
        return Err("email_doesn't_match".to_string());
    }

    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(|error| error.to_string())?
    {
        if existing_account.user_id() != link.user_id {
            return Err("account_already_linked_to_different_user".to_string());
        }

        let token_bundle = encrypt_token_set(
            ctx,
            tokens.access_token.clone(),
            tokens.refresh_token.clone(),
            tokens.id_token.clone(),
        )
        .map_err(|error| error.to_string())?;

        let _ = ctx
            .database
            .update_account(
                existing_account.id(),
                UpdateAccount {
                    access_token: token_bundle.access_token,
                    refresh_token: token_bundle.refresh_token,
                    id_token: token_bundle.id_token,
                    access_token_expires_at: tokens.access_token_expires_at,
                    refresh_token_expires_at: tokens.refresh_token_expires_at,
                    scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| error.to_string())?;

        return Ok(());
    }

    let token_bundle = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )
    .map_err(|error| error.to_string())?;

    let _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: link.user_id.clone(),
            account_id: user_info.id.clone(),
            provider_id: provider_name.to_string(),
            access_token: token_bundle.access_token,
            refresh_token: token_bundle.refresh_token,
            id_token: token_bundle.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
            password: None,
        })
        .await
        .map_err(|_| "unable_to_link_account".to_string())?;

    Ok(())
}

async fn sign_in_with_id_token_core(
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext,
) -> AuthResult<SocialSignInResponse> {
    let verifier = provider
        .verify_id_token
        .as_ref()
        .ok_or_else(|| AuthError::not_found("id token not supported"))?;
    let valid = verifier
        .verify_id_token(&id_token.token, id_token.nonce.as_deref())
        .await
        .map_err(AuthError::internal)?;
    if !valid {
        return Err(AuthError::forbidden("Invalid token"));
    }

    let user_info = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| AuthError::forbidden("Failed to get user info"))?;

    let outcome = process_oauth_sign_in(
        &body.provider,
        provider,
        &user_info.user,
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        provider.disable_implicit_sign_up && !body.request_sign_up.unwrap_or(false)
            || provider.disable_sign_up,
        meta,
        ctx,
    )
    .await
    .map_err(AuthError::forbidden)?;

    Ok(SocialSignInResponse {
        url: None,
        redirect: false,
        status: None,
        token: Some(outcome.session.token().to_string()),
        user: Some(outcome.user),
    })
}

async fn link_with_id_token_core(
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    session: &better_auth_core::Session,
    ctx: &AuthContext,
) -> AuthResult<SocialSignInResponse> {
    let verifier = provider
        .verify_id_token
        .as_ref()
        .ok_or_else(|| AuthError::not_found("id token not supported"))?;
    let valid = verifier
        .verify_id_token(&id_token.token, id_token.nonce.as_deref())
        .await
        .map_err(AuthError::internal)?;
    if !valid {
        return Err(AuthError::forbidden("Invalid token"));
    }

    let response = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| AuthError::forbidden("Failed to get user info"))?;

    if response.user.email.is_empty() {
        return Err(AuthError::forbidden("User email not found"));
    }

    let existing_accounts = ctx.database.get_user_accounts(session.user_id()).await?;
    if existing_accounts.iter().any(|account| {
        account.provider_id() == body.provider && account.account_id() == response.user.id
    }) {
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
            token: None,
            user: None,
        });
    }

    let current_user = ctx
        .database
        .get_user_by_id(session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let current_email = current_user
        .email()
        .ok_or_else(|| AuthError::forbidden("User email not found"))?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == &body.provider);

    if !linking.enabled || (!trusted_provider && !response.user.email_verified) {
        return Err(AuthError::forbidden(
            "Account not linked - linking not allowed",
        ));
    }
    if !linking.allow_different_emails && !response.user.email.eq_ignore_ascii_case(current_email) {
        return Err(AuthError::forbidden(
            "Account not linked - different emails not allowed",
        ));
    }

    let token_bundle = encrypt_token_set(
        ctx,
        id_token.access_token.clone(),
        id_token.refresh_token.clone(),
        Some(id_token.token.clone()),
    )?;
    let _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: session.user_id().to_string(),
            provider_id: body.provider.clone(),
            account_id: response.user.id,
            access_token: token_bundle.access_token,
            refresh_token: token_bundle.refresh_token,
            id_token: token_bundle.id_token,
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            refresh_token_expires_at: None,
            scope: id_token.scopes.as_ref().map(|scopes| scopes.join(",")),
            password: None,
        })
        .await
        .map_err(|_| AuthError::bad_request("Account not linked - unable to create account"))?;

    if linking.update_user_info_on_link {
        let _ = ctx
            .database
            .update_user(
                session.user_id(),
                UpdateUser {
                    name: response.user.name.clone(),
                    image: response.user.image.clone(),
                    ..Default::default()
                },
            )
            .await;
    }

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
        token: None,
        user: None,
    })
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

async fn social_sign_in_core(
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: body.login_hint.as_deref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

async fn link_social_core(
    body: &LinkSocialRequest,
    session: &better_auth_core::Session,
    config: &OAuthConfig,
    ctx: &AuthContext,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    let user = ctx
        .database
        .get_user_by_id(session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User email not found"))?;

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: None,
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().to_string(),
            }),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

pub(crate) async fn get_access_token_core(
    body: &GetAccessTokenRequest,
    config: &OAuthConfig,
    req: &AuthRequest,
    session: &better_auth_core::Session,
    ctx: &AuthContext,
) -> AuthResult<AccessTokenCoreResult> {
    let _ = body.user_id.as_deref();
    let provider = config.providers.get(&body.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!("Provider {} is not supported.", body.provider_id))
    })?;

    let account_cookie = if ctx.config.account.store_account_cookie {
        decode_account_cookie(req, &ctx.config, &ctx.config.secret)?
    } else {
        None
    };
    let cookie_matches = account_cookie.as_ref().is_some_and(|account| {
        account.provider_id == body.provider_id
            && body
                .account_id
                .as_deref()
                .is_none_or(|account_id| account.id.as_deref() == Some(account_id))
    });

    let accounts = if cookie_matches {
        Vec::new()
    } else {
        ctx.database.get_user_accounts(session.user_id()).await?
    };
    let db_account = (!cookie_matches)
        .then(|| {
            find_account_for_provider(&accounts, &body.provider_id, body.account_id.as_deref())
        })
        .transpose()?;
    let cookie_account = cookie_matches.then_some(account_cookie.as_ref()).flatten();

    if cookie_account.is_none() && db_account.is_none() {
        return Err(AuthError::bad_request("Account not found"));
    }

    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;

    let mut access_token = if let Some(account_cookie) = cookie_account {
        maybe_decrypt(account_cookie.access_token.as_deref(), encrypt, secret)?
    } else {
        maybe_decrypt(
            db_account.and_then(|account| account.access_token()),
            encrypt,
            secret,
        )?
    };
    let mut access_token_expires_at = if let Some(account_cookie) = cookie_account {
        account_cookie
            .access_token_expires_at
            .map(|expires_at| expires_at.to_rfc3339())
    } else {
        db_account
            .ok_or_else(|| AuthError::bad_request("Account not found"))?
            .access_token_expires_at()
            .map(|dt| dt.to_rfc3339())
    };
    let mut scopes = if let Some(account_cookie) = cookie_account {
        account_cookie.scope.as_deref()
    } else {
        db_account
            .ok_or_else(|| AuthError::bad_request("Account not found"))?
            .scope()
    }
    .map(|scope| {
        scope
            .split(',')
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default();
    let mut id_token = if let Some(account_cookie) = cookie_account {
        maybe_decrypt(account_cookie.id_token.as_deref(), encrypt, secret)?
    } else {
        maybe_decrypt(
            db_account.and_then(|account| account.id_token()),
            encrypt,
            secret,
        )?
    };

    let access_token_expired = if let Some(account_cookie) = cookie_account {
        account_cookie
            .access_token_expires_at
            .is_some_and(|expires_at| {
                expires_at.timestamp_millis() - Utc::now().timestamp_millis() < 5_000
            })
    } else {
        db_account
            .ok_or_else(|| AuthError::bad_request("Account not found"))?
            .access_token_expires_at()
            .is_some_and(|expires_at| {
                expires_at.timestamp_millis() - Utc::now().timestamp_millis() < 5_000
            })
    };
    if access_token_expired
        && let Some(refresh_token) = if let Some(account_cookie) = cookie_account {
            maybe_decrypt(account_cookie.refresh_token.as_deref(), encrypt, secret)?
        } else {
            maybe_decrypt(
                db_account.and_then(|account| account.refresh_token()),
                encrypt,
                secret,
            )?
        }
    {
        let refreshed = refresh_tokens_via_provider(provider, &refresh_token)
            .await
            .map_err(|_| AuthError::bad_request("Failed to get a valid access token"))?;
        let tokens = encrypt_token_set(
            ctx,
            refreshed.access_token.clone(),
            refreshed.refresh_token.clone(),
            refreshed.id_token.clone(),
        )?;
        let scope = (!refreshed.scopes.is_empty()).then(|| refreshed.scopes.join(","));
        let mut refreshed_cookie_account = None;
        if let Some(account) = db_account {
            let _ = ctx
                .database
                .update_account(
                    account.id(),
                    UpdateAccount {
                        access_token: tokens.access_token,
                        refresh_token: tokens.refresh_token,
                        id_token: tokens.id_token,
                        access_token_expires_at: refreshed.access_token_expires_at,
                        refresh_token_expires_at: refreshed.refresh_token_expires_at,
                        scope: scope.clone(),
                        ..Default::default()
                    },
                )
                .await?;
        } else if let Some(updated_cookie_account) = persist_refreshed_cookie_account(
            cookie_account,
            &body.provider_id,
            req,
            ctx,
            UpdateAccount {
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                id_token: tokens.id_token.clone(),
                access_token_expires_at: refreshed.access_token_expires_at,
                refresh_token_expires_at: refreshed.refresh_token_expires_at,
                scope: scope.clone(),
                ..Default::default()
            },
        )
        .await?
        {
            refreshed_cookie_account = Some(updated_cookie_account);
        }

        access_token = refreshed.access_token;
        access_token_expires_at = refreshed
            .access_token_expires_at
            .map(|expires_at| expires_at.to_rfc3339());
        if !refreshed.scopes.is_empty() {
            scopes = refreshed.scopes.clone();
        }
        if refreshed.id_token.is_some() {
            id_token = refreshed.id_token;
        }

        return Ok(AccessTokenCoreResult {
            response: AccessTokenResponse {
                access_token,
                access_token_expires_at,
                scopes,
                id_token,
            },
            account_cookie: refreshed_cookie_account,
        });
    }

    Ok(AccessTokenCoreResult {
        response: AccessTokenResponse {
            access_token,
            access_token_expires_at,
            scopes,
            id_token,
        },
        account_cookie: None,
    })
}

pub(crate) async fn refresh_token_core(
    body: &RefreshTokenRequest,
    req: &AuthRequest,
    session: &better_auth_core::Session,
    config: &OAuthConfig,
    ctx: &AuthContext,
) -> AuthResult<RefreshTokenCoreResult> {
    let _ = body.user_id.as_deref();
    let provider_name = &body.provider_id;

    let provider = config
        .providers
        .get(provider_name)
        .ok_or_else(|| AuthError::bad_request(format!("Provider {} not found.", provider_name)))?;

    let account_cookie = if ctx.config.account.store_account_cookie {
        decode_account_cookie(req, &ctx.config, &ctx.config.secret)?
    } else {
        None
    };
    let cookie_matches = account_cookie.as_ref().is_some_and(|account| {
        account.provider_id == *provider_name
            && body
                .account_id
                .as_deref()
                .is_none_or(|account_id| account.id.as_deref() == Some(account_id))
    });
    let accounts = if cookie_matches {
        Vec::new()
    } else {
        ctx.database.get_user_accounts(session.user_id()).await?
    };
    let db_account = (!cookie_matches)
        .then(|| find_account_for_provider(&accounts, provider_name, body.account_id.as_deref()))
        .transpose()?;
    let cookie_account = cookie_matches.then_some(account_cookie.as_ref()).flatten();

    if cookie_account.is_none() && db_account.is_none() {
        return Err(AuthError::bad_request("Account not found"));
    }

    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;

    let current_refresh_token = if let Some(account_cookie) = cookie_account {
        maybe_decrypt(account_cookie.refresh_token.as_deref(), encrypt, secret)?
    } else {
        maybe_decrypt(
            db_account.and_then(|account| account.refresh_token()),
            encrypt,
            secret,
        )?
    }
    .ok_or_else(|| AuthError::bad_request("Refresh token not found"))?;

    let refreshed = refresh_tokens_via_provider(provider, &current_refresh_token)
        .await
        .map_err(|_| AuthError::bad_request("Failed to refresh access token"))?;

    let tokens = encrypt_token_set(
        ctx,
        refreshed.access_token.clone(),
        refreshed.refresh_token.clone(),
        refreshed.id_token.clone(),
    )?;
    let scope = (!refreshed.scopes.is_empty()).then(|| refreshed.scopes.join(","));
    let mut refreshed_cookie_account = None;
    if let Some(account) = db_account {
        let _ = ctx
            .database
            .update_account(
                account.id(),
                UpdateAccount {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    id_token: tokens.id_token,
                    access_token_expires_at: refreshed.access_token_expires_at,
                    refresh_token_expires_at: refreshed.refresh_token_expires_at,
                    scope: scope.clone(),
                    ..Default::default()
                },
            )
            .await?;
    } else if let Some(updated_cookie_account) = persist_refreshed_cookie_account(
        cookie_account,
        provider_name,
        req,
        ctx,
        UpdateAccount {
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            id_token: tokens.id_token.clone(),
            access_token_expires_at: refreshed.access_token_expires_at,
            refresh_token_expires_at: refreshed.refresh_token_expires_at,
            scope: scope.clone(),
            ..Default::default()
        },
    )
    .await?
    {
        refreshed_cookie_account = Some(updated_cookie_account);
    }
    let existing_id_token = if let Some(account_cookie) = cookie_account {
        maybe_decrypt(account_cookie.id_token.as_deref(), encrypt, secret)?
    } else {
        maybe_decrypt(
            db_account.and_then(|account| account.id_token()),
            encrypt,
            secret,
        )?
    };

    Ok(RefreshTokenCoreResult {
        response: RefreshTokenResponse {
            access_token: refreshed.access_token,
            access_token_expires_at: refreshed.access_token_expires_at.map(|dt| dt.to_rfc3339()),
            refresh_token: refreshed.refresh_token,
            refresh_token_expires_at: refreshed.refresh_token_expires_at.map(|dt| dt.to_rfc3339()),
            scope: scope
                .or_else(|| db_account.and_then(|account| account.scope().map(String::from)))
                .or_else(|| cookie_account.and_then(|account| account.scope.clone())),
            id_token: refreshed.id_token.or(existing_id_token),
            provider_id: db_account
                .map(|account| account.provider_id().to_string())
                .or_else(|| cookie_account.map(|account| account.provider_id.clone()))
                .unwrap_or_else(|| provider_name.to_string()),
            account_id: db_account
                .map(|account| account.account_id().to_string())
                .or_else(|| cookie_account.map(|account| account.account_id.clone()))
                .ok_or_else(|| AuthError::bad_request("Account not found"))?,
        },
        account_cookie: refreshed_cookie_account,
    })
}

/// Shared logic for social sign-in and link-social flows.
///
/// Both flows build a verification payload, store it, construct the
/// authorization URL, and return a redirect response. The only difference
/// is `link_user_id` (None for sign-in, Some for linking).
async fn initiate_oauth_flow_core(
    ctx: &AuthContext,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state = uuid::Uuid::new_v4().to_string();

    let payload = OAuthStatePayload::new(
        request.callback_url.to_string(),
        code_verifier,
        request.error_callback_url,
        request.new_user_callback_url,
        request.link,
        request.request_sign_up,
        request.additional_data,
    );

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let _ = ctx
                .database
                .create_verification(CreateVerification {
                    identifier: format!("oauth:{}", state),
                    value: serde_json::to_string(&payload)?,
                    expires_at: Utc::now() + Duration::minutes(10),
                })
                .await?;
        }
        better_auth_core::OAuthStateStrategy::Cookie => {}
    }

    let url = build_authorization_url(
        request.provider,
        &format!("{}/callback/{}", auth_base_url(ctx), request.provider_name),
        request.scopes,
        &state,
        &code_challenge,
        request.login_hint,
    )?;

    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
            token: None,
            user: None,
        },
        state,
        payload,
    })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_social_sign_in(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let meta = better_auth_core::RequestMeta::from_request(req);
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = sign_in_with_id_token_core(&body, id_token, provider, &meta, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;
        if let Some(token) = response.token.as_deref() {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
            );
        }
        return Ok(auth_response);
    }

    let flow = social_sign_in_core(&body, config, ctx).await?;
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }
    if let Some(token) = response.token.as_deref() {
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
        );
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_state_cookie(auth_response, &ctx.config, &ctx.config.secret, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_cookie_state_payload(
                auth_response,
                &ctx.config,
                &ctx.config.secret,
                &flow.payload,
            )
        }
    }
}

pub(crate) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let provider = config
        .providers
        .get(provider_name)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;
    let default_error_url = format!("{}/error", auth_base_url(ctx));
    let meta = better_auth_core::RequestMeta::from_request(req);

    let mut merged = req.query.clone();
    if req.method() == &better_auth_core::HttpMethod::Post {
        if let Some(body) = &req.body
            && !body.is_empty()
        {
            let body_text = String::from_utf8(body.clone()).map_err(|error| {
                AuthError::bad_request(format!("Invalid callback body: {error}"))
            })?;
            let parsed_body =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_text)
                    .ok()
                    .map(|body| {
                        body.into_iter()
                            .filter_map(|(key, value)| match value {
                                serde_json::Value::String(value) => Some((key, value)),
                                serde_json::Value::Null => None,
                                other => Some((key, other.to_string())),
                            })
                            .collect::<std::collections::HashMap<String, String>>()
                    })
                    .or_else(|| {
                        Some(
                            url::form_urlencoded::parse(body_text.as_bytes())
                                .into_owned()
                                .collect::<std::collections::HashMap<String, String>>(),
                        )
                    })
                    .ok_or_else(|| AuthError::bad_request("Invalid callback request"))?;
            merged.extend(parsed_body);
        }

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, value) in pairs {
            let _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let error = merged.get("error").cloned();
    let state_param = match merged.get("state").cloned() {
        Some(state) => state,
        None => {
            let separator = if default_error_url.contains('?') {
                '&'
            } else {
                '?'
            };
            return Ok(redirect_response(&format!(
                "{default_error_url}{separator}state=state_not_found"
            )));
        }
    };
    let payload = match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let verification = match ctx
                .database
                .get_verification_by_identifier(&format!("oauth:{state_param}"))
                .await?
            {
                Some(verification) => verification,
                None => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            };

            if !ctx.config.account.skip_state_cookie_check {
                let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                };
                let persisted_state =
                    match decode_database_state_cookie_value(&ctx.config.secret, &cookie_value) {
                        Ok(state) => state,
                        Err(_) => {
                            return Ok(redirect_response(&format!(
                                "{default_error_url}?error=state_mismatch"
                            )));
                        }
                    };
                if persisted_state != state_param {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
            }

            let payload: OAuthStatePayload = serde_json::from_str(verification.value())
                .map_err(|error| AuthError::internal(format!("Invalid state payload: {error}")))?;
            ctx.database.delete_verification(verification.id()).await?;
            payload
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=please_restart_the_process"
                )));
            };
            match decode_cookie_state_value(&ctx.config.secret, &cookie_value) {
                Ok(payload) => payload,
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            }
        }
    };

    let clear_state_cookie = better_auth_core::utils::cookie_utils::create_clear_cookie(
        &state_cookie_name(&ctx.config),
        &ctx.config,
    );
    let error_url = payload
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.clone());

    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        let mut response = redirect_response(
            &build_redirect_url(
                &auth_base_url(ctx),
                Some(&error_url),
                &[("error", error_code)],
            )
            .unwrap_or_else(|_| format!("{default_error_url}?error={error_code}")),
        )
        .with_appended_header("Set-Cookie", clear_state_cookie.clone());
        if let Some(description) = description {
            response = redirect_response(
                &build_redirect_url(
                    &auth_base_url(ctx),
                    Some(&error_url),
                    &[("error", error_code), ("error_description", description)],
                )
                .unwrap_or_else(|_| format!("{default_error_url}?error={error_code}")),
            )
            .with_appended_header("Set-Cookie", clear_state_cookie.clone());
        }
        response
    };

    if let Some(error) = error.as_deref() {
        return Ok(redirect_on_error(
            error,
            merged.get("error_description").map(String::as_str),
        ));
    }

    if payload.is_expired() {
        return Ok(redirect_on_error("please_restart_the_process", None));
    }

    let Some(code) = merged.get("code").cloned() else {
        return Ok(redirect_on_error("no_code", None));
    };

    let tokens = match validate_authorization_code_via_provider(
        provider,
        &code,
        &format!("{}/callback/{}", auth_base_url(ctx), provider_name),
        Some(&payload.code_verifier),
        merged.get("device_id").map(String::as_str),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(_) => return Ok(redirect_on_error("invalid_code", None)),
    };

    let user_info = match fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            token_type: tokens.token_type.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scopes: tokens.scopes.clone(),
            id_token: tokens.id_token.clone(),
            raw: tokens.raw.clone(),
            user: parse_callback_user_payload(merged.get("user").map(String::as_str)),
        },
    )
    .await
    {
        Ok(response) => response,
        Err(_) => return Ok(redirect_on_error("unable_to_get_user_info", None)),
    };

    if let Some(link) = payload.link.as_ref() {
        if let Err(error) =
            complete_link_social(provider_name, &user_info.user, &tokens, link, ctx).await
        {
            return Ok(redirect_on_error(&error, None));
        }

        return Ok(redirect_response(&payload.callback_url)
            .with_appended_header("Set-Cookie", clear_state_cookie));
    }

    let disable_sign_up = provider.disable_implicit_sign_up
        && !payload.request_sign_up.unwrap_or(false)
        || provider.disable_sign_up;
    let outcome = match process_oauth_sign_in(
        provider_name,
        provider,
        &user_info.user,
        &tokens,
        disable_sign_up,
        &meta,
        ctx,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => return Ok(redirect_on_error(&error.replace(' ', "_"), None)),
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_string()
    } else {
        payload.callback_url.clone()
    };
    let mut response = redirect_response(&redirect_target)
        .with_appended_header("Set-Cookie", clear_state_cookie)
        .with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(
                outcome.session.token(),
                &ctx.config,
            ),
        );
    if let Some(account_cookie) = outcome.account_cookie.as_ref() {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account_cookie)?,
        );
    }
    Ok(response)
}

pub(crate) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx).await?;
    let body: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = link_with_id_token_core(&body, id_token, provider, &session, ctx).await?;
        return AuthResponse::json(200, &response).map_err(AuthError::from);
    }

    let flow = link_social_core(&body, &session, config, ctx).await?;
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            attach_state_cookie(auth_response, &ctx.config, &ctx.config.secret, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => attach_cookie_state_payload(
            auth_response,
            &ctx.config,
            &ctx.config.secret,
            &flow.payload,
        ),
    }
}

pub(crate) async fn handle_get_access_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx).await?;
    let body: GetAccessTokenRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let result = get_access_token_core(&body, config, req, &session, ctx).await?;
    let mut response = AuthResponse::json(200, &result.response).map_err(AuthError::from)?;
    if let Some(account_cookie) = result.account_cookie.as_ref() {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account_cookie)?,
        );
    }
    Ok(response)
}

pub(crate) async fn handle_refresh_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx).await?;
    let body: RefreshTokenRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let result = refresh_token_core(&body, req, &session, config, ctx).await?;
    let mut response = AuthResponse::json(200, &result.response).map_err(AuthError::from)?;
    if let Some(account_cookie) = result.account_cookie.as_ref() {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account_cookie)?,
        );
    }
    Ok(response)
}
