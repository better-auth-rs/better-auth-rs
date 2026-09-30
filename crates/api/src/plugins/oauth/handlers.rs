use base64::Engine;
use chrono::{Duration, Utc};
use indexmap::IndexMap;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount,
    CreateVerification, UpdateAccount, UpdateUser,
};

use super::authorization::{AuthorizationRequest, RESERVED_PARAMS, build_authorization_url};
use super::encryption::encrypt_token_set;
pub(super) use super::provider_tokens::refresh_tokens_via_provider;
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthTokenSet, OAuthUserInfo,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use super::resolved::{ResolvedOAuthConfig as OAuthConfig, ResolvedProvider};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, account_cookie_name,
    create_account_cookie_value, create_cookie_state_value, create_database_state_cookie_value,
    decode_account_cookie_value, filter_additional_state_data, get_cookie, state_cookie_name,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};

use super::signin::{OAuthSignInOptions, process_oauth_sign_in};

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

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

pub(super) async fn fetch_user_info_from_provider(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(generic) = &provider.generic {
        return super::generic_profile::fetch_user_info(generic, &request, expected_nonce).await;
    }
    if let Some(handler) = &provider.config.get_user_info {
        return handler
            .get_user_info(request)
            .await
            .map_err(AuthError::internal);
    }

    let user_info_url = provider
        .config
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .config
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

pub(super) fn parse_callback_user_payload(
    user_data: Option<&str>,
) -> Option<OAuthCallbackUserPayload> {
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

pub(super) fn redirect_response(location: &str) -> AuthResponse {
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

pub(super) fn create_account_cookie_header(
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

pub(super) fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    secret: &str,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = get_cookie(req, &account_cookie_name(config)) else {
        return Ok(None);
    };
    decode_account_cookie_value(secret, &value).map(Some)
}

pub(super) fn attach_state_cookie(
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

pub(super) fn attach_cookie_state_payload(
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
            Duration::minutes(10).num_seconds(),
            config,
        ),
    ))
}

pub(crate) fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.advanced.disable_origin_check {
        return Ok(());
    }
    if ctx.config.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_string()))
    }
}

pub(super) fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    if callback_url.is_some_and(|target| target.starts_with("//") || target.starts_with("/\\")) {
        return Err(AuthError::bad_request("Invalid callbackURL"));
    }
    let base = url::Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {error}")))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };
    if !params.is_empty() {
        let appended = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params.iter().copied())
            .finish();
        let query = match url.query() {
            Some(existing) if !existing.is_empty() => {
                let separator = if existing.ends_with('&') { "" } else { "&" };
                format!("{existing}{separator}{appended}")
            }
            _ => appended,
        };
        url.set_query(Some(&query));
    }
    if callback_url.is_some_and(|target| target.starts_with('/')) {
        Ok(url[url::Position::BeforePath..].to_string())
    } else {
        Ok(url.to_string())
    }
}

pub(super) fn auth_base_url(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

pub(super) struct InitiatedOAuthFlow {
    pub(super) response: SocialSignInResponse,
    pub(super) state: String,
    pub(super) payload: OAuthStatePayload,
}

pub(super) struct FlowStartRequest<'a> {
    pub(super) redirect_base: Option<String>,
    pub(super) anonymous_user_id: Option<String>,
    pub(super) provider_name: &'a str,
    pub(super) provider: &'a ResolvedProvider,
    pub(super) callback_url: &'a str,
    pub(super) new_user_callback_url: Option<String>,
    pub(super) error_callback_url: Option<String>,
    pub(super) scopes: Option<&'a [String]>,
    pub(super) additional_params: Option<&'a IndexMap<String, String>>,
    pub(super) login_hint: Option<&'a str>,
    pub(super) request_sign_up: Option<bool>,
    pub(super) additional_data: serde_json::Map<String, serde_json::Value>,
    pub(super) link: Option<OAuthStateLink>,
    pub(super) disable_redirect: bool,
}

pub(super) async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
                &existing_account.id(),
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

fn invalid_additional_params(params: Option<&IndexMap<String, String>>) -> Option<AuthResponse> {
    params.filter(|params| params.keys().any(|key| RESERVED_PARAMS.contains(&key.as_str())))
        .map(|_| crate::plugins::json_body::validation_error(&format!(
            "[body.additionalParams] additionalParams cannot include reserved OAuth parameters: {}", RESERVED_PARAMS.join(", ")
        )))
}

async fn verify_id_token(
    provider: &ResolvedProvider,
    request: &OAuthIdTokenRequest,
) -> AuthResult<()> {
    let valid = if let Some(verifier) = &provider.config.verify_id_token {
        // Upstream converts verifier rejection and verifier errors into the same authentication error.
        verifier
            .verify_id_token(&request.token, request.nonce.as_deref())
            .await
            .unwrap_or(false)
    } else if let Some(verifier) = provider
        .generic
        .as_ref()
        .and_then(|generic| generic.verifier.as_ref())
    {
        verifier
            .verify(&request.token, request.nonce.as_deref())
            .await
            .is_ok()
    } else {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    };
    if !valid {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }
    Ok(())
}

async fn sign_in_with_id_token_core(
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    config: &OAuthConfig,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    verify_id_token(provider, id_token).await?;

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
        None,
    )
    .await
    .map_err(|_| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;
    if user_info.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    let outcome = match process_oauth_sign_in(
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
        OAuthSignInOptions {
            disable_sign_up: provider.config.disable_implicit_sign_up
                && !body.request_sign_up.unwrap_or(false)
                || provider.config.disable_sign_up,
            callback_url: body.callback_url.as_deref().unwrap_or("/"),
            email_verification: config.email_verification.as_deref(),
        },
        meta,
        ctx,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => return error.into_auth_response(),
    };

    let response = SocialSignInResponse {
        url: None,
        redirect: false,
        status: None,
        token: Some(outcome.session.token().to_string()),
        user: Some(outcome.user),
    };
    Ok(AuthResponse::json(200, &response)?.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_session_cookie(
            outcome.session.token(),
            &ctx.config,
        ),
    ))
}

async fn link_with_id_token_core(
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    verify_id_token(provider, id_token).await?;

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
        None,
    )
    .await
    .map_err(|_| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if response.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    let existing_accounts = ctx.database.get_user_accounts(&session.user_id()).await?;
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
        .get_user_by_id(&session.user_id())
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
                &session.user_id(),
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
    req: &AuthRequest,
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or(AuthError::Upstream {
            status: 404,
            code: "PROVIDER_NOT_FOUND",
            message: "Provider not found",
        })?;

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

    let anonymous_user_id =
        if ctx.get_metadata("anonymous.enabled") == Some(&serde_json::Value::Bool(true)) {
            ctx.session_manager()
                .resolve(req, better_auth_core::session::SessionRead::Authoritative)
                .await?
                .data
                .filter(|session| session.user.is_anonymous == Some(true))
                .map(|session| session.user.id)
        } else {
            None
        };
    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            redirect_base: req
                .server_context(super::proxy::REDIRECT_BASE_CONTEXT)?
                .and_then(|value| value.as_str().map(str::to_owned)),
            anonymous_user_id,
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
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
    req: &AuthRequest,
    body: &LinkSocialRequest,
    session: &impl AuthSession,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or(AuthError::Upstream {
            status: 404,
            code: "PROVIDER_NOT_FOUND",
            message: "Provider not found",
        })?;

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
        .get_user_by_id(&session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User email not found"))?;

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            redirect_base: req
                .server_context(super::proxy::REDIRECT_BASE_CONTEXT)?
                .and_then(|value| value.as_str().map(str::to_owned)),
            anonymous_user_id: None,
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
            login_hint: body.login_hint.as_deref(),
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

/// Shared logic for social sign-in and link-social flows.
///
/// Both flows build a verification payload, store it, construct the
/// authorization URL, and return a redirect response. The only difference
/// is `link_user_id` (None for sign-in, Some for linking).
pub(super) async fn initiate_oauth_flow_core(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state = uuid::Uuid::new_v4().to_string();

    let mut payload = OAuthStatePayload::new(
        request.callback_url.to_string(),
        code_verifier,
        request.error_callback_url,
        request.new_user_callback_url,
        request.link,
        request.request_sign_up,
        request.additional_data,
    );

    let _ = payload
        .additional_data
        .insert("oauthState".into(), state.clone().into());
    if let Some(user_id) = request.anonymous_user_id {
        let _ = payload
            .server_context
            .insert("anonymousUserId".into(), serde_json::json!(user_id));
    }

    payload.id_token_nonce = request.provider.requires_nonce().then(|| {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    });

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
        AuthorizationRequest {
            callback_url: &format!(
                "{}/callback/{}",
                request.redirect_base.unwrap_or_else(|| auth_base_url(ctx)),
                request.provider_name
            ),
            scopes: request.scopes,
            state: &state,
            code_challenge: &code_challenge,
            login_hint: request.login_hint,
            nonce: payload.id_token_nonce.as_deref(),
            additional_params: request.additional_params,
        },
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
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Some(response) = invalid_additional_params(body.additional_params.as_ref()) {
        return Ok(response);
    }
    let meta = better_auth_core::RequestMeta::from_request(req);
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or(AuthError::Upstream {
                status: 404,
                code: "PROVIDER_NOT_FOUND",
                message: "Provider not found",
            })?;
        return sign_in_with_id_token_core(&body, id_token, provider, config, &meta, ctx).await;
    }

    let flow = social_sign_in_core(req, &body, config, ctx).await?;
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

pub(crate) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (_, session) = ctx.require_session(req).await?;
    let body: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Some(response) = invalid_additional_params(body.additional_params.as_ref()) {
        return Ok(response);
    }
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or(AuthError::Upstream {
                status: 404,
                code: "PROVIDER_NOT_FOUND",
                message: "Provider not found",
            })?;
        let response = link_with_id_token_core(&body, id_token, provider, &session, ctx).await?;
        return AuthResponse::json(200, &response).map_err(AuthError::from);
    }

    let flow = link_social_core(req, &body, &session, config, ctx).await?;
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

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
