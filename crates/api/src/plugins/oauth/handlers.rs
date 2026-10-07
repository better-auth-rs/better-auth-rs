use base64::Engine;
use chrono::{Duration, Utc};
use indexmap::IndexMap;
use rand::RngCore;
use sha2::{Digest, Sha256};

use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount,
    CreateVerification, UpdateAccount, UpdateUser,
};

use super::authorization::{AuthorizationRequest, build_authorization_url};
use super::encryption::encrypt_token_set;
pub(super) use super::provider_tokens::refresh_tokens_via_provider;
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthTokenSet, OAuthUserInfo,
    OAuthUserInfoRequest,
};
use super::resolved::{ResolvedOAuthConfig as OAuthConfig, ResolvedProvider};
pub(super) use super::social_profile::{fetch_user_info_for_code, fetch_user_info_from_provider};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, account_cookie_name,
    create_account_cookie_value, create_cookie_state_value, create_database_state_cookie_value,
    decode_account_cookie_value, filter_additional_state_data, state_cookie_name,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};

use super::signin::{OAuthSignInOptions, process_oauth_sign_in};

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

fn random_base64url(bytes: usize) -> String {
    let mut random = vec![0; bytes];
    rand::thread_rng().fill_bytes(&mut random);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
}

fn generate_pkce() -> (String, String) {
    let verifier = random_base64url(96);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
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
        .map(|cache| cache.max_age())
        .unwrap_or_else(|| Duration::minutes(5))
}

pub(super) fn create_account_cookie_headers(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    payload: &AccountCookiePayload,
) -> AuthResult<Vec<String>> {
    let max_age = account_cookie_max_age(config);
    let cookie = config.auth_cookie(
        "account_data",
        better_auth_core::CookieAttributes {
            max_age: Some(max_age.as_seconds_f64()),
            ..Default::default()
        },
    );
    let ttl = cookie.attributes.max_age.unwrap_or(300.0);
    let value = create_account_cookie_value(config.encryption_secret(), payload, ttl)?;
    better_auth_core::utils::cookie_utils::create_chunked_cookies(req, &cookie, &value)
}

pub(super) fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = better_auth_core::utils::cookie_utils::get_chunked_cookie(
        req,
        &account_cookie_name(config),
    ) else {
        return Ok(None);
    };
    Ok(decode_account_cookie_value(
        config.encryption_secret(),
        &value,
    ))
}

pub(super) fn attach_state_cookie(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(config.signing_secret(), state)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).as_seconds_f64(),
            config,
        )?,
    ))
}

pub(super) fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(config.encryption_secret(), payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(10).as_seconds_f64(),
            config,
        )?,
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
    if ctx.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_string()))
    }
}

pub(super) fn auth_base_url(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> String {
    ctx.base_url().trim_end_matches('/').to_owned()
}

pub(super) fn state_callback_url<'a>(
    callback: Option<&'a str>,
    ctx: &'a AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<&'a str> {
    callback
        .filter(|value| !value.is_empty())
        .or_else(|| {
            ctx.config
                .base_url
                .as_static()
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| AuthError::bad_request("callbackURL is required"))
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
    pub(super) additional_data: super::state_json::StateExtras,
    pub(super) link: Option<OAuthStateLink>,
    pub(super) disable_redirect: bool,
}

pub(super) async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    profile: Option<&serde_json::Value>,
    endpoint: &crate::plugins::endpoint_context::EndpointContext<
        '_,
        impl better_auth_core::AuthSchema,
    >,
) -> Result<(), super::signin::OAuthSignInError> {
    let ctx = endpoint.auth;
    super::signin::validate_provider_user(
        user_info,
        link.user_id.clone().into(),
        provider_name,
        profile,
        crate::plugins::user_admission::UserValidationAction::LinkAccount,
        endpoint,
    )
    .await?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = ctx
        .trusted_providers()
        .iter()
        .any(|trusted| trusted == provider_name);

    if !linking.enabled() || (!trusted_provider && !user_info.email_verified()?) {
        return Err("unable_to_link_account".to_string().into());
    }

    if !linking.allow_different_emails
        && !user_info
            .email()?
            .is_some_and(|email| email.eq_ignore_ascii_case(&link.email))
    {
        return Err("email_doesn't_match".to_string().into());
    }

    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(|error| error.to_string())?
    {
        if existing_account.user_id != link.user_id {
            return Err("account_already_linked_to_different_user"
                .to_string()
                .into());
        }

        let stored_scope = if existing_account.scope.is_truthy()? {
            existing_account
                .scope
                .typed()?
                .as_deref()
                .unwrap_or_default()
        } else {
            ""
        };
        let merged_scope = stored_scope
            .split(',')
            .chain(tokens.scopes.iter().map(String::as_str))
            .map(|scope| scope.trim_matches(crate::plugins::helpers::oauth_scope_whitespace))
            .filter(|scope| !scope.is_empty())
            .collect::<indexmap::IndexSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
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
                existing_account
                    .id
                    .typed()
                    .map_err(|error| error.to_string())?,
                UpdateAccount {
                    provider_id: provider_name.to_owned().into(),
                    access_token: (token_bundle.access_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    refresh_token: (token_bundle.refresh_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    id_token: (token_bundle.id_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    access_token_expires_at: tokens
                        .access_token_expires_at
                        .clone()
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    refresh_token_expires_at: tokens
                        .refresh_token_expires_at
                        .clone()
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    scope: ((!merged_scope.is_empty()).then_some(merged_scope))
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| error.to_string())?;

        apply_link_user_info(&link.user_id, user_info, ctx).await;
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
            user_id: (link.user_id.clone()).into(),
            account_id: (user_info.id.clone()).into(),
            provider_id: (provider_name.to_string()).into(),
            access_token: (token_bundle.access_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            refresh_token: (token_bundle.refresh_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            id_token: (token_bundle.id_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            access_token_expires_at: tokens
                .access_token_expires_at
                .clone()
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            refresh_token_expires_at: tokens
                .refresh_token_expires_at
                .clone()
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            scope: Some(tokens.scopes.join(",")).into(),
            password: Default::default(),
            ..Default::default()
        })
        .await
        .map_err(|_| "unable_to_link_account".to_string())?;

    apply_link_user_info(&link.user_id, user_info, ctx).await;
    Ok(())
}

async fn sign_in_with_id_token_core(
    req: &AuthRequest,
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    config: &OAuthConfig,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        req.input_field_value()?,
        ctx,
    );
    endpoint.session = req
        .session_snapshot()?
        .map(|data| (data.user, data.session));
    let claims =
        super::id_token::verify_in_endpoint(&body.provider, provider, id_token, &endpoint).await?;

    let user_info = super::social_profile::fetch_user_info_with_claims(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            user: id_token.user.clone(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        id_token.nonce.as_deref(),
        claims,
    )
    .await?
    .ok_or_else(super::social_profile::missing_profile)?;
    if user_info.user.email()?.is_none_or(str::is_empty) {
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
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        OAuthSignInOptions {
            request: req,
            profile: Some(&user_info.data),
            body: req.body_as_json()?,
            disable_sign_up: provider.config.disable_implicit_sign_up()
                && !body.request_sign_up.unwrap_or(false)
                || provider.config.disable_sign_up(),
            override_user_info: false,
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
    ctx.session_manager()
        .set_native_session_cookie(req, outcome.issued, None)
        .await?;
    Ok(AuthResponse::json(200, &response)?)
}

async fn link_with_id_token_core(
    req: &AuthRequest,
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    current_user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        req.input_field_value()?,
        ctx,
    );
    endpoint.session = req
        .session_snapshot()?
        .map(|data| (data.user, data.session));
    let claims =
        super::id_token::verify_in_endpoint(&body.provider, provider, id_token, &endpoint).await?;

    let response = super::social_profile::fetch_user_info_with_claims(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        id_token.nonce.as_deref(),
        claims,
    )
    .await?
    .ok_or_else(super::social_profile::missing_profile)?;

    let Some(provider_email) = response.user.email()?.filter(|email| !email.is_empty()) else {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    };

    if let Some(account) = ctx
        .database
        .get_account(&body.provider, &response.user.id)
        .await?
    {
        if account.user_id != current_user.id().into_owned() {
            return Err(AuthError::Upstream {
                status: 409,
                code: "SOCIAL_ACCOUNT_ALREADY_LINKED",
                message: "Social account already linked",
            });
        }
        let tokens = encrypt_token_set(
            ctx,
            id_token.access_token.clone(),
            id_token.refresh_token.clone(),
            Some(id_token.token.clone()),
        )?;
        let _ = ctx
            .database
            .update_account_optional(
                account.id.typed()?,
                UpdateAccount {
                    access_token: (tokens.access_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    refresh_token: (tokens.refresh_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    id_token: (tokens.id_token)
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await?;
        apply_link_user_info(current_user.id().typed()?, &response.user, ctx).await;
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
            token: None,
            user: None,
        });
    }

    let current_email = current_user
        .email()
        .ok_or_else(|| AuthError::forbidden("User email not found"))?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = ctx
        .trusted_providers()
        .iter()
        .any(|trusted| trusted == &body.provider);

    if !linking.enabled() || (!trusted_provider && !response.user.email_verified()?) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "LINKING_NOT_ALLOWED",
            message: "Account not linked - linking not allowed",
        });
    }
    if !linking.allow_different_emails && !provider_email.eq_ignore_ascii_case(current_email) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            message: "Account not linked - different emails not allowed",
        });
    }

    let created = async {
        let token_bundle = encrypt_token_set(
            ctx,
            id_token.access_token.clone(),
            id_token.refresh_token.clone(),
            Some(id_token.token.clone()),
        )?;
        let _ = ctx
            .database
            .create_account_optional(CreateAccount {
                user_id: current_user.id().into_owned(),
                provider_id: (body.provider.clone()).into(),
                account_id: (response.user.id.clone()).into(),
                access_token: (token_bundle.access_token)
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                refresh_token: (token_bundle.refresh_token)
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                id_token: (token_bundle.id_token)
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                access_token_expires_at: Default::default(),
                refresh_token_expires_at: Default::default(),
                scope: Default::default(),
                password: Default::default(),
                ..Default::default()
            })
            .await?;
        Ok::<_, AuthError>(())
    }
    .await;
    created.map_err(|_| AuthError::Upstream {
        status: 417,
        code: "LINKING_FAILED",
        message: "Account not linked - unable to create account",
    })?;
    apply_link_user_info(current_user.id().typed()?, &response.user, ctx).await;

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
        token: None,
        user: None,
    })
}

async fn apply_link_user_info(
    user_id: &str,
    user_info: &OAuthUserInfo,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) {
    if !ctx
        .config
        .account
        .account_linking
        .update_user_info_on_link()
    {
        return;
    }
    let result = async {
        ctx.database
            .update_user(
                user_id,
                UpdateUser {
                    additional_fields: ctx
                        .config
                        .user
                        .parse_provider_input(&user_info.additional_fields, false)?,
                    name: user_info
                        .name()?
                        .map(|value| Some(value.to_owned()).into())
                        .unwrap_or_default(),
                    image: user_info.image.clone().map(Into::into).unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await
    }
    .await;
    // Upstream treats profile synchronization as optional after the account write succeeds.
    if let Err(error) = result {
        better_auth_core::observability::logger::current().warn(
            "Could not update user info on account link",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
    }
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

    let callback_url = state_callback_url(body.callback_url.as_deref(), ctx)?;
    super::proxy::validate_callback_url(req, callback_url, ctx)?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    let anonymous_user_id = req
        .server_context("anonymousUserId")?
        .and_then(|value| value.as_str().map(str::to_owned));
    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            redirect_base: req
                .server_context(super::proxy::REDIRECT_BASE_CONTEXT)?
                .and_then(|value| value.as_str().map(str::to_owned)),
            anonymous_user_id,
            provider_name: &body.provider,
            provider,
            callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
            login_hint: body.login_hint.as_deref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone())?,
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

    let callback_url = state_callback_url(body.callback_url.as_deref(), ctx)?;
    super::proxy::validate_callback_url(req, callback_url, ctx)?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    let user = ctx
        .database
        .get_user_by_id(session.user_id().typed()?)
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
            callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
            login_hint: body.login_hint.as_deref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone())?,
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().typed()?.to_string(),
            }),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

pub(super) struct PreparedOAuthFlow {
    pub(super) state: String,
    pub(super) payload: OAuthStatePayload,
    code_challenge: String,
}

pub(super) fn prepare_oauth_flow(request: &FlowStartRequest<'_>) -> PreparedOAuthFlow {
    let (code_verifier, code_challenge) = generate_pkce();
    let state = random_base64url(24);
    let mut payload = OAuthStatePayload::new(
        request.callback_url.to_string(),
        code_verifier,
        request.error_callback_url.clone(),
        request.new_user_callback_url.clone(),
        request.link.clone(),
        request.request_sign_up,
        request.additional_data.clone(),
    );
    payload.oauth_state = Some(state.clone());
    if let Some(user_id) = &request.anonymous_user_id {
        let _ = payload
            .server_context
            .insert("anonymousUserId".into(), serde_json::json!(user_id));
    }
    payload.id_token_nonce = request
        .provider
        .requires_nonce()
        .then(|| random_base64url(24));
    PreparedOAuthFlow {
        state,
        payload,
        code_challenge,
    }
}

pub(super) async fn store_oauth_flow(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    flow: &PreparedOAuthFlow,
) -> AuthResult<()> {
    if matches!(
        ctx.config.account.store_state_strategy(),
        better_auth_core::OAuthStateStrategy::Database
    ) {
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: (flow.state.clone()).into(),
                value: (serde_json::to_string(&flow.payload)?).into(),
                expires_at: (Utc::now() + Duration::minutes(10)).into(),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

pub(super) fn oauth_authorization_url(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: &FlowStartRequest<'_>,
    flow: &PreparedOAuthFlow,
) -> AuthResult<String> {
    build_authorization_url(
        request.provider,
        AuthorizationRequest {
            callback_url: &format!(
                "{}/callback/{}",
                request
                    .redirect_base
                    .clone()
                    .unwrap_or_else(|| auth_base_url(ctx)),
                request.provider_name
            ),
            scopes: request.scopes,
            state: &flow.state,
            code_challenge: &flow.code_challenge,
            login_hint: request.login_hint,
            nonce: flow.payload.id_token_nonce.as_deref(),
            additional_params: request.additional_params,
        },
    )
}

/// Prepare, persist, and authorize a social sign-in or account-link flow.
pub(super) async fn initiate_oauth_flow_core(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let flow = prepare_oauth_flow(&request);
    store_oauth_flow(ctx, &flow).await?;
    let url = oauth_authorization_url(ctx, &request, &flow)?;
    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
            token: None,
            user: None,
        },
        state: flow.state,
        payload: flow.payload,
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
    let body: SocialSignInRequest = super::request::read(req)?;
    let meta = better_auth_core::RequestMeta::from_request_with_config(
        req,
        &ctx.config.advanced.ip_address,
    );
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or(AuthError::Upstream {
                status: 404,
                code: "PROVIDER_NOT_FOUND",
                message: "Provider not found",
            })?;
        return sign_in_with_id_token_core(req, &body, id_token, provider, config, &meta, ctx)
            .await;
    }

    let flow = social_sign_in_core(req, &body, config, ctx).await?;
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy() {
        better_auth_core::OAuthStateStrategy::Database => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_state_cookie(auth_response, &ctx.config, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

pub(crate) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: LinkSocialRequest = super::request::read(req)?;
    let (user, session) = ctx.require_session(req).await?;
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or(AuthError::Upstream {
                status: 404,
                code: "PROVIDER_NOT_FOUND",
                message: "Provider not found",
            })?;
        let response = link_with_id_token_core(req, &body, id_token, provider, &user, ctx).await?;
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

    match ctx.config.account.store_state_strategy() {
        better_auth_core::OAuthStateStrategy::Database => {
            attach_state_cookie(auth_response, &ctx.config, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
