use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    UpdateAccount, UpdateUser,
};

use super::encryption::encrypt_token_set;
use super::providers::{OAuthTokenSet, OAuthUserInfo};
use super::resolved::ResolvedProvider;
use super::state::AccountCookiePayload;
use crate::plugins::helpers::{SessionIssueError, apply_default_role, issue_user_session};

pub(super) struct OAuthSignInOptions<'a> {
    pub(super) disable_sign_up: bool,
    pub(super) callback_url: &'a str,
    pub(super) email_verification:
        Option<&'a crate::plugins::email_verification::EmailVerificationPlugin>,
}

impl OAuthSignInOptions<'_> {
    async fn check_email_verification(
        &self,
        provider: &ResolvedProvider,
        user: &impl AuthUser,
        is_register: bool,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<(), OAuthSignInError> {
        let required = provider
            .generic
            .as_ref()
            .is_some_and(|generic| generic.config.require_email_verification);
        if let Some(plugin) = self.email_verification {
            plugin
                .send_verification_on_oauth_sign_in(
                    user,
                    is_register,
                    required,
                    self.callback_url,
                    ctx,
                )
                .await;
        }
        if required && !user.email_verified() {
            return Err(OAuthSignInError::Generic("email_not_verified".to_owned()));
        }
        Ok(())
    }
}

pub(super) struct ProcessOAuthUserResult {
    pub(super) session: SessionView,
    pub(super) user: UserView,
    pub(super) is_register: bool,
    pub(super) account_cookie: Option<AccountCookiePayload>,
}

pub(super) enum OAuthSignInError {
    Generic(String),
    Banned(String),
}

impl OAuthSignInError {
    pub(super) fn into_auth_response(self) -> AuthResult<AuthResponse> {
        Ok(match self {
            Self::Generic(message) if message == "email_not_verified" => AuthError::Upstream {
                status: 403,
                code: "EMAIL_NOT_VERIFIED",
                message: "Email not verified",
            }
            .to_auth_response(),
            Self::Generic(message) => AuthResponse::json(
                401,
                &serde_json::json!({"code": "OAUTH_LINK_ERROR", "message": message}),
            )?,
            Self::Banned(message) => AuthError::banned_user(message).to_auth_response(),
        })
    }

    pub(super) fn redirect_parts(&self) -> (String, Option<&str>) {
        match self {
            // Upstream turns a plain internal error string into the `error`
            // param verbatim, with no description.
            Self::Generic(message) => (message.replace(' ', "_"), None),
            // An APIError instead redirects with its `code` and message, so the
            // param is the constant, not a lowercased word.
            Self::Banned(message) => ("BANNED_USER".to_string(), Some(message.as_str())),
        }
    }
}

impl From<String> for OAuthSignInError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<SessionIssueError> for OAuthSignInError {
    fn from(value: SessionIssueError) -> Self {
        match value {
            SessionIssueError::Auth(error) => Self::Generic(error.to_string()),
            SessionIssueError::Banned { message } => Self::Banned(message),
        }
    }
}

pub(super) async fn process_oauth_sign_in(
    provider_name: &str,
    provider: &ResolvedProvider,
    user_info: &OAuthUserInfo,
    tokens: &OAuthTokenSet,
    options: OAuthSignInOptions<'_>,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    if user_info.email.is_empty() {
        return Err(OAuthSignInError::Generic("email not found".to_string()));
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
                    &existing_account.id(),
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
            .get_user_by_id(&existing_account.user_id())
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
                    &user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        if provider.config.override_user_info_on_sign_in {
            user = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        additional_fields: ctx
                            .config
                            .user
                            .parse_provider_input(&user_info.additional_fields, false)
                            .map_err(|error| error.to_string())?,
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        email_verified: Some(
                            user_info.email_verified
                                || (user.email_verified()
                                    && user.email().is_some_and(|email| {
                                        email.eq_ignore_ascii_case(&user_info.email)
                                    })),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        options
            .check_email_verification(provider, &user, false, ctx)
            .await?;
        let issued = issue_user_session(
            ctx,
            &user.id(),
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie =
            ctx.config
                .account
                .store_account_cookie
                .then(|| AccountCookiePayload {
                    id: Some(existing_account.id().to_string()),
                    user_id: existing_account.user_id().to_string(),
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
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .map_err(|error| error.to_string())?,
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

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
            || (linking.require_local_email_verified && !existing_user.email_verified())
        {
            return Err(OAuthSignInError::Generic("account not linked".to_string()));
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
                    &linked_user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        if provider.config.override_user_info_on_sign_in {
            linked_user = ctx
                .database
                .update_user(
                    &linked_user.id(),
                    UpdateUser {
                        additional_fields: ctx
                            .config
                            .user
                            .parse_provider_input(&user_info.additional_fields, false)
                            .map_err(|error| error.to_string())?,
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        email_verified: Some(
                            user_info.email_verified
                                || (linked_user.email_verified()
                                    && linked_user.email().is_some_and(|email| {
                                        email.eq_ignore_ascii_case(&user_info.email)
                                    })),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        options
            .check_email_verification(provider, &linked_user, false, ctx)
            .await?;
        let issued = issue_user_session(
            ctx,
            &linked_user.id(),
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .map_err(|error| error.to_string())?,
            is_register: false,
            account_cookie,
        })
    } else {
        if options.disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_string()));
        }

        let mut create_user = CreateUser::new()
            .with_email(user_info.email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or(&user_info.email))
            .with_email_verified(user_info.email_verified);
        apply_default_role(ctx, &mut create_user);
        create_user.image = user_info.image.clone();
        create_user.additional_fields = ctx
            .config
            .user
            .parse_provider_input(&user_info.additional_fields, true)
            .map_err(|error| error.to_string())?;

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

        options
            .check_email_verification(provider, &created_user, true, ctx)
            .await?;
        let issued = issue_user_session(
            ctx,
            &created_user.id(),
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .map_err(|error| error.to_string())?,
            is_register: true,
            account_cookie,
        })
    }
}

pub(crate) async fn sign_in_verified_profile(
    provider_name: &str,
    provider: &super::providers::OAuthProvider,
    user: OAuthUserInfo,
    tokens: OAuthTokenSet,
    disable_sign_up: bool,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let outcome = process_oauth_sign_in(
        provider_name,
        &ResolvedProvider {
            config: provider.clone(),
            generic: None,
        },
        &user,
        &tokens,
        OAuthSignInOptions {
            disable_sign_up,
            callback_url: "/",
            email_verification: None,
        },
        &better_auth_core::RequestMeta::from_request(req),
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::Generic(message) if message == "email_not_verified" => {
            AuthError::Upstream {
                status: 403,
                code: "EMAIL_NOT_VERIFIED",
                message: "Email not verified",
            }
        }
        OAuthSignInError::Generic(message) => AuthError::authentication_failed(message),
        OAuthSignInError::Banned(message) => AuthError::banned_user(message),
    })?;
    Ok(AuthResponse::json(
        200,
        &serde_json::json!({"token": outcome.session.token(), "user": outcome.user}),
    )?
    .with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_session_cookie(
            outcome.session.token(),
            &ctx.config,
        ),
    ))
}
