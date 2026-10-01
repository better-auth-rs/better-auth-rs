use better_auth_core::entity::{AuthSession, AuthUser};
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
    pub(super) request: &'a AuthRequest,
    pub(super) profile: Option<&'a serde_json::Value>,
    pub(super) body: serde_json::Value,
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
                    self.request,
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
    pub(super) issued: better_auth_core::session::SessionData,
    pub(super) session: SessionView,
    pub(super) user: UserView,
    pub(super) is_register: bool,
    pub(super) account_cookie: Option<AccountCookiePayload>,
}

pub(super) enum OAuthSignInError {
    Auth(AuthError),
    Generic(String),
    Banned(String),
    Admission(crate::plugins::user_admission::UserValidationRejection),
    Endpoint(AuthResponse),
}

impl OAuthSignInError {
    pub(super) fn into_auth_response(self) -> AuthResult<AuthResponse> {
        Ok(match self {
            Self::Auth(error) => return Err(error),
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
            Self::Admission(error) => error.into_auth_error().to_auth_response(),
            Self::Endpoint(response) => response,
        })
    }

    pub(super) fn redirect_parts(self) -> AuthResult<(String, Option<String>)> {
        Ok(match self {
            Self::Auth(error) => return Err(error),
            Self::Generic(message) => (message.replace(' ', "_"), None),
            Self::Banned(message) => ("BANNED_USER".into(), Some(message.clone())),
            Self::Admission(error) => (error.error.clone(), Some(error.message().to_owned())),
            Self::Endpoint(response) => {
                let body: serde_json::Value = serde_json::from_slice(&response.body)?;
                (
                    body.get("code")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            AuthError::internal("OAuth endpoint rejection omitted its error code")
                        })?
                        .to_owned(),
                    body.get("message")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                )
            }
        })
    }
}

impl From<AuthError> for OAuthSignInError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
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

fn account_query_error(
    error: AuthError,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> OAuthSignInError {
    ctx.config.logger.error(
        "Better auth was unable to query your database.\nError: ",
        &[better_auth_core::observability::logger::LogArgument::Error(
            &error,
        )],
    );
    let target = ctx
        .config
        .api_error
        .error_url
        .clone()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| format!("{}/error", super::handlers::auth_base_url(ctx)));
    let location =
        better_auth_core::utils::url::append_query_params(&target, "error=internal_server_error");
    OAuthSignInError::Auth(match location {
        Ok(location) => AuthError::redirect(location),
        Err(error) => error,
    })
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
    let Some(provider_email) = user_info.email()?.filter(|email| !email.is_empty()) else {
        return Err(OAuthSignInError::Generic("email not found".to_string()));
    };

    let account_owner = ctx
        .database
        .get_account_owner(provider_name, &user_info.id)
        .await
        .map_err(|error| account_query_error(error, ctx))?;

    let token_bundle = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )
    .map_err(|error| error.to_string())?;

    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(options.request),
        options.body.clone(),
        ctx,
    );
    endpoint.path = Some(callback_path(options.request));
    if options.request.path() == "/sign-in/social"
        && ctx.metadata.get("anonymous.enabled") == Some(&serde_json::Value::Bool(true))
    {
        endpoint.session = ctx
            .session_manager()
            .resolve(
                options.request,
                better_auth_core::session::SessionRead::Cached,
            )
            .await
            .map_err(|error| error.to_string())?
            .data
            .map(|data| (data.user, data.session));
    }
    if let Some(owner) = account_owner {
        let Some(mut user) = owner.user else {
            return Err(OAuthSignInError::Generic("unable to link account".into()));
        };
        let existing_account = owner.account;
        validate_provider_user(
            user_info,
            existing_account
                .user_id
                .typed()
                .map_err(|error| error.to_string())?,
            provider_name,
            options.profile,
            crate::plugins::user_admission::UserValidationAction::SignIn,
            &endpoint,
        )
        .await?;
        if ctx.config.account.update_account_on_sign_in() {
            let _ = ctx
                .database
                .update_account(
                    existing_account
                        .id
                        .typed()
                        .map_err(|error| error.to_string())?,
                    UpdateAccount {
                        access_token: (token_bundle.access_token.clone())
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        refresh_token: (token_bundle.refresh_token.clone())
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        id_token: (token_bundle.id_token.clone())
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        access_token_expires_at: (tokens.access_token_expires_at)
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        refresh_token_expires_at: (tokens.refresh_token_expires_at)
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        if user_info.email_verified
            && !user.email_verified()
            && user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(provider_email))
        {
            user = ctx
                .database
                .update_user(
                    user.id()
                        .typed()
                        .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
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
                    user.id()
                        .typed()
                        .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
                    UpdateUser {
                        additional_fields: ctx
                            .config
                            .user
                            .parse_provider_input(&user_info.additional_fields, false)
                            .map_err(|error| error.to_string())?,
                        name: user_info
                            .name
                            .clone()
                            .map(|value| Some(value).into())
                            .unwrap_or_default(),
                        image: user_info.image.clone().map(Into::into).unwrap_or_default(),
                        email: Some(provider_email.to_lowercase()),
                        email_verified: Some(
                            user_info.email_verified
                                || (user.email_verified()
                                    && user.email().is_some_and(|email| {
                                        email.eq_ignore_ascii_case(provider_email)
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
            user.id()
                .typed()
                .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie = ctx.config.account.store_account_cookie().then(|| {
            if !ctx.config.account.update_account_on_sign_in() {
                return existing_account.clone();
            }
            AccountCookiePayload {
                provider_id: provider_name.to_owned().into(),
                access_token: token_bundle
                    .access_token
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_else(|| existing_account.access_token.clone()),
                refresh_token: token_bundle
                    .refresh_token
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_else(|| existing_account.refresh_token.clone()),
                id_token: token_bundle
                    .id_token
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_else(|| existing_account.id_token.clone()),
                access_token_expires_at: tokens
                    .access_token_expires_at
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_else(|| existing_account.access_token_expires_at.clone()),
                refresh_token_expires_at: tokens
                    .refresh_token_expires_at
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_else(|| existing_account.refresh_token_expires_at.clone()),
                ..existing_account.clone()
            }
        });

        return Ok(ProcessOAuthUserResult {
            issued: ctx
                .session_manager()
                .internal_data(&issued.user, &issued.session)
                .await
                .map_err(|error| error.to_string())?,
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .await
                .map_err(|error| error.to_string())?,
            is_register: false,
            account_cookie,
        });
    }

    let existing_user = ctx
        .database
        .get_user_with_accounts(&provider_email.to_lowercase())
        .await
        .map_err(|error| account_query_error(error, ctx))?;

    if let Some(existing) = existing_user {
        let existing_user = existing.user;
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = ctx
            .trusted_providers()
            .iter()
            .any(|trusted| trusted == provider_name);

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled()
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
            || (linking.require_local_email_verified && !existing_user.email_verified())
        {
            return Err(OAuthSignInError::Generic("account not linked".to_string()));
        }

        validate_provider_user(
            user_info,
            existing_user
                .id()
                .typed()
                .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
            provider_name,
            options.profile,
            crate::plugins::user_admission::UserValidationAction::LinkAccount,
            &endpoint,
        )
        .await?;
        let mut linked_user = existing_user;
        let created_account = ctx
            .database
            .create_account(CreateAccount {
                user_id: linked_user.id().into_owned(),
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
                access_token_expires_at: (tokens.access_token_expires_at)
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                refresh_token_expires_at: (tokens.refresh_token_expires_at)
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                scope: ((!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")))
                    .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                    .unwrap_or_default(),
                password: Default::default(),
                ..Default::default()
            })
            .await
            .map_err(|_| "unable to link account".to_string())?;

        if user_info.email_verified
            && !linked_user.email_verified()
            && linked_user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(provider_email))
        {
            linked_user = ctx
                .database
                .update_user(
                    linked_user
                        .id()
                        .typed()
                        .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
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
                    linked_user
                        .id()
                        .typed()
                        .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
                    UpdateUser {
                        additional_fields: ctx
                            .config
                            .user
                            .parse_provider_input(&user_info.additional_fields, false)
                            .map_err(|error| error.to_string())?,
                        name: user_info
                            .name
                            .clone()
                            .map(|value| Some(value).into())
                            .unwrap_or_default(),
                        image: user_info.image.clone().map(Into::into).unwrap_or_default(),
                        email: Some(provider_email.to_lowercase()),
                        email_verified: Some(
                            user_info.email_verified
                                || (linked_user.email_verified()
                                    && linked_user.email().is_some_and(|email| {
                                        email.eq_ignore_ascii_case(provider_email)
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
            linked_user
                .id()
                .typed()
                .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie()
            .then(|| created_account.clone());

        Ok(ProcessOAuthUserResult {
            issued: ctx
                .session_manager()
                .internal_data(&issued.user, &issued.session)
                .await
                .map_err(|error| error.to_string())?,
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .await
                .map_err(|error| error.to_string())?,
            is_register: false,
            account_cookie,
        })
    } else {
        if options.disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_string()));
        }

        let mut create_user = CreateUser::new()
            .with_email(provider_email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or(provider_email))
            .with_email_verified(user_info.email_verified);
        create_user.image = user_info.image.clone().map(Into::into).unwrap_or_default();
        create_user.additional_fields = ctx
            .config
            .user
            .parse_provider_input(&user_info.additional_fields, true)
            .map_err(|error| error.to_string())?;

        let context = ctx.clone();
        let request = options.request.clone();
        let admission_body = options.body.clone();
        let admission_session = endpoint.session;
        let source = crate::plugins::user_admission::UserValidationSource::oauth(
            provider_name,
            options.profile,
            crate::plugins::user_admission::UserValidationAction::CreateUser,
        );
        let account = CreateAccount {
            user_id: (String::new()).into(),
            account_id: (user_info.id.clone()).into(),
            provider_id: (provider_name.to_owned()).into(),
            access_token: (token_bundle.access_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            refresh_token: (token_bundle.refresh_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            id_token: (token_bundle.id_token)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            access_token_expires_at: (tokens.access_token_expires_at)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            refresh_token_expires_at: (tokens.refresh_token_expires_at)
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            scope: ((!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            password: Default::default(),
            ..Default::default()
        };
        let outcome = better_auth_core::store::transaction(ctx.database.as_ref(), move |tx| {
            Box::pin(async move {
                let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
                    Some(&request),
                    admission_body,
                    &context,
                );
                endpoint.path = Some(callback_path(&request));
                endpoint.session = admission_session;
                endpoint.transaction = Some(tx);
                if let Err(error) =
                    crate::plugins::user_admission::validate_create(&create_user, source, &endpoint)
                        .await
                {
                    return Err(error.into_auth_error());
                }
                apply_default_role(&context, &mut create_user);
                let user = tx.create_user(create_user).await?;
                let account = tx
                    .create_account(CreateAccount {
                        user_id: user.id().into_owned(),
                        ..account
                    })
                    .await?;
                Ok((user, account))
            })
        })
        .await
        .map_err(|error| match error {
            AuthError::Response(_) => OAuthSignInError::Endpoint(error.to_auth_response()),
            _ => OAuthSignInError::Generic("unable to create user".to_owned()),
        })?;
        let (created_user, created_account) = outcome;

        options
            .check_email_verification(provider, &created_user, true, ctx)
            .await?;
        let issued = issue_user_session(
            ctx,
            created_user
                .id()
                .typed()
                .map_err(|error| OAuthSignInError::Generic(error.to_string()))?,
            meta.ip_address.clone(),
            meta.user_agent.clone(),
        )
        .await
        .map_err(OAuthSignInError::from)?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie()
            .then(|| created_account.clone());

        Ok(ProcessOAuthUserResult {
            issued: ctx
                .session_manager()
                .internal_data(&issued.user, &issued.session)
                .await
                .map_err(|error| error.to_string())?,
            session: ctx
                .session_view(&issued.session)
                .await
                .map_err(|error| error.to_string())?,
            user: ctx
                .user_view(&issued.user)
                .await
                .map_err(|error| error.to_string())?,
            is_register: true,
            account_cookie,
        })
    }
}

pub(crate) async fn sign_in_verified_profile(
    provider_name: &str,
    provider: &super::providers::OAuthProvider,
    user: super::providers::OAuthUserInfoResponse,
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
        &user.user,
        &tokens,
        OAuthSignInOptions {
            request: req,
            profile: Some(&user.data),
            body: req.body_as_json()?,
            disable_sign_up,
            callback_url: "/",
            email_verification: None,
        },
        &better_auth_core::RequestMeta::from_request_with_config(
            req,
            &ctx.config.advanced.ip_address,
        ),
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::Auth(error) => error,
        OAuthSignInError::Generic(message) if message == "email_not_verified" => {
            AuthError::Upstream {
                status: 403,
                code: "EMAIL_NOT_VERIFIED",
                message: "Email not verified",
            }
        }
        OAuthSignInError::Generic(message) => AuthError::authentication_failed(message),
        OAuthSignInError::Banned(message) => AuthError::banned_user(message),
        OAuthSignInError::Admission(error) => error.into_auth_error(),
        OAuthSignInError::Endpoint(response) => response.into(),
    })?;
    ctx.session_manager()
        .set_session_cookie(req, outcome.issued, None)
        .await?;
    Ok(AuthResponse::json(
        200,
        &serde_json::json!({"token": outcome.session.token(), "user": outcome.user}),
    )?)
}

pub(super) async fn validate_provider_user<S: better_auth_core::AuthSchema>(
    user: &OAuthUserInfo,
    user_id: &str,
    provider: &str,
    profile: Option<&serde_json::Value>,
    action: crate::plugins::user_admission::UserValidationAction,
    endpoint: &crate::plugins::endpoint_context::EndpointContext<'_, S>,
) -> Result<(), OAuthSignInError> {
    let mut fields = user.additional_fields.clone();
    let _ = fields.insert("id".into(), user_id.into());
    if let Some(email) = user.email()? {
        let _ = fields.insert("email".into(), email.to_lowercase().into());
    } else if user.email.is_undefined() {
        let _ = fields.remove("email");
    } else {
        let _ = fields.insert("email".into(), serde_json::Value::Null);
    }
    let _ = fields.insert("emailVerified".into(), user.email_verified.into());
    if let Some(name) = &user.name {
        let _ = fields.insert("name".into(), name.clone().into());
    }
    if let Some(image) = &user.image {
        let _ = fields.insert(
            "image".into(),
            image
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        );
    }
    crate::plugins::user_admission::validate(
        crate::plugins::user_admission::UserValidationData {
            user: fields,
            source: crate::plugins::user_admission::UserValidationSource::oauth(
                provider, profile, action,
            ),
        },
        endpoint,
    )
    .await
    .map_err(OAuthSignInError::Admission)
}

pub(super) fn callback_path(request: &AuthRequest) -> &str {
    if request.path().starts_with("/callback/") {
        "/callback/:id"
    } else if request.path().starts_with("/oauth2/callback/") {
        "/oauth2/callback/:providerId"
    } else {
        request.path()
    }
}
