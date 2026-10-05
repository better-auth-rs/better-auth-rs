use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, CreatePasskey, CreateSession,
    entity::AuthUser,
    store::AuthTransaction,
    wire::{PasskeyView, UserView},
};
use chrono::Utc;
use serde_json::{Map, Value};
use webauthn_rs_core::proto::RegisterPublicKeyCredential;

use super::{
    PasskeyConfig, PasskeyCredential, PasskeyEndpoint, PasskeyExtensions, PasskeyRegistrationInfo,
    PasskeyRegistrationUser, PasskeyRegistrationVerification,
    callbacks::Users,
    credential::WebAuthnCredential,
    handlers::{PasskeyHandlerOutcome, PasskeyHandlerResult, response_message},
    types::VerifyRegistrationRequest,
    webauthn::*,
};

pub(super) async fn optional_session<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
) -> AuthResult<Option<UserView>> {
    Ok(ctx
        .session_manager()
        .resolve(req, better_auth_core::session::SessionRead::Cached)
        .await?
        .data
        .map(|data| data.user))
}

pub(super) async fn registration_session<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    config: &PasskeyConfig,
) -> AuthResult<Option<UserView>> {
    if !config.registration.require_session {
        return optional_session(ctx, req).await;
    }
    let (user, session) = ctx.require_session(req).await?;
    if !crate::plugins::helpers::session_is_fresh(&session, &ctx.config) {
        return Err(AuthError::Upstream {
            status: 403,
            code: "SESSION_NOT_FRESH",
            message: "Session is not fresh",
        });
    }
    Ok(Some(user))
}

pub(super) async fn resolve_user<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    config: &PasskeyConfig,
) -> AuthResult<PasskeyRegistrationUser> {
    if let Some(user) = registration_session(ctx, req, config).await? {
        let name = user
            .email()
            .filter(|email| !email.is_empty())
            .unwrap_or(user.id.typed()?)
            .to_owned();
        return Ok(PasskeyRegistrationUser {
            id: user.id.typed()?.clone(),
            display_name: Some(name.clone()),
            name,
        });
    }
    let resolver = config.registration.resolve_user.as_ref().ok_or(AuthError::Upstream {
        status: 400, code: "RESOLVE_USER_REQUIRED", message: "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
    })?;
    let users = Users {
        ctx,
        transaction: None,
    };
    let user = resolver
        .resolve(
            PasskeyEndpoint::new(ctx, req, &Value::Null, &users),
            req.query_string("context")?,
        )
        .await
        .map_err(generation_error)?;
    if user.id.is_empty() || user.name.is_empty() {
        return Err(invalid_user());
    }
    Ok(user)
}

pub(super) async fn resolve_extensions(
    config: &PasskeyExtensions,
    ctx: PasskeyEndpoint<'_>,
) -> AuthResult<Option<Map<String, Value>>> {
    match config {
        PasskeyExtensions::None => Ok(None),
        PasskeyExtensions::Static(value) => Ok(Some(value.clone())),
        PasskeyExtensions::Dynamic(resolver) => {
            resolver.extensions(ctx).await.map_err(generation_error)
        }
    }
}
fn invalid_user() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "RESOLVED_USER_INVALID",
        message: "Resolved user is invalid",
    }
}
fn forbidden_user() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
        message: "You are not allowed to register this passkey",
    }
}
fn generation_error(error: AuthError) -> AuthError {
    if error.status_code() >= 500
        && !matches!(error, AuthError::Response(_) | AuthError::Upstream { .. })
    {
        better_auth_core::observability::logger::current().error(
            "Passkey options callback failed",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
        better_auth_core::AuthResponse::new(500).into()
    } else {
        error
    }
}
pub(super) fn verification_error(error: AuthError, registration: bool) -> AuthError {
    if error.status_code() >= 500
        && !matches!(error, AuthError::Response(_) | AuthError::Upstream { .. })
    {
        better_auth_core::observability::logger::current().error(
            "Passkey verification failed",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
        if registration {
            AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_VERIFY_REGISTRATION",
                message: "Failed to verify registration",
            }
        } else {
            AuthError::Upstream {
                status: 400,
                code: "AUTHENTICATION_FAILED",
                message: "Authentication failed",
            }
        }
    } else {
        error
    }
}

pub(super) async fn verify_registration_core<S: AuthSchema>(
    body: VerifyRegistrationRequest,
    req: &AuthRequest,
    session_user: Option<UserView>,
    config: &PasskeyConfig,
    ctx: &AuthContext<S>,
) -> PasskeyHandlerResult<(Value, Option<better_auth_core::session::SessionData>)> {
    let Some(origins) = resolve_origins(config, req) else {
        return response_message(400, "Failed to verify registration");
    };
    let Some(cookie) = get_cookie_value(req, &challenge_cookie_name(&ctx.config, config)) else {
        return response_message(400, "Challenge not found");
    };
    let Ok(token) = decode_challenge_cookie(&ctx.config, &cookie) else {
        return response_message(400, "Challenge not found");
    };
    let Some(challenge) = ctx
        .database
        .consume_verification_by_identifier(&token)
        .await?
    else {
        return response_message(400, "Challenge not found");
    };
    let Ok(state) =
        serde_json::from_str::<StoredRegistrationState>(&challenge.value.display_string()?)
    else {
        return response_message(400, "Challenge not found");
    };
    // Optional sessions are read after consuming the challenge, as in the upstream handler.
    let session_user = if config.registration.require_session {
        session_user
    } else {
        optional_session(ctx, req).await?
    };
    if session_user
        .as_ref()
        .is_some_and(|user| user.id != state.user.id)
    {
        return Err(forbidden_user());
    }
    let result = async {
        let registration: RegisterPublicKeyCredential =
            serde_json::from_value(body.response.clone())?;
        let webauthn = build_webauthn(config, &ctx.config, &origins)?;
        let credential = webauthn
            .register_credential(&registration, &state.state.rs, None)
            .map_err(|error| {
                AuthError::internal(format!("WebAuthn registration failed: {error}"))
            })?;
        let stored = WebAuthnCredential::registered(credential, ctx.database.passkey_storage());
        let metadata = extract_registration_metadata(&registration)?;
        let transports = registration
            .response
            .transports
            .as_ref()
            .map(|values| values.iter().map(ToString::to_string).collect::<Vec<_>>());
        let credential_id = URL_SAFE_NO_PAD.encode(stored.cred.cred_id.as_ref());
        let verification = PasskeyRegistrationVerification {
            verified: true,
            registration_info: PasskeyRegistrationInfo {
                fmt: metadata.fmt,
                aaguid: metadata.aaguid.clone().unwrap_or_default(),
                credential: PasskeyCredential {
                    id: credential_id.clone(),
                    public_key: base64::engine::general_purpose::STANDARD
                        .decode(&metadata.public_key)
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                    counter: u64::from(stored.cred.counter),
                    transports: transports.clone(),
                },
                credential_type: "public-key",
                attestation_object: registration.response.attestation_object.as_ref().to_vec(),
                user_verified: stored.cred.user_verified,
                credential_device_type: stored.device_type(),
                credential_backed_up: stored.cred.backup_state,
                origin: client_origin(registration.response.client_data_json.as_ref())?,
                rp_id: rp_id(config, &ctx.config)?,
                authenticator_extension_results: metadata.extensions,
            },
        };
        let input = CreatePasskey {
            user_id: state.user.id.clone(),
            name: body
                .name
                .clone()
                .filter(|name| !name.is_empty())
                .map(|name| Some(name).into())
                .unwrap_or_default(),
            credential_id,
            public_key: metadata.public_key,
            counter: u64::from(stored.cred.counter),
            device_type: stored.device_type().into(),
            backed_up: stored.cred.backup_state,
            transports: Some(transports.unwrap_or_default().join(",")),
            credential: stored.create_state()?,
            aaguid: metadata
                .aaguid
                .map(|aaguid| Some(aaguid).into())
                .unwrap_or_default(),
        };
        let registration = Registration {
            ctx: clone_context(ctx),
            config: config.clone(),
            request: req.clone(),
            state,
            verification,
            input,
            session_user,
            body,
        };
        let create_session = registration.body.create_session == Some(true);
        let (passkey, session) = if create_session {
            let database = ctx.database.clone();
            better_auth_core::store::transaction(database.as_ref(), move |tx| {
                Box::pin(async move { registration.persist(Some(tx)).await })
            })
            .await?
        } else {
            registration.persist(None).await?
        };
        let mut result = serde_json::to_value(PasskeyView::from(&passkey))?;
        let token = if let Some((user, session)) = session {
            if let Some(object) = result.as_object_mut() {
                let _ = object.insert(
                    "session".into(),
                    serde_json::to_value(ctx.session_view(&session).await?)?,
                );
                let _ = object.insert(
                    "user".into(),
                    serde_json::to_value(ctx.user_view(&user).await?)?,
                );
            }
            Some(ctx.session_manager().internal_data(&user, &session).await?)
        } else {
            None
        };
        Ok((result, token))
    }
    .await
    .map_err(|error| verification_error(error, true))?;
    Ok(PasskeyHandlerOutcome::Success(result))
}

struct Registration<S: AuthSchema> {
    ctx: AuthContext<S>,
    config: PasskeyConfig,
    request: AuthRequest,
    state: StoredRegistrationState,
    verification: PasskeyRegistrationVerification,
    input: CreatePasskey,
    session_user: Option<UserView>,
    body: VerifyRegistrationRequest,
}
impl<S: AuthSchema> Registration<S> {
    async fn persist(
        mut self,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<(
        better_auth_core::Passkey,
        Option<(
            better_auth_core::wire::UserView,
            better_auth_core::wire::SessionView,
        )>,
    )> {
        if let Some(hook) = &self.config.registration.after_verification {
            let users = Users {
                ctx: &self.ctx,
                transaction,
            };
            let body = serde_json::to_value(&self.body)?;
            let result = hook
                .after_verification(
                    PasskeyEndpoint::new(&self.ctx, &self.request, &body, &users),
                    &self.verification,
                    &self.state.user,
                    &self.body.response,
                    self.state.context.as_deref(),
                )
                .await?;
            if let Some(user_id) = result.user_id.filter(|id| !id.is_empty()) {
                if self
                    .session_user
                    .as_ref()
                    .is_some_and(|user| user.id != user_id)
                {
                    return Err(forbidden_user());
                }
                self.input.user_id = user_id;
            }
            if self.input.name.is_absent() {
                self.input.name = result
                    .name
                    .map(|name| super::types::trim_name(&name).to_owned())
                    .filter(|name| !name.is_empty())
                    .map(|name| Some(name).into())
                    .unwrap_or_default();
            }
        }
        if self.input.user_id.is_empty() {
            return Err(invalid_user());
        }
        let user = if self.body.create_session == Some(true) {
            Some(
                match transaction {
                    Some(tx) => tx.get_user_by_id(&self.input.user_id).await?,
                    None => {
                        self.ctx
                            .database
                            .get_user_by_id(&self.input.user_id)
                            .await?
                    }
                }
                .ok_or(AuthError::Upstream {
                    status: 500,
                    code: "USER_NOT_FOUND",
                    message: "User not found",
                })?,
            )
        } else {
            None
        };
        let passkey = match transaction {
            Some(tx) => tx.create_passkey(self.input).await?,
            None => self.ctx.database.create_passkey(self.input).await?,
        };
        let session = if let Some(user) = user {
            let _ =
                crate::plugins::helpers::session_user(&self.ctx, user.id().typed()?, transaction)
                    .await
                    .map_err(crate::plugins::helpers::SessionIssueError::into_auth_error)?;
            let input = CreateSession {
                additional_fields: Default::default(),
                user_id: user.id().into_owned(),
                expires_at: Utc::now() + self.ctx.config.session.expires_in(),
                ip_address: self.ctx.config.advanced.ip_address.resolve(&self.request),
                user_agent: self.request.headers.get("user-agent").cloned(),
                impersonated_by: None,
                active_organization_id: None,
            };
            let session = match transaction {
                Some(tx) => tx.create_session_with_deferred_secondary(input).await?,
                None => self.ctx.database.create_session(input).await?,
            };
            Some((user, session))
        } else {
            None
        };
        Ok((passkey, session))
    }
}
fn clone_context<S: AuthSchema>(ctx: &AuthContext<S>) -> AuthContext<S> {
    ctx.clone()
}
