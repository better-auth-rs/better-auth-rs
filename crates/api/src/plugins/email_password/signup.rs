use crate::plugins::{
    email_verification::EmailVerificationPlugin,
    helpers::{apply_default_role, apply_user_create_fields},
};
use async_trait::async_trait;
use better_auth_core::utils::password as password_utils;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, AuthSession, AuthUser,
    CreateAccount, CreateSession, CreateUser, RequestMeta, wire::UserView,
};
use serde_json::{Map, Value, json};

use super::{EmailPasswordConfig, SignUpRequest, SignUpResponse};

/// Notification for a duplicate signup protected against account enumeration.
#[async_trait]
pub trait OnExistingUserSignUp: Send + Sync {
    /// Inspect the existing account and the signup request without returning that account to the client.
    async fn on_existing_user_sign_up(
        &self,
        user: &UserView,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()>;
}

/// Input to the synchronous enumeration-safe user factory.
pub struct SyntheticUserInput {
    /// Submitted core fields and fresh timestamps. The account identifier is provided separately.
    pub core_fields: Map<String, Value>,
    /// Parsed fields from the application's user schema, excluding plugin-owned fields.
    pub additional_fields: Map<String, Value>,
    /// Fresh identifier that is never persisted.
    pub id: String,
}

/// Customize a synthetic signup user before the public user schema filters the response.
pub type CustomSyntheticUser =
    dyn Fn(SyntheticUserInput) -> AuthResult<Map<String, Value>> + Send + Sync;

type SignUpResult = SignUpResponse<Map<String, Value>>;

pub(super) fn synthetic_response<S: AuthSchema>(
    body: &SignUpRequest,
    create: &CreateUser,
    config: &EmailPasswordConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<SignUpResult> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut core = Map::from_iter([
        ("name".into(), json!(body.name)),
        ("email".into(), json!(body.email.to_lowercase())),
        ("emailVerified".into(), json!(false)),
        ("image".into(), json!(body.image)),
        ("createdAt".into(), json!(now)),
        ("updatedAt".into(), json!(now)),
    ]);
    let id = uuid::Uuid::new_v4().to_string();
    let data = if let Some(factory) = &config.custom_synthetic_user {
        factory(SyntheticUserInput {
            core_fields: core,
            additional_fields: create.additional_fields.clone(),
            id,
        })?
    } else {
        core.extend(create.additional_fields.clone());
        for (name, value) in [
            ("username", create.username.as_ref()),
            ("displayUsername", create.display_username.as_ref()),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), json!(value));
            }
        }
        if let Some(phone) = &create.phone_number {
            let _ = core.insert("phoneNumber".into(), json!(phone));
        }
        let _ = core.insert("id".into(), json!(id));
        core
    };
    Ok(SignUpResponse {
        token: None,
        user: UserView::synthetic_output(data, &ctx.config.user, &ctx.metadata),
    })
}

/// Core sign-up logic.
///
/// Issue the session before transaction after hooks run, as in the upstream signup endpoint.
pub(super) async fn sign_up_core<S: AuthSchema>(
    body: &SignUpRequest,
    endpoint_body: Value,
    config: &EmailPasswordConfig,
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<SignUpResult> {
    if !config.enable_signup {
        return Err(AuthError::forbidden("User registration is not enabled"));
    }

    password_utils::validate_password(
        &body.password,
        ctx.password_policy.min_length,
        ctx.password_policy.max_length,
        ctx,
    )?;

    let mut create_user = CreateUser::new()
        .with_email(body.email.to_lowercase())
        .with_name(&body.name);
    apply_user_create_fields(ctx, &body.additional_fields, &mut create_user)?;
    create_user.image = body.image.clone();
    let protect_enumeration = config.require_email_verification || !config.auto_sign_in;
    if let Some(user) = ctx
        .database
        .get_user_by_email(&body.email.to_lowercase())
        .await?
    {
        if !protect_enumeration {
            return Err(AuthError::UnprocessableEntity(
                "User already exists. Use another email.".into(),
            ));
        }
        let _ = password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.password)
            .await?;
        if let Some(callback) = &config.on_existing_user_sign_up {
            let user = ctx.internal_user_view(&user)?;
            if let Err(error) = callback.on_existing_user_sign_up(&user, Some(req)).await {
                // Upstream runs this notification through runInBackgroundOrAwait, which logs failures.
                tracing::error!(%error, "Existing-user signup notification failed");
            }
        }
        return synthetic_response(body, &create_user, config, ctx);
    }
    let password_hash =
        password_utils::hash_password(ctx.password_policy.hasher.as_ref(), &body.password).await?;
    let synthetic_create = create_user.clone();
    apply_default_role(ctx, &mut create_user);
    let auto_sign_in = config.auto_sign_in && !config.require_email_verification;
    let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
    let expires_in = if body.remember_me == Some(false) {
        chrono::Duration::days(1)
    } else {
        ctx.config.session.expires_in
    };
    let ip_address = meta.ip_address.clone();
    let user_agent = meta.user_agent.clone();
    let database = ctx.database.clone();
    let transaction_database = database.clone();
    let user_config = ctx.config.user.clone();
    let adapter_user_config = ctx.adapter_user_fields().clone();
    let user_metadata = ctx.metadata.clone();
    let supports_native_json = database.supports_native_json();

    let dont_remember = body.remember_me == Some(false);
    let admission_context = ctx.clone();
    let admission_request = req.clone();
    let mut admission_input = synthetic_create.clone();
    admission_input.email_verified = Some(false);
    let result: Option<SignUpResult> =
        better_auth_core::store::transaction(database.as_ref(), move |tx| {
            let _database = transaction_database.clone();
            Box::pin(async move {
                let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
                    Some(&admission_request),
                    endpoint_body,
                    &admission_context,
                );
                endpoint.transaction = Some(tx);
                let admitted = crate::plugins::user_admission::validate_create(
                    &admission_input,
                    crate::plugins::user_admission::UserValidationSource::new(
                        "email-password",
                        crate::plugins::user_admission::UserValidationAction::CreateUser,
                    ),
                    &endpoint,
                )
                .await;
                if let Err(error) = admitted {
                    if protect_enumeration {
                        return Ok(None);
                    }
                    return Err(error.into_auth_error());
                }
                let user = match tx.create_user(create_user).await {
                    Ok(user) => user,
                    Err(error) if protect_enumeration && error.status_code() == 403 => {
                        return Ok(None);
                    }
                    Err(AuthError::Database(_)) => {
                        return Err(AuthError::UnprocessableEntity(
                            "Failed to create user".to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                };

                let _ = tx
                    .create_account(CreateAccount {
                        user_id: user.id().to_string(),
                        account_id: user.id().to_string(),
                        provider_id: "credential".to_string(),
                        access_token: None,
                        refresh_token: None,
                        id_token: None,
                        access_token_expires_at: None,
                        refresh_token_expires_at: None,
                        scope: None,
                        password: Some(password_hash.clone()),
                    })
                    .await?;

                if auto_sign_in {
                    let session = tx
                        .create_session(CreateSession {
                            user_id: user.id().to_string(),
                            expires_at: chrono::Utc::now() + expires_in,
                            ip_address,
                            user_agent,
                            impersonated_by: None,
                            active_organization_id: None,
                        })
                        .await?;
                    let token = session.token().to_string();

                    let manager = admission_context.session_manager();
                    let data = manager.internal_data(&user, &session).await?;
                    manager
                        .set_session_cookie_in_transaction(
                            &admission_request,
                            data,
                            Some(dont_remember),
                            tx,
                        )
                        .await?;
                    Ok(Some(SignUpResponse {
                        token: Some(token),
                        user: UserView::with_field_policies(
                            &user,
                            &adapter_user_config,
                            &user_config,
                            &user_metadata,
                            supports_native_json,
                        )?
                        .into(),
                    }))
                } else {
                    Ok(Some(SignUpResponse {
                        token: None,
                        user: UserView::with_field_policies(
                            &user,
                            &adapter_user_config,
                            &user_config,
                            &user_metadata,
                            supports_native_json,
                        )?
                        .into(),
                    }))
                }
            })
        })
        .await?;
    let Some(response) = result else {
        return synthetic_response(body, &synthetic_create, config, ctx);
    };
    let verification = EmailVerificationPlugin::from_context(ctx);
    if let Some(verification) = verification {
        let user = UserView::try_from(response.user.clone())?;
        if let Err(error) = verification
            .send_verification_on_sign_up(
                &user,
                config.require_email_verification,
                Some(req),
                body.callback_url.as_deref(),
                ctx,
            )
            .await
        {
            // Delivery is a background-compatible notification in the upstream signup route.
            tracing::error!(%error, "Signup verification email failed");
        }
    }
    Ok(response)
}
