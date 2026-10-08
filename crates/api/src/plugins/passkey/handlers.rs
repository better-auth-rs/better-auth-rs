use better_auth_core::entity::{AuthPasskey, AuthUser};
use better_auth_core::wire::PasskeyView;
use better_auth_core::{
    AuthContext, AuthError, AuthResult, CreateVerification, FieldMap, FieldValue, RequestMeta,
};
use chrono::{Duration, Utc};
use serde_json::Value;
use uuid::Uuid;
use webauthn_rs_core::proto::{COSEAlgorithm, PublicKeyCredential};

use crate::plugins::StatusResponse;
use crate::plugins::helpers::{SessionIssueError, issue_session_for_id};

use super::PasskeyConfig;
use super::credential::WebAuthnCredential;
use super::descriptors::credential_descriptors;
use super::types::{
    DeletePasskeyRequest, PasskeyResponse, UpdatePasskeyRequest, VerifyAuthenticationRequest,
};
use super::webauthn::{
    AuthenticationChallenge, RegistrationChallenge, StoredAuthenticationState,
    StoredRegistrationState, VERIFICATION_POLICY, authentication_options_json, build_webauthn,
    challenge_cookie_name, create_challenge_cookie, credential_id_from_authentication,
    decode_challenge_cookie, generate_ts_user_handle, get_cookie_value, registration_options_json,
    resolve_origins,
};

pub(super) fn response_message<T>(status: u16, message: &str) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(
            status,
            &better_auth_core::types::ErrorCodeMessageResponse {
                code: AuthError::code_from_message(message),
                message: message.to_string(),
            },
        )
        .map_err(AuthError::from)?,
    ))
}

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(better_auth_core::AuthResponse),
}

fn passkey_authentication_failure<T>() -> PasskeyHandlerResult<T> {
    response_message(400, "Authentication failed")
}

fn passkey_not_found<T>() -> PasskeyHandlerResult<T> {
    response_message(401, "Passkey not found")
}

pub(super) async fn generate_register_options_core(
    user: &super::PasskeyRegistrationUser,
    req: &better_auth_core::AuthRequest,
    passkey_name: Option<&str>,
    authenticator_attachment: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(FieldValue, String)> {
    let webauthn = build_webauthn(
        config,
        &ctx.config,
        &[ctx.config.base_url.as_static().unwrap_or("").to_owned()],
    )?;
    let existing_passkeys = ctx.database.list_passkeys_by_user(&user.id).await?;
    let user_name = passkey_name
        .filter(|name| !name.is_empty())
        .unwrap_or(&user.name);
    let user_display_name = user
        .display_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&user.name);
    let users = super::callbacks::Users {
        ctx,
        transaction: None,
    };
    let extensions = super::registration::resolve_extensions(
        &config.registration.extensions,
        super::PasskeyEndpoint::new(ctx, req, &Value::Null, &users),
    )
    .await?;
    let descriptors = credential_descriptors(&existing_passkeys, "excludeCredential")?;
    let exclude_credentials = descriptors
        .iter()
        .map(super::descriptors::CredentialDescriptor::registration_id)
        .collect::<AuthResult<Vec<_>>>()?;
    let builder = webauthn
        .new_challenge_register_builder(Uuid::new_v4().as_bytes(), user_name, user_display_name)
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate register options: {error}"))
        })?
        .user_verification_policy(VERIFICATION_POLICY)
        .credential_algorithms(vec![
            COSEAlgorithm::EDDSA,
            COSEAlgorithm::ES256,
            COSEAlgorithm::RS256,
        ])
        .exclude_credentials(Some(exclude_credentials));
    let (options, state) = webauthn
        .generate_challenge_register(builder)
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate register options: {error}"))
        })?;

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let serialized_state = serde_json::to_string(&StoredRegistrationState {
        user: user.clone(),
        context: req.query_string("context")?.map(str::to_owned),
        state: RegistrationChallenge { rs: state },
    })?;
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: (token.clone()).into(),
            value: (serialized_state).into(),
            expires_at: (expires_at).into(),
            ..Default::default()
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config, &token)?;
    let mut response = registration_options_json(
        options,
        &generate_ts_user_handle(),
        authenticator_attachment,
        &config.authenticator_selection,
        extensions,
    )?;
    let _ = response.insert(
        "excludeCredentials".into(),
        descriptors
            .into_iter()
            .map(super::descriptors::CredentialDescriptor::into_value)
            .collect::<Vec<_>>()
            .into(),
    );
    Ok((response.into(), cookie))
}

pub(super) async fn generate_authenticate_options_core<U: AuthUser>(
    maybe_user: Option<&U>,
    req: &better_auth_core::AuthRequest,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(FieldValue, String)> {
    let webauthn = build_webauthn(
        config,
        &ctx.config,
        &[ctx.config.base_url.as_static().unwrap_or("").to_owned()],
    )?;

    let stored_passkeys = if let Some(user) = maybe_user {
        ctx.database
            .list_passkeys_by_user(user.id().typed()?)
            .await?
    } else {
        Vec::new()
    };
    let users = super::callbacks::Users {
        ctx,
        transaction: None,
    };
    let extensions = super::registration::resolve_extensions(
        &config.authentication.extensions,
        super::PasskeyEndpoint::new(ctx, req, &Value::Null, &users),
    )
    .await?;
    let descriptors = credential_descriptors(&stored_passkeys, "allowCredential")?;
    let discoverable = stored_passkeys.is_empty();
    let (options, state) = webauthn
        .new_challenge_authenticate_builder(Vec::new(), Some(VERIFICATION_POLICY))
        .and_then(|builder| {
            webauthn.generate_challenge_authenticate(builder.allow_backup_eligible_upgrade(true))
        })
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate authenticate options: {error}"))
        })?;
    let state = AuthenticationChallenge { ast: state };
    let state = if discoverable {
        StoredAuthenticationState::Discoverable { state }
    } else {
        StoredAuthenticationState::Passkey { state }
    };

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: (token.clone()).into(),
            value: (serde_json::to_string(&state)?).into(),
            expires_at: (expires_at).into(),
            ..Default::default()
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config, &token)?;
    let mut response = authentication_options_json(options, extensions)?;
    if !descriptors.is_empty() {
        let _ = response.insert(
            "allowCredentials".into(),
            descriptors
                .into_iter()
                .map(super::descriptors::CredentialDescriptor::into_value)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    Ok((response.into(), cookie))
}

pub(super) async fn verify_authentication_core(
    body: &VerifyAuthenticationRequest,
    req: &better_auth_core::AuthRequest,
    config: &PasskeyConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<(FieldValue, better_auth_core::session::SessionData)> {
    let Some(origin) = resolve_origins(config, req) else {
        return response_message(400, "origin missing");
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config, config))
    else {
        return response_message(400, "Challenge not found");
    };
    let token = match decode_challenge_cookie(&ctx.config, &cookie_value) {
        Ok(token) => token,
        Err(_) => return response_message(400, "Challenge not found"),
    };

    let Some(verification) = ctx
        .database
        .consume_verification_by_identifier(&token)
        .await?
    else {
        return response_message(400, "Challenge not found");
    };

    let stored_state: StoredAuthenticationState =
        match serde_json::from_str(&verification.value.display_string()?) {
            Ok(state) => state,
            Err(_) => return response_message(400, "Challenge not found"),
        };
    let authentication: PublicKeyCredential = match serde_json::from_value(body.response.clone()) {
        Ok(authentication) => authentication,
        Err(_) => return passkey_authentication_failure(),
    };
    let credential_id = match credential_id_from_authentication(&authentication) {
        Ok(credential_id) => credential_id,
        Err(_) => return passkey_authentication_failure(),
    };

    let Some(passkey) = ctx
        .database
        .get_passkey_by_credential_id(&credential_id)
        .await?
    else {
        return passkey_not_found();
    };

    let stored_passkey =
        match WebAuthnCredential::from_record(&passkey, ctx.database.passkey_storage()) {
            Ok(passkey) => passkey,
            Err(_) => return passkey_authentication_failure(),
        };
    let webauthn = match build_webauthn(config, &ctx.config, &origin) {
        Ok(webauthn) => webauthn,
        Err(_) => return passkey_authentication_failure(),
    };

    let mut state = match stored_state {
        StoredAuthenticationState::Passkey { state }
        | StoredAuthenticationState::Discoverable { state } => state,
    };
    let Some(flags) = authentication.response.authenticator_data.get(32) else {
        return passkey_authentication_failure();
    };
    // Upstream checks backup flags within the signed assertion, independently of stored flags.
    let mut verification_credential = stored_passkey.cred.clone();
    verification_credential.backup_eligible = flags & 0x08 != 0;
    state
        .ast
        .set_allowed_credentials(vec![verification_credential]);
    let authentication_result = webauthn.authenticate_credential(&authentication, &state.ast);
    let authentication_result = match authentication_result {
        Ok(result) => result,
        Err(_) => return passkey_authentication_failure(),
    };

    if authentication_result.cred_id() != &stored_passkey.cred.cred_id {
        return passkey_authentication_failure();
    }
    // Another challenge can advance the counter after this challenge captures its credentials.
    let counter = u64::from(authentication_result.counter());
    let stored_counter =
        match better_auth_core::query::field_number(&passkey.counter().field_value()) {
            Ok(counter) => counter,
            Err(_) => return passkey_authentication_failure(),
        };
    if (counter > 0 || stored_counter > 0.0) && counter as f64 <= stored_counter {
        return passkey_authentication_failure();
    }
    if let Some(hook) = &config.authentication.after_verification {
        let verification = super::PasskeyAuthenticationVerification {
            verified: true,
            authentication_info: super::PasskeyAuthenticationInfo {
                credential_id: credential_id.clone(),
                new_counter: counter,
                user_verified: authentication_result.user_verified(),
                credential_device_type: if authentication_result.backup_eligible() {
                    "multiDevice"
                } else {
                    "singleDevice"
                },
                credential_backed_up: authentication_result.backup_state(),
                origin: super::webauthn::client_origin(
                    authentication.response.client_data_json.as_ref(),
                )?,
                rp_id: super::webauthn::rp_id(config, &ctx.config)?,
                authenticator_extension_results: super::webauthn::authentication_extensions(
                    authentication.response.authenticator_data.as_ref(),
                )?,
            },
        };
        let users = super::callbacks::Users {
            ctx,
            transaction: None,
        };
        let parsed_body = serde_json::to_value(body)?;
        if let Err(error) = hook
            .after_verification(
                super::PasskeyEndpoint::new(ctx, req, &parsed_body, &users),
                &verification,
                &body.response,
            )
            .await
        {
            return Err(super::registration::verification_error(error, false));
        }
    }
    let update = match stored_passkey.authentication_update(authentication_result.counter()) {
        Ok(update) => update,
        Err(_) => return passkey_authentication_failure(),
    };
    let _updated_passkey = match ctx
        .database
        .update_passkey_authentication(&passkey.id().into_owned(), update)
        .await
    {
        Ok(passkey) => passkey,
        Err(_) => return passkey_authentication_failure(),
    };

    let user_id = passkey.user_id().into_owned();
    let session = issue_session_for_id(
        ctx,
        user_id.clone(),
        &RequestMeta {
            ip_address,
            user_agent,
        },
        ctx.config.session.expires_in(),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)
    .map_err(|error| super::registration::verification_error(error, false))?;
    let user = if user_id.is_truthy()? {
        ctx.database
            .get_user_by_id_field(&user_id)
            .await
            .map_err(|error| super::registration::verification_error(error, false))?
    } else {
        None
    };
    let Some(user) = user else {
        return response_message(500, "User not found");
    };

    Ok(PasskeyHandlerOutcome::Success((
        FieldMap::from(better_auth_core::session::SessionData {
            session: ctx.session_view(&session).await?,
            user: ctx.user_view(&user).await?,
        })
        .into(),
        ctx.session_manager().internal_data(&user, &session).await?,
    )))
}

pub(super) async fn list_user_passkeys_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<PasskeyView>> {
    let passkeys = ctx
        .database
        .list_passkeys_by_user(user.id().typed()?)
        .await?;
    Ok(passkeys.iter().map(PasskeyView::from).collect())
}

pub(super) async fn delete_passkey_core(
    body: &DeletePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if user.id() != passkey.user_id() {
        return Err(AuthError::forbidden("Unauthorized"));
    }

    ctx.database.delete_passkey(&body.id).await?;
    Ok(StatusResponse { status: true })
}

pub(super) async fn update_passkey_core(
    body: &UpdatePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<PasskeyResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if user.id() != passkey.user_id() {
        return Err(AuthError::forbidden(
            "You are not allowed to register this passkey",
        ));
    }

    let updated = ctx
        .database
        .update_passkey_name(&body.id, &body.name)
        .await?;

    Ok(PasskeyResponse {
        passkey: PasskeyView::from(&updated),
    })
}
