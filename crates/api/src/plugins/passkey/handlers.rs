use base64::Engine;
use better_auth_core::entity::{AuthPasskey, AuthSession, AuthUser, AuthVerification};
use better_auth_core::types::UpdatePasskeyAuthentication;
use better_auth_core::wire::{PasskeyView, SessionView};
use better_auth_core::{AuthContext, AuthError, AuthResult, CreatePasskey, CreateVerification};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs_core::proto::{COSEAlgorithm, PublicKeyCredential, RegisterPublicKeyCredential};

use crate::plugins::StatusResponse;
use crate::plugins::helpers::{SessionIssueError, issue_user_session};

use super::PasskeyConfig;
use super::types::{
    DeletePasskeyRequest, PasskeyResponse, SessionResponse, UpdatePasskeyRequest,
    VerifyAuthenticationRequest, VerifyRegistrationRequest,
};
use super::webauthn::{
    AuthenticationChallenge, RegistrationChallenge, StoredAuthenticationState, StoredPasskey,
    StoredRegistrationState, VERIFICATION_POLICY, authentication_options_json, build_webauthn,
    challenge_cookie_name, create_challenge_cookie, credential_id_from_authentication,
    decode_challenge_cookie, decode_credential_id, extract_registration_metadata,
    generate_ts_user_handle, get_cookie_value, parse_stored_passkey, parse_transports_csv,
    registration_options_json, resolve_origin, snapshot_passkey, transports_to_csv,
};

fn response_message<T>(status: u16, message: &str) -> PasskeyHandlerResult<T> {
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

fn response_null<T>(status: u16) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(status, &Value::Null).map_err(AuthError::from)?,
    ))
}

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(better_auth_core::AuthResponse),
}

fn generation_origin(
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> String {
    if config.origin.is_empty() {
        ctx.config.base_url.clone()
    } else {
        config.origin.clone()
    }
}

fn passkey_registration_failure<T>() -> PasskeyHandlerResult<T> {
    response_message(500, "Failed to verify registration")
}

fn passkey_authentication_failure<T>() -> PasskeyHandlerResult<T> {
    response_message(400, "Authentication failed")
}

fn passkey_not_found<T>() -> PasskeyHandlerResult<T> {
    response_message(403, "Passkey not found")
}

pub(super) async fn generate_register_options_core(
    user: &impl AuthUser,
    passkey_name: Option<&str>,
    authenticator_attachment: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(Value, String)> {
    let webauthn = build_webauthn(config, &ctx.config, &generation_origin(config, ctx))?;
    let existing_passkeys = ctx.database.list_passkeys_by_user(&user.id()).await?;
    let exclude_credentials = existing_passkeys
        .iter()
        .filter_map(|passkey| decode_credential_id(passkey.credential_id()).ok())
        .collect::<Vec<_>>();
    let exclude_credentials_json = existing_passkeys
        .iter()
        .map(|passkey| {
            let mut descriptor = json!({
                "id": passkey.credential_id(),
                "type": "public-key",
            });
            if let Some(transports) = parse_transports_csv(passkey.transports())
                && let Some(object) = descriptor.as_object_mut()
            {
                let _ = object.insert("transports".to_string(), json!(transports));
            }
            descriptor
        })
        .collect::<Vec<_>>();

    let user_name = passkey_name
        .map(str::to_string)
        .or_else(|| user.email().map(str::to_string))
        .unwrap_or_else(|| user.id().into_owned());
    let user_display_name = user
        .email()
        .map(str::to_string)
        .unwrap_or_else(|| user.id().into_owned());
    let builder = webauthn
        .new_challenge_register_builder(Uuid::new_v4().as_bytes(), &user_name, &user_display_name)
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
        user_id: user.id().to_string(),
        state: RegistrationChallenge { rs: state },
    })?;
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: token.clone(),
            value: serialized_state,
            expires_at,
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = registration_options_json(
        options,
        &generate_ts_user_handle(),
        authenticator_attachment,
    )?;
    if let Some(object) = response.as_object_mut() {
        let _ = object.insert(
            "excludeCredentials".to_string(),
            Value::Array(exclude_credentials_json),
        );
    }
    Ok((response, cookie))
}

pub(super) async fn generate_authenticate_options_core<U: AuthUser>(
    maybe_user: Option<&U>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(Value, String)> {
    let webauthn = build_webauthn(config, &ctx.config, &generation_origin(config, ctx))?;

    let stored_passkeys = if let Some(user) = maybe_user {
        ctx.database.list_passkeys_by_user(&user.id()).await?
    } else {
        Vec::new()
    };
    let parsed_passkeys = stored_passkeys
        .iter()
        .filter_map(|passkey| parse_stored_passkey(passkey.credential()).ok())
        .map(|passkey| passkey.cred)
        .collect::<Vec<_>>();
    let allow_credentials_json = stored_passkeys
        .iter()
        .map(|passkey| {
            let mut descriptor = json!({
                "id": passkey.credential_id(),
                "type": "public-key",
            });
            if let Some(transports) = parse_transports_csv(passkey.transports())
                && let Some(object) = descriptor.as_object_mut()
            {
                let _ = object.insert("transports".to_string(), json!(transports));
            }
            descriptor
        })
        .collect::<Vec<_>>();

    let discoverable = parsed_passkeys.is_empty();
    let (options, state) = webauthn
        .new_challenge_authenticate_builder(parsed_passkeys, Some(VERIFICATION_POLICY))
        .and_then(|builder| {
            webauthn.generate_challenge_authenticate(
                builder.allow_backup_eligible_upgrade(!discoverable),
            )
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
            identifier: token.clone(),
            value: serde_json::to_string(&state)?,
            expires_at,
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = authentication_options_json(options)?;
    if let Some(object) = response.as_object_mut() {
        if allow_credentials_json.is_empty() {
            let _ = object.remove("allowCredentials");
        } else {
            let _ = object.insert(
                "allowCredentials".to_string(),
                Value::Array(allow_credentials_json),
            );
        }
    }
    Ok((response, cookie))
}

pub(super) async fn verify_registration_core(
    body: &VerifyRegistrationRequest,
    req: &better_auth_core::AuthRequest,
    user: &impl AuthUser,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<Value> {
    let Some(origin) = resolve_origin(config, req) else {
        return response_null(400);
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config)) else {
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

    let stored_state: StoredRegistrationState = match serde_json::from_str(verification.value()) {
        Ok(state) => state,
        Err(_) => return passkey_registration_failure(),
    };
    if stored_state.user_id != user.id() {
        return response_message(403, "You are not allowed to register this passkey");
    }

    let registration: RegisterPublicKeyCredential =
        match serde_json::from_value(body.response.clone()) {
            Ok(registration) => registration,
            Err(_) => return passkey_registration_failure(),
        };

    let webauthn = match build_webauthn(config, &ctx.config, &origin) {
        Ok(webauthn) => webauthn,
        Err(_) => return passkey_registration_failure(),
    };
    let verified_passkey =
        match webauthn.register_credential(&registration, &stored_state.state.rs, None) {
            Ok(cred) => StoredPasskey { cred },
            Err(_) => return passkey_registration_failure(),
        };
    let snapshot = match snapshot_passkey(&verified_passkey) {
        Ok(snapshot) => snapshot,
        Err(_) => return passkey_registration_failure(),
    };
    let metadata = match extract_registration_metadata(&registration) {
        Ok(metadata) => metadata,
        Err(_) => return passkey_registration_failure(),
    };

    let transports = registration.response.transports.as_ref().map(|transports| {
        transports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    });

    let passkey = match ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id().to_string(),
            name: body.name.clone(),
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(verified_passkey.cred.cred_id.as_ref()),
            public_key: metadata.public_key,
            counter: snapshot.counter,
            device_type: snapshot.device_type().to_string(),
            backed_up: snapshot.backed_up,
            transports: transports_to_csv(&transports),
            credential: snapshot.serialized,
            aaguid: metadata.aaguid,
        })
        .await
    {
        Ok(passkey) => passkey,
        Err(_) => return passkey_registration_failure(),
    };

    Ok(PasskeyHandlerOutcome::Success(serde_json::to_value(
        PasskeyView::from(&passkey),
    )?))
}

pub(super) async fn verify_authentication_core(
    body: &VerifyAuthenticationRequest,
    req: &better_auth_core::AuthRequest,
    config: &PasskeyConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<(Value, String)> {
    let Some(origin) = resolve_origin(config, req) else {
        return response_message(400, "origin missing");
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config)) else {
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

    let stored_state: StoredAuthenticationState = match serde_json::from_str(verification.value()) {
        Ok(state) => state,
        Err(_) => return passkey_authentication_failure(),
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

    let mut stored_passkey = match parse_stored_passkey(passkey.credential()) {
        Ok(passkey) => passkey,
        Err(_) => return passkey_authentication_failure(),
    };
    let webauthn = match build_webauthn(config, &ctx.config, &origin) {
        Ok(webauthn) => webauthn,
        Err(_) => return passkey_authentication_failure(),
    };

    let authentication_result = match stored_state {
        StoredAuthenticationState::Passkey { state } => {
            webauthn.authenticate_credential(&authentication, &state.ast)
        }
        StoredAuthenticationState::Discoverable { mut state } => {
            state
                .ast
                .set_allowed_credentials(vec![stored_passkey.cred.clone()]);
            webauthn.authenticate_credential(&authentication, &state.ast)
        }
    };
    let authentication_result = match authentication_result {
        Ok(result) => result,
        Err(_) => return passkey_authentication_failure(),
    };

    if authentication_result.cred_id() != &stored_passkey.cred.cred_id {
        return passkey_authentication_failure();
    }
    // Another challenge can advance the counter after this challenge captures its credentials.
    let counter = u64::from(authentication_result.counter());
    if (counter > 0 || passkey.counter() > 0) && counter <= passkey.counter() {
        return passkey_authentication_failure();
    }
    stored_passkey.cred.counter = authentication_result.counter();
    stored_passkey.cred.backup_state = authentication_result.backup_state();
    stored_passkey.cred.backup_eligible = authentication_result.backup_eligible();

    let snapshot = match snapshot_passkey(&stored_passkey) {
        Ok(snapshot) => snapshot,
        Err(_) => return passkey_authentication_failure(),
    };
    let device_type = snapshot.device_type().to_string();
    let updated_passkey = match ctx
        .database
        .update_passkey_authentication(
            passkey.id().as_ref(),
            UpdatePasskeyAuthentication {
                credential: snapshot.serialized,
                counter: snapshot.counter,
                backed_up: snapshot.backed_up,
                device_type,
            },
        )
        .await
    {
        Ok(passkey) => passkey,
        Err(_) => return passkey_authentication_failure(),
    };

    let Some(user) = ctx
        .database
        .get_user_by_id(updated_passkey.user_id().as_ref())
        .await?
    else {
        return response_message(500, "User not found");
    };

    let session = match issue_user_session(ctx, &user.id(), ip_address, user_agent)
        .await
        .map_err(SessionIssueError::into_auth_error)
    {
        Ok(issued) => issued.session,
        Err(error) => return Err(error),
    };

    Ok(PasskeyHandlerOutcome::Success((
        serde_json::to_value(SessionResponse {
            session: SessionView::with_fields(&session, &ctx.config.session)?,
            user: ctx.user_view(&user)?,
        })?,
        session.token().to_string(),
    )))
}

pub(super) async fn list_user_passkeys_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<PasskeyView>> {
    let passkeys = ctx.database.list_passkeys_by_user(&user.id()).await?;
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

    if passkey.user_id() != user.id() {
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

    if passkey.user_id() != user.id() {
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
