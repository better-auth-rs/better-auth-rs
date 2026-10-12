use better_auth_core::entity::AuthPasskey;
use better_auth_core::wire::PasskeyView;
use better_auth_core::{
    AuthContext, AuthError, AuthResult, CreateVerification, FieldMap, FieldValue, RequestMeta,
};
use chrono::{Duration, Utc};
use serde_json::Value;
use uuid::Uuid;
use webauthn_rs_core::proto::COSEAlgorithm;

use crate::plugins::StatusResponse;
use crate::plugins::helpers::{SessionIssueError, issue_session_for_id_optional};

use super::PasskeyConfig;
use super::descriptors::credential_descriptors;
use super::types::{
    DeletePasskeyRequest, PasskeyResponse, UpdatePasskeyRequest, VerifyAuthenticationRequest,
};
use super::webauthn::{
    VERIFICATION_POLICY, authentication_options_json, build_webauthn, create_challenge_cookie,
    generate_ts_user_handle, registration_options_json, resolve_origins,
};

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
    let existing_passkeys = ctx
        .database
        .list_passkeys_by_user_value(&user.id.field_value())
        .await?;
    let user_name = passkey_name.filter(|name| !name.is_empty()).map_or_else(
        || {
            let name = user.name.field_value();
            if name.is_truthy() {
                name
            } else {
                user.id.field_value()
            }
        },
        Into::into,
    );
    let user_display_name = if user.display_name.is_truthy()? {
        user.display_name.field_value()
    } else {
        let name = user.name.field_value();
        if name.is_truthy() {
            name
        } else {
            user.id.field_value()
        }
    };
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
    // WebAuthn requires nonempty labels; the response replaces these internal labels with the native values below.
    let builder = webauthn
        .new_challenge_register_builder(Uuid::new_v4().as_bytes(), "user", "user")
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
    let (options, _) = webauthn
        .generate_challenge_register(builder)
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate register options: {error}"))
        })?;

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let serialized_state = super::challenge::registration_value(
        options.public_key.challenge.as_ref(),
        user,
        req.query_string("context")?,
    )?;
    let _ = ctx
        .database
        .create_verification_optional(CreateVerification {
            identifier: (token.clone()).into(),
            value: better_auth_core::SchemaValue::from_field(serialized_state),
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
    let mut identity = response
        .get("user")
        .and_then(FieldValue::as_object)
        .ok_or_else(|| AuthError::internal("Registration options omitted the user object"))?
        .snapshot_fields()?;
    let _ = identity.insert("name".into(), user_name);
    let _ = identity.insert("displayName".into(), user_display_name);
    let _ = response.insert("user".into(), identity.into());
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

pub(super) async fn generate_authenticate_options_core(
    user_id: Option<&FieldValue>,
    req: &better_auth_core::AuthRequest,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(FieldValue, String)> {
    let webauthn = build_webauthn(
        config,
        &ctx.config,
        &[ctx.config.base_url.as_static().unwrap_or("").to_owned()],
    )?;

    let stored_passkeys = if let Some(user_id) = user_id {
        ctx.database.list_passkeys_by_user_value(user_id).await?
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
    let (options, _) = webauthn
        .new_challenge_authenticate_builder(Vec::new(), Some(VERIFICATION_POLICY))
        .and_then(|builder| {
            webauthn.generate_challenge_authenticate(builder.allow_backup_eligible_upgrade(true))
        })
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate authenticate options: {error}"))
        })?;
    let state =
        super::challenge::authentication_value(options.public_key.challenge.as_ref(), user_id)?;

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let _ = ctx
        .database
        .create_verification_optional(CreateVerification {
            identifier: (token.clone()).into(),
            value: better_auth_core::SchemaValue::from_field(state),
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
) -> AuthResult<FieldValue> {
    let Some(origin) = resolve_origins(config, req) else {
        return Err(AuthError::from_status(
            "BAD_REQUEST",
            FieldMap::from([("message".into(), "origin missing".into())]).into(),
        ));
    };

    let stored_state =
        super::challenge::consume(ctx, req, config, super::challenge::Ceremony::Authentication)
            .await?;
    let credential_id = body.response.model_property("id")?;

    let Some(passkey) = ctx
        .database
        .get_passkey_by_credential_id_value(&credential_id)
        .await?
    else {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "PASSKEY_NOT_FOUND",
            "Passkey not found",
        ));
    };

    async {
        let prepared = super::credential::PreparedCredential::from_record(
            &passkey, ctx.database.passkey_storage(),
        )?;
        let expected_challenge = stored_state.model_property("expectedChallenge")?;
        let authentication = super::verification::authentication_response(
            &body.response, &expected_challenge, &origin,
        )?;
        let stored_passkey = prepared.into_credential(&passkey, &authentication.id)?;
        let webauthn = build_webauthn(config, &ctx.config, &origin)?;
        let Some(flags) = authentication.response.authenticator_data.get(32) else {
            return Err(AuthError::internal("Authenticator data was shorter than 37 bytes"));
        };
        // Upstream checks backup flags within the signed assertion, independently of stored flags.
        let mut verification_credential = stored_passkey.cred.clone();
        verification_credential.backup_eligible = flags & 0x08 != 0;
        let state = super::challenge::authentication_state(
            &webauthn, &expected_challenge, verification_credential,
        )?;
        let authentication_result = webauthn.authenticate_credential(&authentication, &state);
        if matches!(
            authentication_result,
            Ok(_)
                | Err(webauthn_rs_core::error::WebauthnError::AuthenticationFailure)
                | Err(webauthn_rs_core::error::WebauthnError::CredentialPossibleCompromise)
                | Err(webauthn_rs_core::error::WebauthnError::CredentialMayNotBeHardwareBound)
        ) {
            // The engine checks backup flags and signatures before counters; upstream checks counters first.
            let data = webauthn_rs_core::internals::AuthenticatorData::<
                webauthn_rs_core::proto::Authentication,
            >::try_from(authentication.response.authenticator_data.as_ref())
            .map_err(|error| AuthError::internal(error.to_string()))?;
            validate_counter(data.counter, &passkey.counter().field_value())?;
        }
        let authentication_result = match authentication_result {
            Ok(result) => result,
            Err(webauthn_rs_core::error::WebauthnError::AuthenticationFailure) => {
                return Err(AuthError::from_code(
                    "UNAUTHORIZED",
                    "AUTHENTICATION_FAILED",
                    "Authentication failed",
                ));
            }
            Err(webauthn_rs_core::error::WebauthnError::InvalidRPIDHash) => {
                let error = AuthError::internal("Unexpected RP ID hash").into_thrown_value()?;
                error.set_model_property("name", "UnexpectedRPIDHash".into())?;
                return Err(AuthError::from_thrown(error));
            }
            Err(webauthn_rs_core::error::WebauthnError::CredentialMayNotBeHardwareBound) => {
                let error = AuthError::internal(
                    "Single-device credential indicated that it was backed up, which should be impossible.",
                )
                .into_thrown_value()?;
                error.set_model_property("name", "InvalidBackupFlags".into())?;
                return Err(AuthError::from_thrown(error));
            }
            Err(error) => return Err(AuthError::internal(error.to_string())),
        };

        if authentication_result.cred_id() != &stored_passkey.cred.cred_id {
            return Err(AuthError::internal("Authentication credential ID did not match the selected key"));
        }
        let counter = u64::from(authentication_result.counter());
        if let Some(hook) = &config.authentication.after_verification {
            let verification = super::PasskeyAuthenticationVerification {
                verified: true,
                authentication_info: super::PasskeyAuthenticationInfo {
                    credential_id: passkey.credential_id().clone(),
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
            let parsed_body = req.input_body()?.unwrap_or(Value::Null);
            let client_data = parsed_body.get("response").unwrap_or(&Value::Null);
            hook.after_verification(
                super::PasskeyEndpoint::new(ctx, req, &parsed_body, &users),
                &verification,
                client_data,
            )
            .await?;
        }
        let update = stored_passkey.authentication_update(authentication_result.counter())?;
        let _updated_passkey = ctx
            .database
            .update_passkey_authentication_optional(&passkey.id().into_owned(), update)
            .await?;

        let user_id = passkey.user_id().into_owned();
        let session = issue_session_for_id_optional(
            ctx,
            user_id.clone(),
            &RequestMeta {
                ip_address,
                user_agent,
            },
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        let Some(session) = session else {
            return Err(AuthError::from_code(
                "INTERNAL_SERVER_ERROR",
                "UNABLE_TO_CREATE_SESSION",
                "Unable to create session",
            ));
        };
        let user = if user_id.is_truthy()? {
            ctx.database.get_user_by_id_field(&user_id).await?
        } else {
            None
        };
        let Some(user) = user else {
            return Err(AuthError::from_status(
                "INTERNAL_SERVER_ERROR",
                FieldMap::from([("message".into(), "User not found".into())]).into(),
            ));
        };

        let manager = ctx.session_manager();
        manager
            .set_session_cookie(req, manager.internal_data(&user, &session).await?, None)
            .await?;
        Ok(
            FieldMap::from(better_auth_core::session::SessionData {
                session: ctx.session_view(&session).await?,
                user: ctx.user_view(&user).await?,
            })
            .into(),
        )
    }
    .await
    .map_err(|error| super::registration::verification_error(error, false))
}

fn validate_counter(counter: u32, stored: &FieldValue) -> AuthResult<()> {
    use std::cmp::Ordering;

    let value = FieldValue::Number(f64::from(counter));
    if (value.is_truthy()
        || better_auth_core::query::field_compare(stored, &0.0.into())? == Some(Ordering::Greater))
        && matches!(
            better_auth_core::query::field_compare(&value, stored)?,
            Some(Ordering::Less | Ordering::Equal)
        )
    {
        let mut message = format!("Response counter value {counter} was lower than expected ")
            .encode_utf16()
            .collect::<Vec<_>>();
        message.extend_from_slice(stored.display_utf16()?.as_utf16());
        let error = AuthError::internal("").into_thrown_value()?;
        error.set_model_property(
            "message",
            better_auth_core::Utf16String::from_units(message).into(),
        )?;
        return Err(AuthError::from_thrown(error));
    }
    Ok(())
}

pub(super) async fn list_user_passkeys_core(
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<PasskeyView>> {
    let passkeys = ctx.database.list_passkeys_by_user_value(user_id).await?;
    Ok(passkeys.iter().map(PasskeyView::from).collect())
}

pub(super) async fn delete_passkey_core(
    body: &DeletePasskeyRequest,
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    require_passkey_owner(&body.id, user_id, ctx, empty_unauthorized()).await?;

    ctx.database.delete_passkey(&body.id).await?;
    Ok(StatusResponse { status: true })
}

pub(super) async fn update_passkey_core(
    body: &UpdatePasskeyRequest,
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<PasskeyResponse> {
    require_passkey_owner(
        &body.id,
        user_id,
        ctx,
        AuthError::from_code(
            "UNAUTHORIZED",
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            "You are not allowed to register this passkey",
        ),
    )
    .await?;

    let updated = ctx
        .database
        .update_passkey_optional(
            &body.id.to_owned().into(),
            better_auth_core::UpdatePasskey {
                name: Some(body.name.clone()).into(),
                ..Default::default()
            },
        )
        .await?
        .ok_or_else(|| {
            AuthError::from_code(
                "INTERNAL_SERVER_ERROR",
                "FAILED_TO_UPDATE_PASSKEY",
                "Failed to update passkey",
            )
        })?;

    Ok(PasskeyResponse {
        passkey: PasskeyView::from(&updated),
    })
}

fn empty_unauthorized() -> AuthError {
    AuthError::from_status("UNAUTHORIZED", FieldValue::Undefined)
}

async fn require_passkey_owner(
    id: &str,
    owner: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    forbidden: AuthError,
) -> AuthResult<()> {
    if !owner.is_truthy() {
        return Err(empty_unauthorized());
    }
    if id.is_empty() {
        return Err(AuthError::from_status(
            "BAD_REQUEST",
            FieldMap::from([("message".into(), "Missing required parameter: id".into())]).into(),
        ));
    }
    let passkey = ctx.database.get_passkey_by_id(id).await?.ok_or_else(|| {
        AuthError::from_code("NOT_FOUND", "PASSKEY_NOT_FOUND", "Passkey not found")
    })?;
    if !passkey.user_id().field_value().strict_equals(owner) {
        return Err(forbidden);
    }
    Ok(())
}
