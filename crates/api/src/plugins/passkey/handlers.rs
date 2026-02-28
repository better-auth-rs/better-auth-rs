use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthPasskey, AuthSession, AuthUser};
use better_auth_core::{AuthContext, CreatePasskey, CreateVerification};
use better_auth_core::{AuthError, AuthResult};

use crate::plugins::StatusResponse;

use super::PasskeyConfig;
use super::types::{
    DeletePasskeyRequest, PasskeyResponse, PasskeyView, SessionUserResponse, UpdatePasskeyRequest,
    VerifyAuthenticationRequest, VerifyRegistrationRequest,
};

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

pub(super) fn generate_challenge() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn ensure_insecure_verification_enabled(config: &PasskeyConfig) -> AuthResult<()> {
    if config.allow_insecure_unverified_assertion {
        Ok(())
    } else {
        Err(AuthError::not_implemented(
            "Passkey verification requires full WebAuthn signature validation. \
            Set `allow_insecure_unverified_assertion = true` only for local development.",
        ))
    }
}

pub(super) fn decode_client_data_json(
    response: &serde_json::Value,
) -> AuthResult<serde_json::Value> {
    let encoded = response
        .get("response")
        .and_then(|r| r.get("clientDataJSON"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON in response"))?;

    let decode_and_parse = |bytes: Vec<u8>| -> Option<serde_json::Value> {
        serde_json::from_slice::<serde_json::Value>(&bytes).ok()
    };

    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded)
        && let Some(client_data) = decode_and_parse(bytes)
    {
        return Ok(client_data);
    }

    if let Ok(bytes) = STANDARD.decode(encoded)
        && let Some(client_data) = decode_and_parse(bytes)
    {
        return Ok(client_data);
    }

    Err(AuthError::bad_request("Invalid clientDataJSON encoding"))
}

pub(super) fn validate_client_data(
    config: &PasskeyConfig,
    client_data: &serde_json::Value,
    expected_type: &str,
) -> AuthResult<String> {
    let client_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.type"))?;

    if client_type != expected_type {
        return Err(AuthError::bad_request(format!(
            "Invalid clientDataJSON.type, expected {}",
            expected_type
        )));
    }

    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.origin"))?;

    if origin != config.origin {
        return Err(AuthError::bad_request("Invalid clientDataJSON.origin"));
    }

    let challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.challenge"))?;

    Ok(challenge.to_string())
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn generate_register_options_core<DB: DatabaseAdapter>(
    user: &DB::User,
    authenticator_attachment: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<serde_json::Value> {
    let challenge = generate_challenge();

    // Store challenge as a verification token
    let identifier = format!("passkey_reg:{}", user.id());
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(config.challenge_ttl_secs);
    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: challenge.clone(),
            expires_at,
        })
        .await?;

    // Build excludeCredentials from existing passkeys
    let existing_passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
    let exclude_credentials: Vec<serde_json::Value> = existing_passkeys
        .iter()
        .map(|pk| {
            let mut cred = serde_json::json!({
                "type": "public-key",
                "id": pk.credential_id(),
            });
            if let Some(transports) = pk.transports()
                && let Ok(t) = serde_json::from_str::<Vec<String>>(transports)
            {
                cred["transports"] = serde_json::json!(t);
            }
            cred
        })
        .collect();

    let authenticator_attachment = authenticator_attachment.unwrap_or("platform");

    let user_id_b64 = URL_SAFE_NO_PAD.encode(user.id().as_bytes());
    let display_name = user
        .name()
        .unwrap_or_else(|| user.email().unwrap_or("user"));
    let user_name = user
        .email()
        .unwrap_or_else(|| user.name().unwrap_or("user"));

    let options = serde_json::json!({
        "challenge": challenge,
        "rp": {
            "name": config.rp_name,
            "id": config.rp_id,
        },
        "user": {
            "id": user_id_b64,
            "name": user_name,
            "displayName": display_name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 },
        ],
        "timeout": 60000,
        "excludeCredentials": exclude_credentials,
        "authenticatorSelection": {
            "authenticatorAttachment": authenticator_attachment,
            "requireResidentKey": false,
            "userVerification": "preferred",
        },
        "attestation": "none",
    });

    Ok(options)
}

pub(crate) async fn verify_registration_core<DB: DatabaseAdapter>(
    body: &VerifyRegistrationRequest,
    user: &DB::User,
    config: &PasskeyConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<PasskeyView> {
    ensure_insecure_verification_enabled(config)?;

    let client_data = decode_client_data_json(&body.response)?;
    let challenge = validate_client_data(config, &client_data, "webauthn.create")?;

    // Atomically consume the challenge (single-use)
    let identifier = format!("passkey_reg:{}", user.id());
    ctx.database
        .consume_verification(&identifier, &challenge)
        .await?
        .ok_or_else(|| {
            AuthError::bad_request(
                "Invalid or expired registration challenge. Please generate registration options again.",
            )
        })?;

    // Extract credential data from the client response
    let resp = &body.response;
    let credential_id = resp
        .get("id")
        .or_else(|| resp.get("rawId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing credential id in response"))?;

    // Extract public key from attestation response
    let public_key = resp
        .get("response")
        .and_then(|r| r.get("attestationObject"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            resp.get("response")
                .and_then(|r| r.get("clientDataJSON"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();

    // Extract device type and backup info
    let authenticator_attachment = resp
        .get("authenticatorAttachment")
        .and_then(|v| v.as_str())
        .unwrap_or("platform");

    let device_type = if authenticator_attachment == "cross-platform" {
        "multiDevice"
    } else {
        "singleDevice"
    }
    .to_string();

    let backed_up = resp
        .get("clientExtensionResults")
        .and_then(|v| v.get("credProps"))
        .and_then(|v| v.get("rk"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let transports = resp
        .get("response")
        .and_then(|r| r.get("transports"))
        .map(|v| v.to_string());

    let passkey_name = body
        .name
        .clone()
        .unwrap_or_else(|| format!("Passkey {}", chrono::Utc::now().format("%Y-%m-%d")));

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id().to_string(),
            name: passkey_name,
            credential_id: credential_id.to_string(),
            public_key,
            counter: 0,
            device_type,
            backed_up,
            transports,
        })
        .await?;

    Ok(PasskeyView::from_entity(&passkey))
}

pub(crate) async fn generate_authenticate_options_core<DB: DatabaseAdapter>(
    maybe_user: Option<&DB::User>,
    config: &PasskeyConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<serde_json::Value> {
    let challenge = generate_challenge();

    // If user is provided, build allowCredentials from their passkeys
    let allow_credentials: Vec<serde_json::Value> = if let Some(user) = maybe_user {
        let passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
        passkeys
            .iter()
            .map(|pk| {
                let mut cred = serde_json::json!({
                    "type": "public-key",
                    "id": pk.credential_id(),
                });
                if let Some(transports) = pk.transports()
                    && let Ok(t) = serde_json::from_str::<Vec<String>>(transports)
                {
                    cred["transports"] = serde_json::json!(t);
                }
                cred
            })
            .collect()
    } else {
        vec![]
    };

    // Store challenge with the challenge itself as part of the identifier
    let identifier = format!("passkey_auth:{}", challenge);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(config.challenge_ttl_secs);
    ctx.database
        .create_verification(CreateVerification {
            identifier,
            value: challenge.clone(),
            expires_at,
        })
        .await?;

    let options = serde_json::json!({
        "challenge": challenge,
        "timeout": 60000,
        "rpId": config.rp_id,
        "allowCredentials": allow_credentials,
        "userVerification": "preferred",
    });

    Ok(options)
}

pub(crate) async fn verify_authentication_core<DB: DatabaseAdapter>(
    body: &VerifyAuthenticationRequest,
    config: &PasskeyConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<DB>,
) -> AuthResult<(SessionUserResponse<DB::User, DB::Session>, String)> {
    ensure_insecure_verification_enabled(config)?;

    let resp = &body.response;

    // Extract credential_id from the response
    let credential_id = resp
        .get("id")
        .or_else(|| resp.get("rawId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::bad_request("Missing credential id in response"))?;

    let client_data = decode_client_data_json(resp)?;
    let challenge = validate_client_data(config, &client_data, "webauthn.get")?;

    // Atomically consume challenge so it cannot be replayed.
    let identifier = format!("passkey_auth:{}", challenge);
    ctx.database
        .consume_verification(&identifier, &challenge)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired authentication challenge"))?;

    // Look up the passkey by credential_id
    let passkey = ctx
        .database
        .get_passkey_by_credential_id(credential_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Passkey not found for credential"))?;

    // Look up the user
    let user = ctx
        .database
        .get_user_by_id(passkey.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;

    // Update the passkey counter
    let new_counter = passkey
        .counter()
        .checked_add(1)
        .ok_or_else(|| AuthError::internal("Passkey counter overflow"))?;
    ctx.database
        .update_passkey_counter(passkey.id(), new_counter)
        .await?;

    // Create a session
    let session_manager =
        better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let session = session_manager
        .create_session(&user, ip_address, user_agent)
        .await?;

    let token = session.token().to_string();
    let response = SessionUserResponse { session, user };
    Ok((response, token))
}

pub(crate) async fn list_user_passkeys_core<DB: DatabaseAdapter>(
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<PasskeyView>> {
    let passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
    Ok(passkeys.iter().map(PasskeyView::from_entity).collect())
}

pub(crate) async fn delete_passkey_core<DB: DatabaseAdapter>(
    body: &DeletePasskeyRequest,
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Verify ownership
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Err(AuthError::not_found("Passkey not found"));
    }

    ctx.database.delete_passkey(&body.id).await?;

    Ok(StatusResponse { status: true })
}

pub(crate) async fn update_passkey_core<DB: DatabaseAdapter>(
    body: &UpdatePasskeyRequest,
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<PasskeyResponse> {
    // Verify ownership
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Err(AuthError::not_found("Passkey not found"));
    }

    let updated = ctx
        .database
        .update_passkey_name(&body.id, &body.name)
        .await?;

    Ok(PasskeyResponse {
        passkey: PasskeyView::from_entity(&updated),
    })
}
