use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use better_auth_core::{AuthConfig, AuthError, AuthRequest, AuthResult};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use super::PasskeyConfig;

pub(super) const PASSKEY_CHALLENGE_COOKIE_NAME: &str = "better-auth-passkey";
const OPTIONS_TIMEOUT_MS: u64 = 60_000;
const GENERATED_USER_ID_LENGTH: usize = 32;
const GENERATED_USER_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug)]
pub(super) struct RegisteredPasskeyMetadata {
    pub public_key: String,
    pub aaguid: Option<String>,
}

#[derive(Debug)]
pub(super) struct PasskeySnapshot {
    pub serialized: String,
    pub counter: u64,
    pub backed_up: bool,
    pub backup_eligible: bool,
}

impl PasskeySnapshot {
    pub(super) fn device_type(&self) -> &'static str {
        if self.backup_eligible {
            "multiDevice"
        } else {
            "singleDevice"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredRegistrationState {
    pub user_id: String,
    pub state: webauthn_rs::prelude::PasskeyRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum StoredAuthenticationState {
    Passkey {
        state: webauthn_rs::prelude::PasskeyAuthentication,
    },
    Discoverable {
        state: DiscoverableAuthentication,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeCookieClaims {
    token: String,
    exp: usize,
    iat: usize,
}

pub(super) fn resolve_origin(config: &PasskeyConfig, req: &AuthRequest) -> Option<String> {
    if config.origin.is_empty() {
        req.headers.get("origin").cloned()
    } else {
        Some(config.origin.clone())
    }
}

pub(super) fn get_cookie_value(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            let (cookie_name, cookie_value) = trimmed.split_once('=')?;
            (cookie_name == name).then_some(cookie_value.to_string())
        })
        .next()
}

pub(super) fn challenge_cookie_name(auth_config: &AuthConfig) -> String {
    auth_config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{prefix}{PASSKEY_CHALLENGE_COOKIE_NAME}"))
        .unwrap_or_else(|| PASSKEY_CHALLENGE_COOKIE_NAME.to_string())
}

pub(super) fn build_webauthn(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
    origin: &str,
) -> AuthResult<Webauthn> {
    let rp_id = if config.rp_id.is_empty() {
        Url::parse(&auth_config.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| AuthError::config("Missing passkey RP ID".to_string()))?
    } else {
        config.rp_id.clone()
    };
    let parsed_origin = Url::parse(origin)
        .map_err(|error| AuthError::bad_request(format!("Invalid passkey origin: {error}")))?;

    WebauthnBuilder::new(&rp_id, &parsed_origin)
        .map_err(|error| AuthError::config(format!("Invalid passkey config: {error}")))?
        .rp_name(&config.rp_name)
        .timeout(Duration::from_millis(OPTIONS_TIMEOUT_MS))
        .allow_any_port(true)
        .build()
        .map_err(|error| AuthError::config(format!("Invalid passkey config: {error}")))
}

pub(super) fn create_challenge_cookie(
    auth_config: &AuthConfig,
    ttl_secs: i64,
    token: &str,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = ChallengeCookieClaims {
        token: token.to_string(),
        exp: (now + chrono::Duration::seconds(ttl_secs)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    let signed = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(auth_config.secret.as_bytes()),
    )?;
    Ok(better_auth_core::utils::cookie_utils::create_cookie(
        &challenge_cookie_name(auth_config),
        &signed,
        ttl_secs,
        auth_config,
    ))
}

pub(super) fn decode_challenge_cookie(
    auth_config: &AuthConfig,
    raw_cookie: &str,
) -> AuthResult<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<ChallengeCookieClaims>(
        raw_cookie,
        &DecodingKey::from_secret(auth_config.secret.as_bytes()),
        &validation,
    )?
    .claims
    .token)
}

pub(super) fn generate_ts_user_handle() -> String {
    let mut rng = rand::thread_rng();
    let handle: String = (0..GENERATED_USER_ID_LENGTH)
        .map(|_| {
            GENERATED_USER_ID_ALPHABET
                .choose(&mut rng)
                .copied()
                .unwrap_or(b'a') as char
        })
        .collect();
    URL_SAFE_NO_PAD.encode(handle.as_bytes())
}

pub(super) fn registration_options_json(
    options: CreationChallengeResponse,
    generated_user_handle: &str,
    authenticator_attachment: Option<&str>,
) -> AuthResult<Value> {
    let mut value = serde_json::to_value(options.public_key)?;
    let Some(root) = value.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey registration options must serialize as an object",
        ));
    };

    let Some(user) = root.get_mut("user").and_then(Value::as_object_mut) else {
        return Err(AuthError::internal(
            "Passkey registration options missing user object",
        ));
    };
    let _ = user.insert(
        "id".to_string(),
        Value::String(generated_user_handle.to_string()),
    );

    if !root.contains_key("excludeCredentials") {
        let _ = root.insert("excludeCredentials".to_string(), Value::Array(Vec::new()));
    }

    let _ = root.insert(
        "pubKeyCredParams".to_string(),
        json!([
            { "alg": -8, "type": "public-key" },
            { "alg": -7, "type": "public-key" },
            { "alg": -257, "type": "public-key" }
        ]),
    );

    let selection = root
        .entry("authenticatorSelection".to_string())
        .or_insert_with(|| json!({}));
    let Some(selection) = selection.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey registration options missing authenticatorSelection object",
        ));
    };
    let _ = selection.insert(
        "userVerification".to_string(),
        Value::String("preferred".to_string()),
    );
    let _ = selection.insert(
        "residentKey".to_string(),
        Value::String("preferred".to_string()),
    );
    let _ = selection.insert("requireResidentKey".to_string(), Value::Bool(false));
    if let Some(authenticator_attachment) = authenticator_attachment {
        let _ = selection.insert(
            "authenticatorAttachment".to_string(),
            Value::String(authenticator_attachment.to_string()),
        );
    }

    let _ = root.insert("hints".to_string(), Value::Array(Vec::new()));
    let _ = root.insert("extensions".to_string(), json!({ "credProps": true }));
    let _ = root.insert(
        "timeout".to_string(),
        Value::Number(OPTIONS_TIMEOUT_MS.into()),
    );
    Ok(value)
}

pub(super) fn authentication_options_json(options: RequestChallengeResponse) -> AuthResult<Value> {
    let mut value = serde_json::to_value(options.public_key)?;
    let Some(root) = value.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey authentication options must serialize as an object",
        ));
    };

    if root
        .get("allowCredentials")
        .and_then(Value::as_array)
        .is_some_and(|credentials| credentials.is_empty())
    {
        let _ = root.remove("allowCredentials");
    }

    let _ = root.remove("extensions");
    let _ = root.insert(
        "timeout".to_string(),
        Value::Number(OPTIONS_TIMEOUT_MS.into()),
    );
    let _ = root.insert(
        "userVerification".to_string(),
        Value::String("preferred".to_string()),
    );
    let _ = root.remove("hints");
    Ok(value)
}

pub(super) fn decode_credential_id(credential_id: &str) -> AuthResult<CredentialID> {
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id)
        .or_else(|_| URL_SAFE.decode(credential_id))
        .or_else(|_| STANDARD.decode(credential_id))
        .map_err(|_| AuthError::bad_request("Invalid passkey credential id"))?;
    Ok(bytes.into())
}

pub(super) fn parse_stored_passkey(serialized: &str) -> AuthResult<WebauthnPasskey> {
    serde_json::from_str(serialized)
        .map_err(|error| AuthError::internal(format!("Failed to decode stored passkey: {error}")))
}

pub(super) fn extract_passkey_snapshot_fields(value: &Value) -> AuthResult<(u64, bool, bool)> {
    // webauthn-rs does not expose stable accessors for all persisted passkey
    // attributes we need at registration time. We intentionally depend on the
    // current 0.5.x serialized shape here and fail closed if it drifts.
    let Some(cred) = value.get("cred").and_then(Value::as_object) else {
        return Err(AuthError::internal(
            "Stored passkey JSON missing credential payload",
        ));
    };
    let counter = cred
        .get("counter")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing counter"))?;
    let backed_up = cred
        .get("backup_state")
        .and_then(Value::as_bool)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing backup_state"))?;
    let backup_eligible = cred
        .get("backup_eligible")
        .and_then(Value::as_bool)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing backup_eligible"))?;

    Ok((counter, backed_up, backup_eligible))
}

pub(super) fn snapshot_passkey(passkey: &WebauthnPasskey) -> AuthResult<PasskeySnapshot> {
    let serialized = serde_json::to_string(passkey)?;
    let value: Value = serde_json::from_str(&serialized)?;
    let (counter, backed_up, backup_eligible) = extract_passkey_snapshot_fields(&value)?;

    Ok(PasskeySnapshot {
        serialized,
        counter,
        backed_up,
        backup_eligible,
    })
}

pub(super) fn extract_registration_metadata(
    registration: &RegisterPublicKeyCredential,
) -> AuthResult<RegisteredPasskeyMetadata> {
    let attestation_bytes = registration.response.attestation_object.as_ref();
    let attestation: serde_cbor_2::Value = serde_cbor_2::from_slice(attestation_bytes)
        .map_err(|error| AuthError::internal(format!("Invalid attestation CBOR: {error}")))?;
    let serde_cbor_2::Value::Map(attestation_map) = attestation else {
        return Err(AuthError::internal("Attestation object must be a CBOR map"));
    };
    let auth_data = attestation_map
        .get(&serde_cbor_2::Value::Text("authData".to_string()))
        .and_then(|value| match value {
            serde_cbor_2::Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| AuthError::internal("Attestation object missing authData"))?;

    if auth_data.len() < 55 {
        return Err(AuthError::internal("Attestation authData is too short"));
    }

    let mut offset = 37;
    let aaguid_bytes = auth_data
        .get(offset..offset + 16)
        .ok_or_else(|| AuthError::internal("Attestation authData missing AAGUID"))?;
    offset += 16;

    let credential_id_length = auth_data
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| AuthError::internal("Attestation authData missing credential length"))?;
    offset += 2;
    offset += credential_id_length;

    let credential_public_key = auth_data
        .get(offset..)
        .ok_or_else(|| AuthError::internal("Attestation authData missing credential public key"))?;
    let mut deserializer = serde_cbor_2::de::Deserializer::from_slice(credential_public_key);
    let _: serde_cbor_2::Value = Deserialize::deserialize(&mut deserializer).map_err(|error| {
        AuthError::internal(format!("Invalid credential public key CBOR: {error}"))
    })?;
    let public_key_length = deserializer.byte_offset();
    let public_key = credential_public_key
        .get(..public_key_length)
        .ok_or_else(|| AuthError::internal("Credential public key length is invalid"))?;

    Ok(RegisteredPasskeyMetadata {
        public_key: STANDARD.encode(public_key),
        aaguid: Uuid::from_slice(aaguid_bytes)
            .ok()
            .map(|uuid| uuid.to_string()),
    })
}

pub(super) fn transports_to_csv(transports: &Option<Vec<String>>) -> Option<String> {
    transports
        .as_ref()
        .filter(|transports| !transports.is_empty())
        .map(|transports| transports.join(","))
}

pub(super) fn parse_transports_csv(transports: Option<&str>) -> Option<Vec<String>> {
    transports.map(|transports| {
        transports
            .split(',')
            .filter(|transport| !transport.is_empty())
            .map(str::to_string)
            .collect()
    })
}

pub(super) fn credential_id_from_authentication(
    authentication: &PublicKeyCredential,
) -> AuthResult<String> {
    if !authentication.id.is_empty() {
        return Ok(authentication.id.clone());
    }

    let raw_id: &Base64UrlSafeData = &authentication.raw_id;
    Ok(URL_SAFE_NO_PAD.encode(raw_id.as_ref()))
}
