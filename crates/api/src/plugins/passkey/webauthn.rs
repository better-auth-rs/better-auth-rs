use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use better_auth_core::{AuthConfig, AuthError, AuthRequest, AuthResult};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    AuthenticationState, Base64UrlSafeData, CreationChallengeResponse, Credential, CredentialID,
    PublicKeyCredential, RegisterPublicKeyCredential, RegistrationState, RequestChallengeResponse,
    UserVerificationPolicy,
};

use super::PasskeyConfig;

const OPTIONS_TIMEOUT_MS: u64 = 60_000;
const GENERATED_USER_ID_LENGTH: usize = 32;
const GENERATED_USER_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug)]
pub(super) struct RegisteredPasskeyMetadata {
    pub public_key: String,
    pub aaguid: Option<String>,
    pub fmt: String,
    pub extensions: Option<Value>,
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
    pub user: super::PasskeyRegistrationUser,
    pub context: Option<String>,
    pub state: RegistrationChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RegistrationChallenge {
    pub rs: RegistrationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthenticationChallenge {
    pub ast: AuthenticationState,
}

// Preserve the existing persisted credential envelope when using the core API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredPasskey {
    pub cred: Credential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum StoredAuthenticationState {
    Passkey { state: AuthenticationChallenge },
    Discoverable { state: AuthenticationChallenge },
}

pub(super) fn resolve_origins(config: &PasskeyConfig, req: &AuthRequest) -> Option<Vec<String>> {
    match &config.origin {
        super::PasskeyOrigins::Request => req
            .headers
            .get("origin")
            .filter(|value| !value.is_empty())
            .map(|value| vec![value.clone()]),
        super::PasskeyOrigins::Explicit(origins) => Some(origins.clone()),
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

pub(super) fn challenge_cookie_name(auth_config: &AuthConfig, config: &PasskeyConfig) -> String {
    better_auth_core::utils::cookie_utils::related_cookie_name(
        auth_config,
        &config.web_authn_challenge_cookie,
    )
}

pub(super) fn build_webauthn(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
    origins: &[String],
) -> AuthResult<WebauthnCore> {
    let rp_id = rp_id(config, auth_config)?;
    let origins = origins
        .iter()
        .map(|origin| {
            Url::parse(origin)
                .map_err(|error| AuthError::bad_request(format!("Invalid passkey origin: {error}")))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let rp_name = if config.rp_name.is_empty() {
        &auth_config.app_name
    } else {
        &config.rp_name
    };
    Ok(WebauthnCore::new_unsafe_experts_only(
        rp_name,
        &rp_id,
        origins,
        Duration::from_millis(OPTIONS_TIMEOUT_MS),
        Some(false),
        Some(false),
    ))
}

pub(super) fn rp_id(config: &PasskeyConfig, auth_config: &AuthConfig) -> AuthResult<String> {
    if config.rp_id.is_empty() {
        Url::parse(&auth_config.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| AuthError::config("Missing passkey RP ID"))
    } else {
        Ok(config.rp_id.clone())
    }
}

// Better Auth treats UV as a UI preference and permits absent UV after verified registration.
pub(super) const VERIFICATION_POLICY: UserVerificationPolicy =
    UserVerificationPolicy::Discouraged_DO_NOT_USE;

pub(super) fn create_challenge_cookie(
    auth_config: &AuthConfig,
    config: &PasskeyConfig,
    token: &str,
) -> AuthResult<String> {
    let signed = better_auth_core::utils::cookie_utils::sign_cookie_value(
        token,
        auth_config.signing_secret(),
    );
    Ok(better_auth_core::utils::cookie_utils::create_cookie(
        &challenge_cookie_name(auth_config, config),
        &signed,
        config.challenge_ttl_secs,
        auth_config,
    ))
}

pub(super) fn decode_challenge_cookie(
    auth_config: &AuthConfig,
    raw_cookie: &str,
) -> AuthResult<String> {
    better_auth_core::utils::cookie_utils::verify_cookie_value(
        raw_cookie,
        auth_config.signing_secret(),
    )
    .ok_or(AuthError::Unauthenticated)
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
    config: &super::AuthenticatorSelection,
    extensions: Option<serde_json::Map<String, Value>>,
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

    let mut selection = serde_json::Map::from_iter([
        ("residentKey".into(), json!("preferred")),
        ("userVerification".into(), json!("preferred")),
    ]);
    if let Value::Object(config) = serde_json::to_value(config)? {
        selection.extend(config);
    }
    let require_resident_key =
        selection.get("residentKey").and_then(Value::as_str) == Some("required");
    let _ = selection.insert("requireResidentKey".into(), require_resident_key.into());
    if let Some(attachment) = authenticator_attachment {
        let _ = selection.insert("authenticatorAttachment".into(), attachment.into());
    }
    let _ = root.insert("authenticatorSelection".into(), selection.into());

    let _ = root.insert("hints".to_string(), Value::Array(Vec::new()));
    let mut extensions = extensions.unwrap_or_default();
    let _ = extensions.insert("credProps".into(), true.into());
    let _ = root.insert("extensions".into(), extensions.into());
    let _ = root.insert(
        "timeout".to_string(),
        Value::Number(OPTIONS_TIMEOUT_MS.into()),
    );
    Ok(value)
}

pub(super) fn authentication_options_json(
    options: RequestChallengeResponse,
    extensions: Option<serde_json::Map<String, Value>>,
) -> AuthResult<Value> {
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
    if let Some(extensions) = extensions {
        let _ = root.insert("extensions".into(), extensions.into());
    }
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

pub(super) fn parse_stored_passkey(serialized: &str) -> AuthResult<StoredPasskey> {
    let mut passkey: StoredPasskey = serde_json::from_str(serialized).map_err(|error| {
        AuthError::internal(format!("Failed to decode stored passkey: {error}"))
    })?;
    passkey.cred.registration_policy = VERIFICATION_POLICY;
    Ok(passkey)
}

pub(super) fn snapshot_passkey(passkey: &StoredPasskey) -> AuthResult<PasskeySnapshot> {
    Ok(PasskeySnapshot {
        serialized: serde_json::to_string(passkey)?,
        counter: u64::from(passkey.cred.counter),
        backed_up: passkey.cred.backup_state,
        backup_eligible: passkey.cred.backup_eligible,
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

    let extensions = if auth_data.get(32).is_some_and(|flags| flags & 0x80 != 0) {
        Some(
            serde_cbor_2::from_slice(
                credential_public_key
                    .get(public_key_length..)
                    .ok_or_else(|| AuthError::internal("Invalid authenticator extension offset"))?,
            )
            .map_err(|error| {
                AuthError::internal(format!("Invalid authenticator extensions: {error}"))
            })?,
        )
    } else {
        None
    };
    let fmt = attestation_map
        .get(&serde_cbor_2::Value::Text("fmt".into()))
        .and_then(|value| match value {
            serde_cbor_2::Value::Text(value) => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| AuthError::internal("Attestation object missing format"))?;
    Ok(RegisteredPasskeyMetadata {
        fmt,
        extensions,
        public_key: STANDARD.encode(public_key),
        aaguid: Uuid::from_slice(aaguid_bytes)
            .ok()
            .map(|uuid| uuid.to_string()),
    })
}

pub(super) fn parse_transports_csv(transports: Option<&str>) -> Option<Vec<String>> {
    transports.map(|transports| transports.split(',').map(str::to_string).collect())
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

pub(super) fn client_origin(client_data: &[u8]) -> AuthResult<String> {
    #[derive(Deserialize)]
    struct ClientData {
        origin: String,
    }
    Ok(serde_json::from_slice::<ClientData>(client_data)?.origin)
}

pub(super) fn authentication_extensions(auth_data: &[u8]) -> AuthResult<Option<Value>> {
    if auth_data.get(32).is_some_and(|flags| flags & 0x80 != 0) {
        Ok(Some(
            serde_cbor_2::from_slice(
                auth_data
                    .get(37..)
                    .ok_or_else(|| AuthError::internal("Missing authenticator extensions"))?,
            )
            .map_err(|error| {
                AuthError::internal(format!("Invalid authenticator extensions: {error}"))
            })?,
        ))
    } else {
        Ok(None)
    }
}
