use base64::{Engine, engine::general_purpose::STANDARD};
use better_auth_core::{
    AuthError, AuthResult, PasskeyCredentialState, PasskeyStorage, UpdatePasskeyAuthentication,
    entity::AuthPasskey,
};
use serde::{Deserialize, Serialize};
use webauthn_rs_core::proto::{
    AttestationFormat, COSEKey, Credential, ParsedAttestation, RegisteredExtensions,
};

use super::webauthn::{VERIFICATION_POLICY, decode_credential_id, parse_transports_csv};

// The serialized form remains the Legacy credential envelope.
#[derive(Serialize)]
pub(super) struct WebAuthnCredential {
    pub cred: Credential,
    #[serde(skip)]
    storage: PasskeyStorage,
}

#[derive(Deserialize)]
struct StoredPasskey {
    cred: Credential,
}

impl WebAuthnCredential {
    pub(super) fn registered(cred: Credential, storage: PasskeyStorage) -> Self {
        Self { cred, storage }
    }

    pub(super) fn from_record(
        passkey: &impl AuthPasskey,
        storage: PasskeyStorage,
    ) -> AuthResult<Self> {
        let cred = match storage {
            PasskeyStorage::Legacy => {
                let mut stored: StoredPasskey = serde_json::from_str(passkey.credential().typed()?)
                    .map_err(|error| {
                        AuthError::internal(format!("Failed to decode stored passkey: {error}"))
                    })?;
                stored.cred.registration_policy = VERIFICATION_POLICY;
                stored.cred
            }
            PasskeyStorage::Native => {
                let public_key = STANDARD.decode(passkey.public_key()).map_err(|error| {
                    AuthError::internal(format!("Invalid passkey public key encoding: {error}"))
                })?;
                let public_key: serde_cbor_2::Value = serde_cbor_2::from_slice(&public_key)
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid passkey public key CBOR: {error}"))
                    })?;
                let key = COSEKey::try_from(&public_key).map_err(|error| {
                    AuthError::internal(format!("Invalid passkey public key: {error}"))
                })?;
                Credential {
                    cred_id: decode_credential_id(passkey.credential_id())?,
                    cred: key,
                    counter: u32::try_from(passkey.counter()).map_err(|error| {
                        AuthError::internal(format!("Invalid passkey counter: {error}"))
                    })?,
                    transports: parse_transports_csv(passkey.transports())
                        .map(|values| serde_json::from_value(serde_json::to_value(values)?))
                        .transpose()?,
                    // Native storage has no historical UV or attestation metadata. Authentication
                    // uses the same explicit policy as Legacy and verifies the current assertion.
                    user_verified: false,
                    backup_eligible: passkey.device_type() == "multiDevice",
                    backup_state: passkey.backed_up(),
                    registration_policy: VERIFICATION_POLICY,
                    extensions: RegisteredExtensions::none(),
                    attestation: ParsedAttestation::default(),
                    attestation_format: AttestationFormat::None,
                }
            }
        };
        Ok(Self { cred, storage })
    }

    pub(super) fn device_type(&self) -> &'static str {
        if self.cred.backup_eligible {
            "multiDevice"
        } else {
            "singleDevice"
        }
    }

    pub(super) fn create_state(&self) -> AuthResult<PasskeyCredentialState> {
        match self.storage {
            PasskeyStorage::Native => Ok(PasskeyCredentialState::Native),
            PasskeyStorage::Legacy => {
                Ok(PasskeyCredentialState::Legacy(serde_json::to_string(self)?))
            }
        }
    }

    pub(super) fn authentication_update(
        mut self,
        counter: u32,
    ) -> AuthResult<UpdatePasskeyAuthentication> {
        self.cred.counter = counter;
        match self.storage {
            PasskeyStorage::Native => Ok(UpdatePasskeyAuthentication::Native {
                counter: u64::from(counter),
            }),
            PasskeyStorage::Legacy => Ok(UpdatePasskeyAuthentication::Legacy {
                credential: serde_json::to_string(&self)?,
                counter: u64::from(counter),
                backed_up: self.cred.backup_state,
                device_type: self.device_type().to_owned(),
            }),
        }
    }
}
