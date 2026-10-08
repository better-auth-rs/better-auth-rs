use base64::{
    Engine,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use better_auth_core::{
    AuthError, AuthResult, PasskeyCredentialState, PasskeyStorage, SchemaValue,
    UpdatePasskeyAuthentication, Utf16String, entity::AuthPasskey,
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
                let public_key = decode_public_key(passkey.public_key())?;
                let public_key: serde_cbor_2::Value = serde_cbor_2::from_slice(&public_key)
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid passkey public key CBOR: {error}"))
                    })?;
                let key = COSEKey::try_from(&public_key).map_err(|error| {
                    AuthError::internal(format!("Invalid passkey public key: {error}"))
                })?;
                Credential {
                    cred_id: decode_credential_id(passkey.credential_id().typed()?)?,
                    cred: key,
                    // The endpoint applies the upstream relational check to the original runtime value.
                    // The engine receives only counters that its fixed integer representation can retain.
                    counter: match passkey.counter().field_value() {
                        better_auth_core::FieldValue::Number(value)
                            if value >= 0.0
                                && value <= f64::from(u32::MAX)
                                && value.fract() == 0.0 =>
                        {
                            value as u32
                        }
                        _ => 0,
                    },
                    transports: parse_transports_csv(passkey.transports())?
                        .map(|values| values.into_iter().map(|value| {
                            // Transports are hints; unknown UTF-16 values do not affect signature verification.
                            match value.to_utf8() {
                                Ok(value) => serde_json::from_value(serde_json::Value::String(value)),
                                Err(_) => Ok(webauthn_rs_core::proto::AuthenticatorTransport::Unknown),
                            }
                        }).collect::<Result<Vec<_>, serde_json::Error>>())
                        .transpose()?,
                    // Native storage has no historical UV or attestation metadata. Authentication
                    // uses the same explicit policy as Legacy and verifies the current assertion.
                    user_verified: false,
                    backup_eligible: false,
                    backup_state: false,
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

fn decode_public_key(value: &SchemaValue<String>) -> AuthResult<Vec<u8>> {
    let text = value.field_value().decode::<Utf16String>()?;
    let units = text.as_utf16();
    let alphabet = if units.contains(&u16::from(b'-')) || units.contains(&u16::from(b'_')) {
        &base64::alphabet::URL_SAFE
    } else {
        &base64::alphabet::STANDARD
    };
    let decoder = GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    // Better Auth stops at padding, validates an orphan sextet, and discards its bits.
    let bytes = units
        .iter()
        .take_while(|unit| **unit != u16::from(b'='))
        .map(|unit| u8::try_from(*unit))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AuthError::internal(format!("Invalid passkey public key encoding: {error}"))
        })?;
    let invalid =
        |error| AuthError::internal(format!("Invalid passkey public key encoding: {error}"));
    let bytes = match bytes.split_last() {
        Some((last, prefix)) if bytes.len() % 4 == 1 => {
            let _ = decoder.decode([*last, b'A', b'A', b'A']).map_err(invalid)?;
            prefix
        }
        _ => &bytes,
    };
    decoder.decode(bytes).map_err(invalid)
}
