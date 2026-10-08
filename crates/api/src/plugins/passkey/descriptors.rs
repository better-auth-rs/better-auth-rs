use base64::{
    Engine,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use better_auth_core::{
    AuthError, AuthPasskey, AuthResult, FieldMap, FieldValue, SchemaValue, Utf16String,
};
use webauthn_rs_core::proto::CredentialID;

use super::webauthn::parse_transports_csv;

pub(super) struct CredentialDescriptor {
    id: String,
    transports: Option<Vec<Utf16String>>,
}

impl CredentialDescriptor {
    pub(super) fn registration_id(&self) -> AuthResult<CredentialID> {
        // Upstream options accept incomplete sextets. The decoder keeps only complete bytes.
        let bytes = self.id.as_bytes();
        let bytes = match bytes.split_last() {
            Some((_, prefix)) if bytes.len() % 4 == 1 => prefix,
            _ => bytes,
        };
        let decoder = GeneralPurpose::new(
            &base64::alphabet::URL_SAFE,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        decoder
            .decode(bytes)
            .map(Into::into)
            .map_err(|error| AuthError::internal(format!("Invalid descriptor ID: {error}")))
    }

    pub(super) fn into_value(self) -> FieldValue {
        FieldMap::from([
            ("id".into(), self.id.into()),
            (
                "transports".into(),
                self.transports.map_or(FieldValue::Undefined, |values| {
                    values
                        .into_iter()
                        .map(FieldValue::from)
                        .collect::<Vec<_>>()
                        .into()
                }),
            ),
            ("type".into(), "public-key".into()),
        ])
        .into()
    }
}

pub(super) fn credential_descriptors(
    passkeys: &[impl AuthPasskey],
    label: &str,
) -> AuthResult<Vec<CredentialDescriptor>> {
    // Better Auth maps transports before SimpleWebAuthn validates descriptor IDs.
    let candidates = passkeys
        .iter()
        .map(|passkey| {
            Ok((
                passkey.credential_id().field_value(),
                parse_transports_csv(passkey.transports())?,
            ))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    candidates
        .into_iter()
        .map(|(id, transports)| {
            if !id.is_string() {
                return Err(AuthError::internal("input.replace is not a function"));
            }
            let text = SchemaValue::<String>::from_field(id).display_string()?;
            let normalized = text.replace('=', "");
            if !normalized
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(AuthError::internal(format!(
                    "{label} id \"{text}\" is not a valid base64url string",
                )));
            }
            Ok(CredentialDescriptor {
                id: normalized,
                transports,
            })
        })
        .collect()
}
