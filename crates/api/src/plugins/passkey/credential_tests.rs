use std::{collections::BTreeMap, error::Error, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use better_auth_core::{
    Passkey, PasskeyCredentialState, PasskeyStorage, SchemaValue, UpdatePasskeyAuthentication,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sha::sha256,
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use serde_json::json;
use webauthn_rs_core::{
    WebauthnCore,
    proto::{
        AuthenticatorTransport, COSEAlgorithm, PublicKeyCredential, RegisterPublicKeyCredential,
    },
};

use super::{
    credential::WebAuthnCredential,
    webauthn::{VERIFICATION_POLICY, extract_registration_metadata},
};

#[path = "credential_reopen_tests.rs"]
mod reopen;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const ORIGIN: &str = "https://passkey.example";
const RP_ID: &str = "passkey.example";
const OWNER: &[u8] = b"passkey-owner-id";
const CREDENTIAL_ID: &[u8] = b"ordinary-native-passkey";
const TRANSPORTS: &[&str] = &["internal", "hybrid"];

struct Authenticator {
    key: PKey<Private>,
    cose: Vec<u8>,
}

impl Authenticator {
    fn new() -> TestResult<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let mut context = BigNumContext::new()?;
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)?;
        let cose = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(x.to_vec_padded(32)?)),
            (Cbor::Integer(-3), Cbor::Bytes(y.to_vec_padded(32)?)),
        ])))?;
        Ok(Self {
            key: PKey::from_ec_key(key)?,
            cose,
        })
    }

    fn register(
        &self,
        challenge: &[u8],
        transports: Option<&[&str]>,
    ) -> TestResult<RegisterPublicKeyCredential> {
        let mut data = authenticator_data(0x45, 0);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&u16::try_from(CREDENTIAL_ID.len())?.to_be_bytes());
        data.extend_from_slice(CREDENTIAL_ID);
        data.extend_from_slice(&self.cose);
        let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
        ])))?;
        let mut response = json!({
            "id": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "rawId": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data("webauthn.create", challenge)?)
            },
            "clientExtensionResults": {}
        });
        if let Some(transports) = transports {
            response["response"]["transports"] = json!(transports);
        }
        Ok(serde_json::from_value(response)?)
    }

    fn authenticate(
        &self,
        challenge: &[u8],
        counter: u32,
        user_handle: &[u8],
    ) -> TestResult<PublicKeyCredential> {
        let data = authenticator_data(0x05, counter);
        let client_data = client_data("webauthn.get", challenge)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        signer.update(&data)?;
        signer.update(&sha256(&client_data))?;
        Ok(serde_json::from_value(json!({
            "id": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "rawId": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "signature": URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?),
                "userHandle": URL_SAFE_NO_PAD.encode(user_handle)
            },
            "clientExtensionResults": {}
        }))?)
    }
}

fn authenticator_data(flags: u8, counter: u32) -> Vec<u8> {
    let mut data = sha256(RP_ID.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

fn client_data(kind: &str, challenge: &[u8]) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "type": kind,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": ORIGIN,
        "crossOrigin": false
    }))?)
}

#[test]
fn standard_columns_and_legacy_envelope_authenticate_registered_key() -> TestResult {
    let authenticator = Authenticator::new()?;
    let webauthn = WebauthnCore::new_unsafe_experts_only(
        "Passkey",
        RP_ID,
        vec![ORIGIN.parse()?],
        Duration::from_secs(60),
        Some(false),
        Some(false),
    );
    for transports in [Some(TRANSPORTS), None] {
        let builder = webauthn
            .new_challenge_register_builder(OWNER, "owner", "Owner")?
            .user_verification_policy(VERIFICATION_POLICY)
            .credential_algorithms(vec![COSEAlgorithm::ES256]);
        let (options, state) = webauthn.generate_challenge_register(builder)?;
        let registration =
            authenticator.register(options.public_key.challenge.as_ref(), transports)?;
        let registered = webauthn.register_credential(&registration, &state, None)?;
        let metadata = extract_registration_metadata(&registration)?;
        assert_eq!(STANDARD.decode(&metadata.public_key)?, authenticator.cose);

        for storage in [PasskeyStorage::Native, PasskeyStorage::Legacy] {
            let registered = WebAuthnCredential::registered(registered.clone(), storage);
            let credential = match registered.create_state()? {
                PasskeyCredentialState::Native => SchemaValue::Undefined,
                PasskeyCredentialState::Legacy(value) => value.into(),
            };
            let mut row = Passkey {
                additional_fields: Default::default(),
                id: "passkey-row".to_owned().into(),
                user_id: String::from_utf8(OWNER.to_vec())?.into(),
                name: Some("Personal key".to_owned()).into(),
                public_key: metadata.public_key.clone().into(),
                credential_id: URL_SAFE_NO_PAD
                    .encode(registered.cred.cred_id.as_ref())
                    .into(),
                counter: u64::from(registered.cred.counter).into(),
                device_type: registered.device_type().to_owned().into(),
                backed_up: registered.cred.backup_state.into(),
                transports: Some(
                    transports
                        .map(|values| values.join(","))
                        .unwrap_or_default(),
                )
                .into(),
                created_at: Some(chrono::Utc::now().into()).into(),
                updated_at: match storage {
                    PasskeyStorage::Native => SchemaValue::Undefined,
                    PasskeyStorage::Legacy => chrono::Utc::now().into(),
                },
                aaguid: metadata.aaguid.clone().into(),
                credential,
            };
            for counter in [1_u32, 2] {
                let stored = WebAuthnCredential::from_record(&row, storage)?;
                assert_eq!(stored.cred.cred_id, registered.cred.cred_id);
                let expected_transports = match (storage, transports) {
                    (PasskeyStorage::Native, Some(_)) => Some(vec![
                        AuthenticatorTransport::Internal,
                        AuthenticatorTransport::Hybrid,
                    ]),
                    (PasskeyStorage::Native, None) => Some(vec![AuthenticatorTransport::Unknown]),
                    (PasskeyStorage::Legacy, _) => registered.cred.transports.clone(),
                };
                assert_eq!(stored.cred.transports, expected_transports);
                let builder = webauthn
                    .new_challenge_authenticate_builder(Vec::new(), Some(VERIFICATION_POLICY))?
                    .allow_backup_eligible_upgrade(true);
                let (options, mut state) = webauthn.generate_challenge_authenticate(builder)?;
                let authentication = authenticator.authenticate(
                    options.public_key.challenge.as_ref(),
                    counter,
                    OWNER,
                )?;
                state.set_allowed_credentials(vec![stored.cred.clone()]);
                let result = webauthn.authenticate_credential(&authentication, &state)?;
                assert_eq!(result.cred_id(), &stored.cred.cred_id);
                assert_eq!(result.counter(), counter);
                assert!(u64::from(result.counter()) > *row.counter.typed()?);
                assert!(result.user_verified());
                assert_eq!(row.user_id.typed()?.as_bytes(), OWNER);
                match stored.authentication_update(result.counter())? {
                    UpdatePasskeyAuthentication::Native { counter } => {
                        assert_eq!(storage, PasskeyStorage::Native);
                        assert!(row.credential.is_undefined());
                        assert!(row.updated_at.is_undefined());
                        row.counter = counter.into();
                    }
                    UpdatePasskeyAuthentication::Legacy {
                        credential,
                        counter,
                        backed_up,
                        device_type,
                    } => {
                        assert_eq!(storage, PasskeyStorage::Legacy);
                        let mut expected = serde_json::to_value(&registered)?;
                        expected["cred"]["counter"] = counter.into();
                        assert_eq!(
                            serde_json::from_str::<serde_json::Value>(&credential)?,
                            expected
                        );
                        assert_eq!(row.backed_up, backed_up);
                        assert_eq!(row.device_type, device_type);
                        row.credential = credential.into();
                        row.counter = counter.into();
                    }
                }
            }
            assert_eq!(row.counter, 2);
        }
    }
    Ok(())
}
