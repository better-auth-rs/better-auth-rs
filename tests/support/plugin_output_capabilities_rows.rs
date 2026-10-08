use better_auth::__private_core::{
    AuthError, AuthResult, AuthSchema, AuthStore, CreateApiKey, CreateDeviceCode, CreateJwk,
    CreatePasskey, CreateTwoFactor, CreateWalletAddress, FieldMap, FieldValue, Jwk, Passkey,
    PasskeyCredentialState, PasskeyStorage, WalletAddress, wire::PasskeyView,
};
use better_auth::seaorm::sea_orm::entity::prelude::DateTimeUtc;
use serde_json::Value;

use super::{ADDRESS, DATE, EXTRA_DATE};

fn input() -> FieldMap {
    FieldMap::from([
        ("enabledFlag".into(), true.into()),
        ("disabledFlag".into(), false.into()),
        (
            "labels".into(),
            vec!["first".into(), "second".into()].into(),
        ),
        ("scores".into(), vec![1.0.into(), 2.5.into()].into()),
        ("shortDate".into(), EXTRA_DATE.into()),
        ("invalidDate".into(), EXTRA_DATE.into()),
    ])
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions verify the complete Passkey record and legacy envelope; Result propagates serialization and typed-value errors."
)]
fn passkey_value(row: &Passkey, storage: PasskeyStorage) -> AuthResult<Value> {
    let value = serde_json::to_value(PasskeyView::from(row))?;
    let mut stored = serde_json::to_value(row)?;
    let stored = stored.as_object_mut().expect("complete Passkey object");
    match storage {
        PasskeyStorage::Native => {
            assert!(row.credential.is_undefined());
            assert!(row.updated_at.is_undefined());
        }
        PasskeyStorage::Legacy => {
            assert_eq!(row.credential.typed()?, "ordinary-private-record");
            let _ = row.updated_at.typed()?;
        }
    }
    // The legacy Rust envelope has an update timestamp that the upstream model does not declare.
    let _ = stored.remove("updatedAt");
    assert_eq!(
        &*stored,
        value.as_object().expect("complete public Passkey object")
    );
    Ok(value)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The observation rejects collisions between plugin columns and additional fields before serializing the complete row."
)]
fn jwk_value(row: &Jwk) -> AuthResult<Value> {
    let mut fields = row.additional_fields.clone();
    for (name, value) in [
        ("id", row.id.field_value()),
        ("publicKey", row.public_key.field_value()),
        ("privateKey", row.private_key.field_value()),
        ("createdAt", row.created_at.field_value()),
        ("expiresAt", row.expires_at.field_value()),
        ("alg", row.alg.field_value()),
        ("crv", row.crv.field_value()),
    ] {
        assert!(fields.insert(name.into(), value).is_none());
    }
    Ok(Value::Object(fields.json()?))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The observation rejects collisions between plugin columns and additional fields before serializing the complete row."
)]
fn wallet_value(row: &WalletAddress) -> AuthResult<Value> {
    let mut fields = row.additional_fields.clone();
    for (name, value) in [
        ("id", row.id.field_value()),
        ("userId", row.user_id.field_value()),
        ("address", row.address.field_value()),
        ("chainId", row.chain_id.field_value()),
        ("isPrimary", row.is_primary.field_value()),
        ("createdAt", row.created_at.field_value()),
    ] {
        assert!(fields.insert(name.into(), value).is_none());
    }
    Ok(Value::Object(fields.json()?))
}

pub(super) async fn create<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: &str,
    owner: &str,
) -> AuthResult<Value> {
    Ok(match model {
        "apikey" => serde_json::to_value(
            store
                .create_api_key(CreateApiKey {
                    reference_id: owner.into(),
                    config_id: "default".into(),
                    name: Some("Desk".into()).into(),
                    prefix: None,
                    key_hash: "ordinary-stored-hash".into(),
                    start: None,
                    expires_at: None,
                    remaining: Some(10.0),
                    rate_limit_enabled: true,
                    rate_limit_time_window: Some(60_000.0),
                    rate_limit_max: Some(3.0),
                    refill_interval: Some(60_000.0),
                    refill_amount: Some(10.0),
                    permissions: None,
                    metadata: None,
                    enabled: true.into(),
                    additional_fields: input(),
                })
                .await?,
        )?,
        "passkey" => passkey_value(
            &store
                .create_passkey(CreatePasskey {
                    user_id: owner.into(),
                    name: Some("Desk".into()).into(),
                    credential_id: "ordinary-credential".into(),
                    public_key: "ordinary-public-key".into(),
                    counter: 0,
                    device_type: "singleDevice".into(),
                    backed_up: false,
                    transports: None,
                    credential: match store.passkey_storage() {
                        PasskeyStorage::Native => PasskeyCredentialState::Native,
                        PasskeyStorage::Legacy => "ordinary-private-record".into(),
                    },
                    aaguid: Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4".into()).into(),
                    additional_fields: input(),
                })
                .await?,
            store.passkey_storage(),
        )?,
        "deviceCode" => serde_json::to_value(
            store
                .create_device_code(CreateDeviceCode {
                    device_code: "ordinary-device".into(),
                    user_code: "ordinary-user".into(),
                    user_id: Some(owner.into()),
                    expires_at: "2032-01-02T03:04:05.000Z"
                        .parse::<DateTimeUtc>()
                        .expect("fixed expiration")
                        .into(),
                    status: "pending".into(),
                    last_polled_at: None,
                    polling_interval: Some(5000.0),
                    client_id: Some("ordinary-client".into()),
                    scope: Some("read".into()).into(),
                    additional_fields: input(),
                })
                .await?,
        )?,
        "twoFactor" => {
            let mut additional_fields = input();
            let _ = additional_fields.insert("failedVerificationCount".into(), 0.into());
            let _ = additional_fields.insert("lockedUntil".into(), FieldValue::Null);
            serde_json::to_value(
                store
                    .create_two_factor(CreateTwoFactor {
                        user_id: owner.into(),
                        secret: "ordinary-encrypted-secret".into(),
                        backup_codes: "ordinary-encrypted-codes".into(),
                        verified: false,
                        additional_fields,
                    })
                    .await?,
            )?
        }
        "jwks" => jwk_value(
            &store
                .create_jwk(CreateJwk {
                    public_key: "public".into(),
                    private_key: "private".into(),
                    created_at: DATE
                        .parse::<DateTimeUtc>()
                        .expect("fixed creation date")
                        .into(),
                    expires_at: None,
                    alg: "EdDSA".into(),
                    crv: None,
                    additional_fields: input(),
                })
                .await?,
        )?,
        "walletAddress" => wallet_value(
            &store
                .create_wallet_address(CreateWalletAddress {
                    user_id: owner.into(),
                    address: ADDRESS.into(),
                    chain_id: 1,
                    is_primary: false,
                    created_at: DATE
                        .parse::<DateTimeUtc>()
                        .expect("fixed creation date")
                        .into(),
                    additional_fields: input(),
                })
                .await?,
        )?,
        _ => return Err(AuthError::internal("Unknown plugin output model")),
    })
}

pub(super) async fn read<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    model: &str,
    owner: &str,
    id: &str,
) -> AuthResult<Value> {
    Ok(match model {
        "apikey" => {
            serde_json::to_value(store.get_api_key_by_id(id).await?.expect("stored API Key"))?
        }
        "passkey" => passkey_value(
            &store.get_passkey_by_id(id).await?.expect("stored Passkey"),
            store.passkey_storage(),
        )?,
        "deviceCode" => serde_json::to_value(
            store
                .get_device_code_by_device_code("ordinary-device")
                .await?
                .expect("stored Device Code"),
        )?,
        "twoFactor" => serde_json::to_value(
            store
                .get_two_factor_by_user_id(owner)
                .await?
                .expect("stored TwoFactor"),
        )?,
        "jwks" => jwk_value(&store.get_jwk(id).await?.expect("stored JWK"))?,
        "walletAddress" => wallet_value(
            &store
                .get_wallet_address(ADDRESS, Some(1))
                .await?
                .expect("stored Wallet Address"),
        )?,
        _ => return Err(AuthError::internal("Unknown plugin output model")),
    })
}
