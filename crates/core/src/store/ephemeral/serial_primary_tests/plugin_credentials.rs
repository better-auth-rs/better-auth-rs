use super::*;
use crate::store::{ApiKeyStore, ApiKeyUsageWrite, ConsumeApiKeyResult};
use crate::{CreateApiKey, UpdateApiKey, UpdatePasskeyAuthentication, UpdateTwoFactor};

fn api_key(label: &str) -> CreateApiKey {
    CreateApiKey {
        additional_fields: FieldMap::new(),
        reference_id: "owner".into(),
        config_id: "default".into(),
        name: Some(label.into()),
        prefix: None,
        key_hash: label.into(),
        start: None,
        expires_at: None,
        remaining: Some(1.0),
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
        refill_interval: None,
        refill_amount: None,
        permissions: None,
        metadata: None,
        enabled: true,
    }
}

fn passkey(label: &str) -> CreatePasskey {
    CreatePasskey {
        additional_fields: FieldMap::new(),
        user_id: "owner".into(),
        name: Some(label.into()).into(),
        credential_id: label.into(),
        public_key: "public-key".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        credential: "private-credential".into(),
        aaguid: None.into(),
    }
}

fn two_factor(owner: &str) -> CreateTwoFactor {
    CreateTwoFactor {
        additional_fields: FieldMap::new(),
        user_id: owner.into(),
        secret: "encrypted-secret".into(),
        backup_codes: "encrypted-codes".into(),
        verified: true,
    }
}

#[tokio::test]
async fn serial_api_key_ids_bind_queries_sort_numerically_and_reuse_row_count() -> AuthResult<()> {
    let store = serial_store();
    for index in 1..=12 {
        let created = store.create_api_key(api_key(&index.to_string())).await?;
        assert_eq!(created.id.field_value(), Value::String(index.to_string()));
    }
    assert_eq!(
        store
            .lock()?
            .api_keys
            .snapshot()?
            .iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        (1..=12)
            .map(|id| Value::Number(f64::from(id)))
            .collect::<Vec<_>>()
    );
    for (direction, expected) in [
        ("asc", (1..=12).map(|id| id.to_string()).collect::<Vec<_>>()),
        (
            "desc",
            (1..=12).rev().map(|id| id.to_string()).collect::<Vec<_>>(),
        ),
    ] {
        let rows = store
            .find_api_keys_by_reference("owner", Some(("id", direction)))
            .await?;
        assert_eq!(
            rows.iter()
                .map(|row| row.id.typed().cloned())
                .collect::<AuthResult<Vec<_>>>()?,
            expected
        );
    }
    assert_eq!(required(store.get_api_key_by_id("001").await?)?.id, "1");
    let padded = "001".to_owned().into();
    assert_eq!(
        required(store.get_api_key_by_id_value(&padded).await?)?.key_hash,
        "1"
    );
    let updated = store
        .update_api_key(
            &padded,
            UpdateApiKey {
                name: Some(Some("renamed".into()).into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id, "1");
    assert_eq!(updated.name.typed()?.as_deref(), Some("renamed"));
    assert_eq!(
        required(store.get_api_key_by_id("002").await?)?
            .name
            .typed()?
            .as_deref(),
        Some("2")
    );
    store.delete_api_key(&"002".to_owned().into()).await?;
    assert!(store.get_api_key_by_hash("2").await?.is_none());
    assert_eq!(store.create_api_key(api_key("reused")).await?.id, "12");
    store.delete_api_key(&"0012".to_owned().into()).await?;
    assert!(store.get_api_key_by_hash("12").await?.is_none());
    assert_eq!(
        required(store.get_api_key_by_hash("reused").await?)?.id,
        "12"
    );
    Ok(())
}

#[tokio::test]
async fn serial_api_key_quota_is_atomic_and_expiration_uses_raw_ids() -> AuthResult<()> {
    let store = serial_store();
    let snapshot = store.create_api_key(api_key("quota")).await?;
    let padded = "001".to_owned().into();
    let (first, second) = tokio::join!(
        store.write_api_key_usage(&padded, ApiKeyUsageWrite::Decrement),
        store.write_api_key_usage(&padded, ApiKeyUsageWrite::Decrement),
    );
    let consumed = [first?, second?].into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(consumed.len(), 1);
    assert_eq!(required(consumed.first())?.id, snapshot.id);
    assert_eq!(required(consumed.first())?.remaining, Some(0.0));
    assert!(matches!(
        store
            .consume_api_key_usage(required(consumed.first())?, false)
            .await?,
        ConsumeApiKeyResult::UsageExhausted
    ));
    assert!(store.get_api_key_by_hash("quota").await?.is_none());

    let _ = store.create_api_key(api_key("live")).await?;
    let mut expired = api_key("expired-number");
    let past = crate::FieldDate::from(Utc::now() - chrono::Duration::hours(1));
    expired.expires_at = Some(past.clone());
    let _ = store.create_api_key(expired).await?;
    {
        let mut state = store.lock()?;
        let mut shadow = required(state.api_keys.snapshot()?.first()).cloned()?;
        shadow.id = "001".to_owned().into();
        shadow.key_hash = "expired-string".into();
        shadow.expires_at = Some(past);
        state.api_keys.push(shadow);
    }
    assert_eq!(store.delete_expired_api_keys().await?, 2);
    assert_eq!(required(store.get_api_key_by_hash("live").await?)?.id, "1");
    assert!(store.get_api_key_by_hash("expired-number").await?.is_none());
    assert!(store.get_api_key_by_hash("expired-string").await?.is_none());
    assert_eq!(store.lock()?.api_keys.len(), 1);
    Ok(())
}

#[tokio::test]
async fn api_key_numeric_id_sort_keeps_unordered_subtractions_equal() -> AuthResult<()> {
    for (left, right) in [
        (f64::NAN, 1.0),
        (1.0, f64::NAN),
        (f64::INFINITY, f64::INFINITY),
    ] {
        let store = serial_store();
        let _ = store.create_api_key(api_key("first")).await?;
        let _ = store.create_api_key(api_key("second")).await?;
        store.lock()?.api_keys.update_each(|row| {
            row.id = crate::SchemaValue::from_field(Value::Number(if row.key_hash == "first" {
                left
            } else {
                right
            }));
            Ok(())
        })?;
        for direction in ["asc", "desc"] {
            let rows = store
                .find_api_keys_by_reference("owner", Some(("id", direction)))
                .await?;
            assert_eq!(
                rows.iter()
                    .map(|row| row.key_hash.as_str())
                    .collect::<Vec<_>>(),
                ["first", "second"]
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn serial_passkey_ids_bind_updates_and_delete_only_the_first_reused_id() -> AuthResult<()> {
    let store = serial_store();
    for label in ["first", "second", "third"] {
        let created = store.create_passkey(passkey(label)).await?;
        assert!(matches!(created.id.field_value(), Value::String(_)));
    }
    assert_eq!(
        store
            .lock()?
            .passkeys
            .snapshot()?
            .iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]
    );
    let renamed = store.update_passkey_name("001", "renamed").await?;
    assert_eq!(renamed.id, "1");
    assert_eq!(renamed.name.typed()?.as_deref(), Some("renamed"));
    let updated = store
        .update_passkey_authentication(
            &"001".to_owned().into(),
            UpdatePasskeyAuthentication::Legacy {
                credential: "updated-private-credential".into(),
                counter: 7,
                backed_up: true,
                device_type: "multiDevice".into(),
            },
        )
        .await?;
    assert_eq!(updated.id, "1");
    assert_eq!(updated.user_id, "owner");
    assert_eq!(updated.credential.typed()?, "updated-private-credential");
    assert_eq!(updated.counter, 7);
    assert_eq!(required(store.get_passkey_by_id("001").await?)?, updated);
    assert_eq!(
        required(store.get_passkey_by_credential_id("second").await?)?.counter,
        0
    );
    store.delete_passkey("002").await?;
    assert_eq!(store.create_passkey(passkey("reused")).await?.id, "3");
    store.delete_passkey("003").await?;
    assert!(store.get_passkey_by_credential_id("third").await?.is_none());
    assert_eq!(
        required(store.get_passkey_by_credential_id("reused").await?)?.id,
        "3"
    );
    assert_eq!(store.list_passkeys_by_user("owner").await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn serial_two_factor_ids_keep_backup_code_and_lockout_guards() -> AuthResult<()> {
    let store = serial_store();
    let created = store.create_two_factor(two_factor("first")).await?;
    assert_eq!(created.id, "1");
    let second = store.create_two_factor(two_factor("second")).await?;
    assert_eq!(second.id, "2");
    assert_eq!(
        store
            .lock()?
            .two_factors
            .snapshot()?
            .iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), Value::Number(2.0)]
    );
    let padded = "001".to_owned().into();
    let updated = store
        .update_two_factor(
            &padded,
            UpdateTwoFactor {
                secret: Some("updated-secret".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id, "1");
    assert_eq!(updated.secret, "updated-secret");
    let (first, second_attempt) = tokio::join!(
        store.compare_exchange_two_factor_backup_codes(
            &padded,
            "encrypted-codes",
            "first-replacement"
        ),
        store.compare_exchange_two_factor_backup_codes(
            &padded,
            "encrypted-codes",
            "second-replacement"
        ),
    );
    assert_eq!(
        [first?, second_attempt?]
            .into_iter()
            .filter(|success| *success)
            .count(),
        1
    );
    assert!(
        !store
            .compare_exchange_two_factor_backup_codes(&padded, "encrypted-codes", "replayed")
            .await?
    );
    let until = Utc::now() + chrono::Duration::minutes(15);
    store
        .record_two_factor_failure(&padded, 2, &|| Ok(until))
        .await?;
    store
        .record_two_factor_failure(&padded, 2, &|| Ok(until))
        .await?;
    let locked = required(store.get_two_factor_by_user_id("first").await?)?;
    assert_eq!(locked.failed_verification_count, Some(2));
    assert_eq!(locked.locked_until, Some(until.into()));
    store
        .reset_two_factor_failures(&padded, Some(until - chrono::Duration::seconds(1)))
        .await?;
    assert_eq!(
        required(store.get_two_factor_by_user_id("first").await?)?.failed_verification_count,
        Some(2)
    );
    store
        .reset_two_factor_failures(&padded, Some(until))
        .await?;
    let reset = required(store.get_two_factor_by_user_id("first").await?)?;
    assert_eq!(reset.failed_verification_count, Some(0));
    assert_eq!(reset.locked_until, None);
    assert_eq!(
        required(store.get_two_factor_by_user_id("second").await?)?,
        second
    );
    store.delete_two_factor("first").await?;
    assert_eq!(store.create_two_factor(two_factor("reused")).await?.id, "2");
    store.delete_two_factor("second").await?;
    assert!(store.get_two_factor_by_user_id("second").await?.is_none());
    assert_eq!(
        required(store.get_two_factor_by_user_id("reused").await?)?.id,
        "2"
    );
    Ok(())
}
