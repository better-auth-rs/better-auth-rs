use super::*;
use crate::DeviceCodeOwnership;

fn device(code: &str) -> CreateDeviceCode {
    CreateDeviceCode {
        device_code: code.into(),
        user_code: format!("user-{code}"),
        user_id: None,
        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
        status: "pending".into(),
        last_polled_at: None,
        polling_interval: Some(5000.0),
        client_id: Some("client".into()),
        scope: Some("read".into()).into(),
        additional_fields: FieldMap::new(),
    }
}

#[tokio::test]
async fn serial_device_queries_preserve_claim_and_consumption_bindings() -> AuthResult<()> {
    let store = serial_store();
    let first = store.create_device_code(device("first")).await?;
    let second = store.create_device_code(device("second")).await?;
    assert_eq!(first.id, "1");
    assert_eq!(second.id, "2");
    assert_eq!(
        store
            .lock()?
            .device_codes
            .snapshot()?
            .iter()
            .map(|row| row.get("id").cloned().unwrap_or_default())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), Value::Number(2.0)]
    );
    let padded = "001".to_owned().into();
    assert!(store.claim_device_code(&padded, &"owner".into()).await?);
    assert!(!store.claim_device_code(&padded, &"other".into()).await?);
    assert!(
        store
            .update_device_code_if_status(
                &padded,
                "pending",
                UpdateDeviceCode {
                    status: Some("approved".into()),
                    ..Default::default()
                }
            )
            .await?
    );
    assert!(
        !store
            .update_device_code_if_status(
                &padded,
                "pending",
                UpdateDeviceCode {
                    user_id: Some(Some("other".into()).into()),
                    ..Default::default()
                }
            )
            .await?
    );
    let mut expected = required(store.get_device_code_by_user_code("user-first").await?)?;
    let ownership = DeviceCodeOwnership::ClientId("client".into());
    expected.id = "002".to_owned().into();
    assert!(
        store
            .consume_device_code(&expected, &ownership)
            .await?
            .is_none()
    );
    expected.id = padded.clone();
    assert!(
        store
            .consume_device_code(&expected, &ownership)
            .await?
            .is_none()
    );
    expected.id = first.id.clone();
    expected.user_id = Some("other".into()).into();
    assert!(
        store
            .consume_device_code(&expected, &ownership)
            .await?
            .is_none()
    );
    expected.user_id = Some("owner".into()).into();
    let consumed = required(store.consume_device_code(&expected, &ownership).await?)?;
    assert_eq!(consumed.id, "1");
    assert_eq!(consumed.user_id.typed()?.as_deref(), Some("owner"));
    assert!(
        store
            .consume_device_code(&expected, &ownership)
            .await?
            .is_none()
    );
    let second_id = "002".to_owned().into();
    assert!(
        !store
            .delete_device_code_if_status(&second_id, "approved")
            .await?
    );
    let second = store
        .update_device_code(
            &second_id,
            UpdateDeviceCode {
                status: Some("denied".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(second.id, "2");
    assert!(
        store
            .delete_device_code_if_status(&second_id, "denied")
            .await?
    );
    assert_eq!(store.create_device_code(device("third")).await?.id, "1");
    store.delete_device_code(&padded).await?;
    assert!(store.lock()?.device_codes.snapshot()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn serial_device_transaction_rejects_changed_owner_and_commits_unchanged_owner()
-> AuthResult<()> {
    let store = serial_store();
    let mut input = device("transaction");
    input.status = "approved".into();
    input.user_id = Some("owner".into());
    let expected = store.create_device_code(input).await?;
    let ownership = DeviceCodeOwnership::ClientId("client".into());
    let (base, isolated, queue) = store.begin_transaction()?;
    assert_eq!(
        required(isolated.consume_device_code(&expected, &ownership).await?)?.id,
        "1"
    );
    let updated = store
        .update_device_code(
            &expected.id,
            UpdateDeviceCode {
                user_id: Some(Some("changed".into()).into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(matches!(
        store.commit_transaction(base, isolated, queue).await,
        Err(AuthError::Internal(message)) if message == "Device code changed before transaction commit"
    ));
    let raw = required(store.lock()?.device_codes.snapshot()?.first()).cloned()?;
    assert_eq!(
        raw.get("id").cloned().unwrap_or_default(),
        Value::Number(1.0)
    );
    assert_eq!(raw.get("userId").and_then(Value::as_str), Some("changed"));
    let (base, isolated, queue) = store.begin_transaction()?;
    assert_eq!(
        required(isolated.consume_device_code(&updated, &ownership).await?)?,
        updated
    );
    store.commit_transaction(base, isolated, queue).await?;
    assert!(
        store
            .get_device_code_by_device_code("transaction")
            .await?
            .is_none()
    );
    Ok(())
}
