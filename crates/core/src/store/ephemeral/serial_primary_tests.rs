use super::*;

mod device;
mod fixture;
mod organization;
mod plugin_credentials;
mod session_plugins;

fn serial_store() -> EphemeralStore {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    EphemeralStore::new(Arc::new(config))
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a stored Serial fixture row"))
}

fn verification(identifier: &str) -> CreateVerification {
    CreateVerification {
        identifier: identifier.into(),
        value: "proof".into(),
        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn serial_account_primary_ids_bind_padded_queries_and_project_strings() -> AuthResult<()> {
    let store = serial_store();
    for subject in ["first", "second"] {
        let created = store
            .create_account(CreateAccount {
                account_id: subject.into(),
                provider_id: "fixture".into(),
                user_id: "1".into(),
                ..Default::default()
            })
            .await?;
        assert!(matches!(created.id.field_value(), Value::String(_)));
    }
    assert_eq!(
        store
            .lock()?
            .accounts
            .snapshot()?
            .into_iter()
            .map(|row| row.get("id").cloned().unwrap_or_default())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), Value::Number(2.0)]
    );
    let updated = store
        .update_account(
            "001",
            UpdateAccount {
                account_id: "updated".into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id, "1");
    assert_eq!(updated.account_id, "updated");
    store.delete_account("001").await?;
    assert!(store.get_account("fixture", "updated").await?.is_none());
    assert_eq!(
        required(store.get_account("fixture", "second").await?)?.id,
        "2"
    );
    Ok(())
}

#[tokio::test]
async fn serial_verification_deletion_keeps_reserved_string_ids() -> AuthResult<()> {
    let store = serial_store();
    let _ = store.create_verification(verification("ordinary")).await?;
    assert!(
        store
            .reserve_verification("1", verification("reserved"))
            .await?
    );
    let reserved = required(store.get_verification_by_identifier("reserved").await?)?;
    store.delete_verification("1").await?;
    assert!(
        store
            .get_verification_by_identifier("reserved")
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_verification_by_identifier("ordinary").await?)?.id,
        "1"
    );
    assert!(
        store
            .reserve_verification("1", verification("reserved"))
            .await?
    );
    store.delete_verification("001").await?;
    assert!(
        store
            .get_verification_by_identifier("ordinary")
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_verification_by_identifier("reserved").await?)?.id,
        reserved.id
    );
    store.delete_verification(reserved.id.typed()?).await?;
    assert!(store.lock()?.verifications.snapshot()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn serial_verification_consumption_preserves_numeric_and_reservation_ids() -> AuthResult<()> {
    let store = serial_store();
    let ordinary = store.create_verification(verification("ordinary")).await?;
    assert_eq!(ordinary.id, "1");
    assert!(
        store
            .reserve_verification_value(verification("reserved"))
            .await?
    );
    assert!(
        !store
            .reserve_verification_value(verification("reserved"))
            .await?
    );
    let reserved = required(store.get_verification_by_identifier("reserved").await?)?;
    assert_eq!(
        store
            .lock()?
            .verifications
            .snapshot()?
            .into_iter()
            .map(|row| row.get("id").cloned().unwrap_or_default())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), reserved.id.field_value()]
    );
    for (identifier, expected_id) in [("ordinary", ordinary.id), ("reserved", reserved.id)] {
        let (first, second) = tokio::join!(
            store.consume_verification_by_identifier(identifier),
            store.consume_verification_by_identifier(identifier),
        );
        let consumed = [first?, second?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(consumed.len(), 1);
        assert_eq!(required(consumed.first())?.id, expected_id);
    }
    assert!(store.lock()?.verifications.snapshot()?.is_empty());
    Ok(())
}
