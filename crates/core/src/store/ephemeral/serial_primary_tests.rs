#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::store::schema::EntityRole;

mod device;
mod fixture;
mod organization;
mod plugin_credentials;
mod session_plugins;
mod team_members;

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
            .storage_rows(EntityRole::Account)?
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
async fn serial_verification_deletion_uses_numeric_reservation_ids() -> AuthResult<()> {
    let store = serial_store();
    let _ = store.create_verification(verification("ordinary")).await?;
    assert!(
        store
            .reserve_verification("1", verification("reserved"))
            .await?
    );
    let reserved = required(store.get_verification_by_identifier("reserved").await?)?;
    assert_eq!(reserved.id, "2");
    store.delete_verification("1").await?;
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
    assert_eq!(
        store
            .storage_rows(EntityRole::Verification)?
            .into_iter()
            .map(|row| row.get("id").cloned().unwrap_or_default())
            .collect::<Vec<_>>(),
        [Value::Number(2.0), Value::Number(2.0)]
    );
    store.delete_verification(reserved.id.typed()?).await?;
    assert!(store.storage_rows(EntityRole::Verification)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn serial_verification_consumption_preserves_numeric_reservation_ids() -> AuthResult<()> {
    let store = serial_store();
    let ordinary = store.create_verification(verification("ordinary")).await?;
    assert_eq!(ordinary.id, "1");
    assert!(
        store
            .reserve_verification_value(verification("reserved"))
            .await?
    );
    assert!(
        store
            .reserve_verification_value(verification("reserved"))
            .await?
    );
    assert_eq!(
        required(store.get_verification_by_identifier("reserved").await?)?.id,
        "2"
    );
    // Reservations replace caller timestamps. Fix stored dates so latest selection cannot tie.
    let mut created_at = 0.0;
    store.operation(|op| {
        for row in op
            .capture_table(EntityRole::Verification)?
            .snapshot_refs()?
        {
            created_at += 1_000.0;
            row.set_field(
                "createdAt".into(),
                crate::FieldDate::from_milliseconds(created_at).into(),
            )?;
        }
        Ok(())
    })?;
    assert_eq!(
        store
            .storage_rows(EntityRole::Verification)?
            .into_iter()
            .map(|row| row.get("id").cloned().unwrap_or_default())
            .collect::<Vec<_>>(),
        [Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]
    );
    for (identifier, expected_id) in [("ordinary", "1"), ("reserved", "3")] {
        let (first, second) = tokio::join!(
            store.consume_verification_by_identifier(identifier),
            store.consume_verification_by_identifier(identifier),
        );
        let consumed = [first?, second?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(consumed.len(), 1);
        assert_eq!(required(consumed.first())?.id, expected_id);
    }
    assert!(store.storage_rows(EntityRole::Verification)?.is_empty());
    Ok(())
}
