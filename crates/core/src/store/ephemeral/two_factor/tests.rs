use super::*;
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn settings() -> CreateTwoFactor {
    CreateTwoFactor {
        additional_fields: Default::default(),
        user_id: "owner".into(),
        secret: "encrypted-secret".into(),
        backup_codes: "encrypted-codes".into(),
        verified: true,
    }
}

#[tokio::test]
async fn nullable_memory_counter_starts_at_zero_and_keeps_account_lockout() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let factor = store.create_two_factor(settings()).await?;
    let _ = store
        .update_two_factor_record(
            &factor.id,
            [
                ("failedVerificationCount".into(), FieldValue::Null),
                ("lockedUntil".into(), FieldValue::Null),
            ]
            .into(),
        )
        .await?;
    let lock: FieldDate = (Utc::now() + chrono::Duration::minutes(15)).into();
    for expected in [1, 2] {
        store
            .record_two_factor_failure(&factor.id, 2, &|| Ok(lock.clone()))
            .await?;
        let stored = store
            .get_two_factor_by_user_id("owner")
            .await?
            .ok_or_else(|| AuthError::internal("Missing factor"))?;
        assert_eq!(
            stored.failed_verification_count.field_value(),
            expected.into()
        );
        assert_eq!(
            stored.locked_until.field_value(),
            if expected == 2 {
                lock.clone().into()
            } else {
                FieldValue::Null
            }
        );
        assert_eq!(stored.verified.field_value(), true.into());
        assert_eq!(stored.secret, factor.secret);
        assert_eq!(stored.backup_codes, factor.backup_codes);
    }
    Ok(())
}

#[tokio::test]
async fn lock_uses_projected_counter_but_retains_physical_atomic_guard() -> AuthResult<()> {
    let writes = Arc::new(AtomicUsize::new(0));
    let observed = writes.clone();
    let mut store = EphemeralStore::default();
    store.model_fields.register(
        EntityRole::TwoFactor,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "failedVerificationCount".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            field_name: Some("failures".into()),
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(|_| Ok(9.into()))),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "lockedUntil".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Date,
                            field_name: Some("deadline".into()),
                            on_update: Some(Arc::new(move || {
                                let _ = observed.fetch_add(1, Ordering::SeqCst);
                                Ok(FieldValue::Null)
                            })),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    )?;
    let factor = store.create_two_factor(settings()).await?;
    let deadlines = AtomicUsize::new(0);
    store
        .record_two_factor_failure(&factor.id, 2, &|| {
            let _ = deadlines.fetch_add(1, Ordering::SeqCst);
            Ok(FieldDate::from_milliseconds(100.0))
        })
        .await?;
    let row = store
        .plugin_storage_rows(EntityRole::TwoFactor)?
        .pop()
        .ok_or_else(|| AuthError::internal("Missing row"))?;
    assert_eq!(row.get("failures"), Some(&1.into()));
    assert_eq!(row.get("deadline"), None);
    assert_eq!(deadlines.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    store
        .record_two_factor_failure(&factor.id, 2, &|| Ok(FieldDate::from_milliseconds(100.0)))
        .await?;
    let row = store
        .plugin_storage_rows(EntityRole::TwoFactor)?
        .pop()
        .ok_or_else(|| AuthError::internal("Missing row"))?;
    assert_eq!(row.get("failures"), Some(&2.into()));
    assert_eq!(
        row.get("deadline")
            .and_then(FieldValue::as_date)
            .map(FieldDate::milliseconds),
        Some(100.0)
    );
    Ok(())
}

#[tokio::test]
async fn backup_cas_applies_input_mapping_and_retains_commit_after_output_error() -> AuthResult<()>
{
    let mut store = EphemeralStore::default();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let throw = fail.clone();
    store.model_fields.register(
        EntityRole::TwoFactor,
        UserConfig {
            additional_fields: Some(
                [(
                    "backupCodes".into(),
                    UserFieldConfig {
                        field_name: Some("codes".into()),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|value| Ok(value))),
                            output: Some(UserFieldTransform::new(move |value| {
                                if throw.load(Ordering::SeqCst) {
                                    Err(AuthError::internal("projected backup failure"))
                                } else {
                                    Ok(value)
                                }
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    )?;
    let factor = store.create_two_factor(settings()).await?;
    fail.store(true, Ordering::SeqCst);
    let result = store
        .compare_exchange_two_factor_backup_codes(
            &factor.id,
            &factor.backup_codes.field_value(),
            7.into(),
        )
        .await;
    assert!(result.is_err());
    let row = store
        .plugin_storage_rows(EntityRole::TwoFactor)?
        .pop()
        .ok_or_else(|| AuthError::internal("Missing row"))?;
    assert_eq!(row.get("codes"), Some(&7.into()));
    assert!(
        !store
            .compare_exchange_two_factor_backup_codes(
                &factor.id,
                &factor.backup_codes.field_value(),
                8.into()
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn backup_cas_rejects_transformed_empty_set_before_storage_or_output() -> AuthResult<()> {
    for asynchronous in [false, true] {
        for matches_guard in [false, true] {
            let mut store = EphemeralStore::default();
            let factor = store.create_two_factor(settings()).await?;
            let stored = store.plugin_storage_rows(EntityRole::TwoFactor)?;
            let inputs = Arc::new(AtomicUsize::new(0));
            let outputs = Arc::new(AtomicUsize::new(0));
            let observed_input = inputs.clone();
            let discard = move |value: FieldValue| {
                assert_eq!(value, FieldValue::from("replacement-codes"));
                let _ = observed_input.fetch_add(1, Ordering::SeqCst);
                Ok(FieldValue::Undefined)
            };
            let input = if asynchronous {
                UserFieldTransform::new_async(move |value| std::future::ready(discard(value)))
            } else {
                UserFieldTransform::new(discard)
            };
            let observed_output = outputs.clone();
            store.model_fields.register(
                EntityRole::TwoFactor,
                UserConfig {
                    additional_fields: Some(
                        [(
                            "backupCodes".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    input: Some(input),
                                    output: Some(UserFieldTransform::new(move |value| {
                                        let _ = observed_output.fetch_add(1, Ordering::SeqCst);
                                        Ok(value)
                                    })),
                                }),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
            )?;
            let previous = if matches_guard {
                factor.backup_codes.field_value()
            } else {
                "stale-codes".into()
            };
            let result = store
                .compare_exchange_two_factor_backup_codes(
                    &factor.id,
                    &previous,
                    "replacement-codes".into(),
                )
                .await;
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message
                == "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.")
            );
            assert_eq!(store.plugin_storage_rows(EntityRole::TwoFactor)?, stored);
            assert_eq!(inputs.load(Ordering::SeqCst), 1);
            assert_eq!(outputs.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}
