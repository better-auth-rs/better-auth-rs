use super::*;
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use crate::{FieldMap, SchemaValue};
use std::sync::Arc;

fn only_row(store: &EphemeralStore) -> AuthResult<FieldMap> {
    let mut rows = store.plugin_storage_rows(EntityRole::ApiKey)?;
    assert_eq!(rows.len(), 1);
    rows.pop()
        .ok_or_else(|| AuthError::internal("Missing usage row"))
}

#[tokio::test]
async fn atomic_setters_reject_transformed_empty_updates_but_plain_updates_remain_valid()
-> AuthResult<()> {
    let mut store = EphemeralStore::default();
    let key = store.create_api_key(input()).await?;
    let stored = only_row(&store)?;
    store.model_fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [
                    ("remaining", UserFieldType::Number),
                    ("lastRefillAt", UserFieldType::Date),
                    ("requestCount", UserFieldType::Number),
                    ("lastRequest", UserFieldType::Date),
                ]
                .into_iter()
                .map(|(name, field_type)| {
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type,
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|_| Ok(FieldValue::Undefined))),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
            ),
        },
    );
    let at = Utc::now();
    for write in [
        ApiKeyUsageWrite::Refill {
            previous: FieldValue::Null,
            remaining: 7.0,
            at,
        },
        ApiKeyUsageWrite::StartWindow {
            previous_before: None,
            at,
        },
    ] {
        let result = store.write_api_key_usage(&key.id, write).await;
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message
            == "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.")
        );
        assert_eq!(only_row(&store)?, stored);
    }
    assert!(
        store
            .write_api_key_usage(&key.id, ApiKeyUsageWrite::LastRequest(at))
            .await?
            .is_some()
    );
    assert_eq!(only_row(&store)?, stored);
    Ok(())
}

// Memory incrementOne checks typeof number before adding; cache arithmetic has a different contract.
#[tokio::test]
async fn memory_atomic_usage_treats_nonnumeric_storage_as_zero() -> AuthResult<()> {
    for value in [
        FieldValue::Number(5.0),
        "5".into(),
        true.into(),
        vec![5.0.into()].into(),
    ] {
        let store = EphemeralStore::default();
        let initial: FieldValue = FieldDate::from_milliseconds(10_000.0).into();
        let _ = store
            .create_api_key_record(FieldMap::from([
                ("id".into(), "key".into()),
                ("remaining".into(), value.clone()),
                ("requestCount".into(), value.clone()),
                ("lastRequest".into(), initial),
            ]))
            .await?;
        let id: SchemaValue<String> = "key".to_owned().into();
        let mut expected = only_row(&store)?;
        let decremented = store
            .write_api_key_usage(&id, ApiKeyUsageWrite::Decrement)
            .await?
            .ok_or_else(|| AuthError::internal("Expected quota write"))?;
        let decrement: FieldValue = if value.is_number() { 4.0 } else { -1.0 }.into();
        let _ = expected.insert("remaining".into(), decrement.clone());
        assert_eq!(decremented.remaining.field_value(), decrement);
        assert_eq!(only_row(&store)?, expected);

        let at = Utc::now();
        let incremented = store
            .write_api_key_usage(
                &id,
                ApiKeyUsageWrite::IncrementWindow {
                    previous_after: FieldDate::from_milliseconds(9_000.0),
                    maximum: 10.0.into(),
                    at,
                },
            )
            .await?
            .ok_or_else(|| AuthError::internal("Expected rate write"))?;
        let increment: FieldValue = if value.is_number() { 6.0 } else { 1.0 }.into();
        expected.extend([
            ("requestCount".into(), increment.clone()),
            ("lastRequest".into(), at.into()),
        ]);
        assert_eq!(incremented.request_count.field_value(), increment);
        assert_eq!(only_row(&store)?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn memory_usage_binds_replaced_guards_and_applies_set_after_increment() -> AuthResult<()> {
    let mut store = EphemeralStore::default();
    store.model_fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "lastRefillAt".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            ..Default::default()
                        },
                    ),
                    (
                        "requestCount".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            field_name: Some("counter".into()),
                            on_update: Some(Arc::new(|| Ok(99.0.into()))),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    );
    let _ = store
        .create_api_key_record(FieldMap::from([
            ("id".into(), "key".into()),
            ("remaining".into(), 5.0.into()),
            ("requestCount".into(), 2.0.into()),
            ("lastRefillAt".into(), 123.0.into()),
            (
                "lastRequest".into(),
                FieldDate::from_milliseconds(10_000.0).into(),
            ),
        ]))
        .await?;
    let id: SchemaValue<String> = "key".to_owned().into();
    let mut expected = only_row(&store)?;
    let at = Utc::now();
    let result = store
        .write_api_key_usage(
            &id,
            ApiKeyUsageWrite::IncrementWindow {
                previous_after: FieldDate::from_milliseconds(9_000.0),
                maximum: "10".into(),
                at,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected mapped rate write"))?;
    expected.extend([
        ("counter".into(), 99.0.into()),
        ("lastRequest".into(), at.into()),
    ]);
    assert_eq!(result.request_count.field_value(), 99.0.into());
    assert_eq!(only_row(&store)?, expected);

    let result = store
        .write_api_key_usage(
            &id,
            ApiKeyUsageWrite::Refill {
                previous: "123".into(),
                remaining: 7.0,
                at,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected converted refill guard"))?;
    expected.extend([
        ("remaining".into(), 7.0.into()),
        ("lastRefillAt".into(), at.into()),
    ]);
    assert_eq!(result.remaining.field_value(), 7.0.into());
    assert_eq!(only_row(&store)?, expected);
    Ok(())
}

#[tokio::test]
async fn multi_match_update_and_atomic_usage_keep_distinct_targets() -> AuthResult<()> {
    let store = EphemeralStore::default();
    for remaining in [0.0, 2.0, 3.0] {
        let _ = store
            .create_api_key_record(
                [
                    ("id".into(), "shared".into()),
                    ("remaining".into(), remaining.into()),
                ]
                .into(),
            )
            .await?;
    }
    let id = "shared".to_owned().into();
    let result = store
        .write_api_key_usage(&id, ApiKeyUsageWrite::Decrement)
        .await?
        .ok_or_else(|| AuthError::internal("The second matching row must consume quota"))?;
    assert_eq!(result.remaining.field_value(), 1.0.into());
    let remaining = || -> AuthResult<Vec<FieldValue>> {
        Ok(store
            .plugin_storage_rows(EntityRole::ApiKey)?
            .iter()
            .map(|row| row.get("remaining").cloned().unwrap_or_default())
            .collect())
    };
    assert_eq!(remaining()?, [0.0.into(), 1.0.into(), 3.0.into()]);
    let _ = store
        .update_api_key_record(&id, [("remaining".into(), 8.0.into())].into())
        .await?;
    assert_eq!(remaining()?, [8.0.into(), 8.0.into(), 8.0.into()]);
    store.delete_api_key(&id).await?;
    assert!(remaining()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn atomic_usage_finishes_guard_evaluation_before_any_write() -> AuthResult<()> {
    let store = EphemeralStore::default();
    for remaining in [
        2.0.into(),
        FieldValue::from(FieldMap::from([
            ("valueOf".into(), false.into()),
            ("toString".into(), false.into()),
        ])),
    ] {
        let _ = store
            .create_api_key_record(
                [
                    ("id".into(), "shared".into()),
                    ("remaining".into(), remaining),
                ]
                .into(),
            )
            .await?;
    }
    let before = store.plugin_storage_rows(EntityRole::ApiKey)?;
    let result = store
        .write_api_key_usage(&"shared".to_owned().into(), ApiKeyUsageWrite::Decrement)
        .await;
    assert!(result.is_err());
    assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, before);
    Ok(())
}
