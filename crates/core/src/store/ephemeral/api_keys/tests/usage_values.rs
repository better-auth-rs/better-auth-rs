use super::*;
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use crate::{FieldMap, SchemaValue};
use std::sync::Arc;

fn only_row(store: &EphemeralStore) -> AuthResult<FieldMap> {
    let mut rows = store.plugin_storage_rows(EntityRole::ApiKey)?;
    assert_eq!(rows.len(), 1);
    rows.pop()
        .ok_or_else(|| AuthError::internal("Missing usage row"))
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
    )?;
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
