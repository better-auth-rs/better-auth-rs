#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use better_auth_core::{FieldArray, FieldFunction, FieldObject, FromFieldMap};
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn omitted_record_serialization_reaches_both_writes_before_a_reference_failure()
-> AuthResult<()> {
    let cache = Arc::new(Cache::default());
    cache.seed(INDEX, "{}".into());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut fields = record("key".into()).field_values()?;
    let _ = fields.insert(
        "toJSON".into(),
        FieldFunction::contextual(move |receiver, arguments| {
            assert_eq!(receiver.model_property("id")?, "key".into());
            assert_eq!(arguments, &[FieldValue::from("")]);
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            Ok(FieldValue::Undefined)
        })
        .into(),
    );
    let key = ApiKey::from_field_values(fields)?;
    let error = put(cache.clone(), &key, false).await.unwrap_err();
    assert!(error.to_string().contains("includes"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.value("api-key:hash"), Some(FieldValue::Undefined));
    assert_eq!(
        cache.value("api-key:by-id:key"),
        Some(FieldValue::Undefined)
    );
    assert_eq!(cache.value(INDEX), Some("{}".into()));
    assert_eq!(
        *cache.writes.lock().unwrap(),
        vec![
            Write::Set("api-key:hash".into(), FieldValue::Undefined),
            Write::Set("api-key:by-id:key".into(), FieldValue::Undefined),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn omitted_reference_serialization_is_a_write_after_key_deletion() -> AuthResult<()> {
    for result in [
        FieldValue::Undefined,
        FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
    ] {
        let cache = Arc::new(Cache::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let output: FieldValue = FieldMap::from([
            ("length".into(), 1.into()),
            (
                "toJSON".into(),
                FieldFunction::contextual(move |_, arguments| {
                    assert_eq!(arguments, &[FieldValue::from("")]);
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Ok(result.clone())
                })
                .into(),
            ),
        ])
        .into();
        let index = FieldArray::from_values_with_properties(
            vec!["key".into()],
            FieldObject::from(FieldMap::from([(
                "filter".into(),
                FieldFunction::contextual(move |_, _| Ok(output.clone())).into(),
            )])),
        );
        cache.seed("api-key:hash", "old-hash".into());
        cache.seed("api-key:by-id:key", "old-id".into());
        cache.seed(INDEX, index.into());
        remove_cached(cache.clone(), &record("key".into()), false).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.value("api-key:hash"), None);
        assert_eq!(cache.value("api-key:by-id:key"), None);
        assert_eq!(cache.value(INDEX), Some(FieldValue::Undefined));
        assert_eq!(
            *cache.writes.lock().unwrap(),
            vec![
                Write::Delete("api-key:hash".into()),
                Write::Delete("api-key:by-id:key".into()),
                Write::Set(INDEX.into(), FieldValue::Undefined),
            ]
        );
    }
    Ok(())
}
