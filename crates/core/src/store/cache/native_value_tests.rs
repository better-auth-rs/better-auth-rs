#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};
use crate::{AuthResult, FieldMap, FieldValue};
use std::sync::Arc;

#[tokio::test]
async fn native_cache_retains_undefined_null_and_object_identity_without_changing_typed_access()
-> AuthResult<()> {
    let cache = MemoryCacheAdapter::new();
    SecondaryStorage::set(&cache, "typed", "value", None).await?;
    assert_eq!(
        CacheAdapter::get(&cache, "typed").await?,
        Some("value".into())
    );
    assert_eq!(
        SecondaryStorage::get(&cache, "typed").await?,
        Some(serde_json::Value::String("value".into()))
    );

    let undefined = FieldValue::Undefined;
    cache
        .set_native(&"undefined".into(), &undefined, None)
        .await?;
    cache
        .set_native(&"null".into(), &FieldValue::Null, None)
        .await?;
    assert_eq!(
        cache.get_native(&"undefined".into()).await?,
        Some(undefined)
    );
    assert_eq!(
        cache.get_native(&"null".into()).await?,
        Some(FieldValue::Null)
    );
    assert!(cache.get_native(&"missing".into()).await?.is_none());
    assert!(CacheAdapter::exists(&cache, "undefined").await?);
    assert!(CacheAdapter::get(&cache, "undefined").await.is_err());
    assert!(SecondaryStorage::get(&cache, "undefined").await.is_err());

    let object: FieldValue = FieldMap::from([("before".into(), true.into())]).into();
    cache.set_native(&"object".into(), &object, None).await?;
    object.set_model_property("after", 7.into())?;
    let consumed = cache
        .get_and_delete_native(&"object".into())
        .await?
        .ok_or_else(|| crate::AuthError::internal("Native cache record is missing"))?;
    assert!(consumed.strict_equals(&object));
    assert_eq!(consumed.model_property("after")?, 7.into());
    assert!(cache.get_native(&"object".into()).await?.is_none());
    assert_eq!(
        cache.get_and_delete_native(&"undefined".into()).await?,
        Some(FieldValue::Undefined)
    );
    assert!(!CacheAdapter::exists(&cache, "undefined").await?);
    Ok(())
}

#[tokio::test]
async fn concurrent_native_consumers_claim_a_present_undefined_once() -> AuthResult<()> {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let key: FieldValue = FieldMap::default().into();
    cache.set_native(&key, &FieldValue::Undefined, None).await?;
    let mut consumers = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let cache = cache.clone();
        let key = key.clone();
        consumers.spawn(async move { cache.get_and_delete_native(&key).await });
    }
    let mut claimed = Vec::new();
    while let Some(result) = consumers.join_next().await {
        if let Some(value) =
            result.map_err(|error| crate::AuthError::internal(error.to_string()))??
        {
            claimed.push(value);
        }
    }
    assert_eq!(claimed, vec![FieldValue::Undefined]);
    assert!(cache.get_native(&key).await?.is_none());
    Ok(())
}
