use super::*;
use better_auth_core::{ApiKey, SchemaValue, store::ConsumeApiKeyResult};

#[tokio::test]
async fn secondary_usage_skips_a_null_requests_window_and_repeats_later_conversion()
-> AuthResult<()> {
    for start in [true, false] {
        let cache = Arc::new(Cache::successful(false, &seed())?);
        let config = Arc::new(AuthConfig::default());
        let database = Arc::new(EphemeralStore::new(config.clone()));
        let context = AuthContext::new(config, database)?;
        let options = ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache.clone()),
            disable_key_hashing: true,
            ..Default::default()
        };
        let mut key: ApiKey = serde_json::from_value(seed())?;
        key.remaining = None.into();
        key.rate_limit_enabled = true.into();
        key.request_count = Some(1.0).into();
        if !start {
            key.last_request = Some(better_auth_core::FieldDate::from_milliseconds(0.0)).into();
        }
        let original = FieldValue::from(FieldMap::from([("cause".into(), "window".into())]));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        key.rate_limit_time_window = SchemaValue::from_field(
            FieldMap::from([(
                "valueOf".into(),
                FieldFunction::contextual({
                    let calls = calls.clone();
                    let original = original.clone();
                    move |_, _| {
                        let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if !start && call == 0 {
                            Ok(f64::INFINITY.into())
                        } else {
                            Err(AuthError::from_thrown(original.clone()))
                        }
                    }
                })
                .into(),
            )])
            .into(),
        );
        let before = lock(&cache.values)?.clone();
        let result = super::super::consume(&options, &context, &key, "usage-secret").await;
        if start {
            let ConsumeApiKeyResult::Allowed(updated) = result? else {
                return Err(AuthError::internal("A first request must start its window"));
            };
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(updated.request_count.field_value(), 1.0.into());
            assert!(updated.remaining.field_value().is_null());
            let values = lock(&cache.values)?;
            let stored: Value = serde_json::from_str(
                values
                    .get(HASH)
                    .ok_or_else(|| AuthError::internal("Missing cache row"))?,
            )?;
            assert_eq!(stored, serde_json::to_value(updated)?);
        } else {
            let error = match result {
                Err(error) => error,
                Ok(_) => return Err(AuthError::internal("The second conversion must fail")),
            };
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(&original))
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert_eq!(*lock(&cache.values)?, before);
            assert!(lock(&cache.events)?.is_empty());
        }
    }
    Ok(())
}
