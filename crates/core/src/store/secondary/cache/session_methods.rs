#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::FieldArray;

#[tokio::test]
async fn creation_retains_get_time_results_until_their_cache_boundary() -> AuthResult<()> {
    let (store, cache) = storage()?;
    let user = store
        .create_user(CreateUser::new().with_email("get-time@example.test"))
        .await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let date = FieldDate::from_milliseconds_with_properties(
        EXPIRY as f64,
        FieldMap::from([(
            "getTime".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(arguments.is_empty());
                let mut calls = recorded.lock().unwrap();
                calls.push(receiver.clone());
                Ok(if calls.len() == 1 {
                    FieldValue::Undefined
                } else {
                    EXPIRY.into()
                })
            })
            .into(),
        )])
        .into(),
    );
    let mut input = session_input(user.id.clone(), "get-time".into());
    input.expires_at = date.clone();
    store.create_session(input).await?;
    assert_eq!(calls.lock().unwrap().len(), 3);
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .all(|receiver| receiver.strict_equals(&date.clone().into()))
    );
    let index = crate::store::secondary::sessions::active_sessions_key(&user.id.field_value())?;
    assert_eq!(encoded(&cache, &index).await?, r#"[{"token":"get-time"}]"#);
    assert!(cache.get_native(&"get-time".into()).await?.is_some());
    Ok(())
}

#[test]
fn cache_ttl_calls_get_time_before_numeric_conversion_and_preserves_errors() -> AuthResult<()> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let number = FieldMap::from([(
        "valueOf".into(),
        FieldFunction::contextual(move |_, arguments| {
            assert!(arguments.is_empty());
            recorded.lock().unwrap().push("valueOf");
            Ok(EXPIRY.to_string().into())
        })
        .into(),
    )]);
    let recorded = calls.clone();
    let expires: FieldValue = FieldMap::from([(
        "getTime".into(),
        FieldFunction::contextual(move |_, arguments| {
            assert!(arguments.is_empty());
            recorded.lock().unwrap().push("getTime");
            Ok(number.clone().into())
        })
        .into(),
    )])
    .into();
    let now = chrono::DateTime::from_timestamp_millis(NOW).unwrap();
    assert_eq!(
        SchemaValue::<FieldDate>::from_field(expires).cache_ttl(now)?,
        3_600.0
    );
    assert_eq!(*calls.lock().unwrap(), ["getTime", "valueOf"]);

    let failed: FieldValue = FieldMap::from([(
        "getTime".into(),
        FieldFunction::contextual(|_, _| Err(AuthError::bad_request("original getTime failure")))
            .into(),
    )])
    .into();
    assert!(matches!(
        SchemaValue::<FieldDate>::from_field(failed).cache_ttl(now),
        Err(AuthError::BadRequest(message)) if message == "original getTime failure"
    ));
    let non_callable = FieldDate::from_milliseconds_with_properties(
        EXPIRY as f64,
        FieldMap::from([("getTime".into(), FieldValue::Undefined)]).into(),
    );
    assert!(
        SchemaValue::from(non_callable.clone())
            .cache_ttl(now)
            .is_err()
    );
    assert_eq!(
        SchemaValue::from(non_callable).converted_cache_ttl(now)?,
        3_600.0
    );
    Ok(())
}

#[tokio::test]
async fn session_update_keeps_custom_filter_concat_sort_and_at_results() -> AuthResult<()> {
    let cache = Arc::new(NativeCache::default());
    let store = native_store(cache.clone())?;
    let user = store
        .create_user(CreateUser::new().with_email("method-chain@example.test"))
        .await?;
    let index = crate::store::secondary::sessions::active_sessions_key(&user.id.field_value())?;
    store
        .create_session(session_input(user.id, "current".into()))
        .await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let record = FieldMap::from([
        ("extra".into(), payload(7.0)),
        ("token".into(), "from-custom-sort".into()),
        ("expiresAt".into(), EXPIRY.into()),
    ]);
    let last = record.clone();
    let recorded = calls.clone();
    let sorted: FieldValue = FieldArray::from_values_with_properties(
        vec![record.into()],
        FieldMap::from([(
            "at".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert_eq!(arguments, &[FieldValue::from(-1)]);
                assert!(matches!(receiver, FieldValue::Array(_)));
                recorded.lock().unwrap().push("at");
                Ok(last.clone().into())
            })
            .into(),
        )])
        .into(),
    )
    .into();
    let expected = sorted.stringify()?.unwrap();
    let recorded = calls.clone();
    let sort_result = sorted.clone();
    let sortable: FieldValue = FieldDate::from_milliseconds_with_properties(
        0.0,
        FieldMap::from([(
            "sort".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(matches!(receiver, FieldValue::Date(_)));
                assert_eq!(arguments.len(), 1);
                let FieldValue::Function(compare) = &arguments[0] else {
                    return Err(AuthError::internal("Missing comparison callback"));
                };
                let entries = [EXPIRY, EXPIRY - 10].map(|expiration| {
                    FieldValue::from(FieldMap::from([("expiresAt".into(), expiration.into())]))
                });
                assert_eq!(
                    compare.call_with(&FieldValue::Undefined, &entries)?,
                    10.into()
                );
                recorded.lock().unwrap().push("sort");
                Ok(sort_result.clone())
            })
            .into(),
        )])
        .into(),
    )
    .into();
    let recorded = calls.clone();
    let concatenable: FieldValue = FieldFunction::contextual_with_properties(
        |_, _| Ok(FieldValue::Undefined),
        FieldMap::from([(
            "concat".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(matches!(receiver, FieldValue::Function(_)));
                assert_eq!(arguments.len(), 1);
                assert_eq!(
                    arguments[0],
                    FieldValue::from(vec![FieldValue::from(FieldMap::from([
                        ("token".into(), "current".into()),
                        ("expiresAt".into(), EXPIRY.into()),
                    ]))])
                );
                recorded.lock().unwrap().push("concat");
                Ok(sortable.clone())
            })
            .into(),
        )])
        .into(),
    )
    .into();
    let recorded = calls.clone();
    let list: FieldValue = FieldFunction::contextual_with_properties(
        |_, _| Ok(FieldValue::Undefined),
        FieldMap::from([(
            "filter".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(matches!(receiver, FieldValue::Function(_)));
                assert_eq!(arguments.len(), 1);
                recorded.lock().unwrap().push("filter");
                Ok(concatenable.clone())
            })
            .into(),
        )])
        .into(),
    )
    .into();
    cache.seed(&index.display_utf16()?.to_utf8().unwrap(), list);
    assert!(
        store
            .update_session_fields("current", FieldMap::new())
            .await?
            .is_some()
    );
    assert_eq!(*calls.lock().unwrap(), ["filter", "concat", "sort", "at"]);
    assert_eq!(encoded(&cache.values, &index).await?, expected);
    Ok(())
}
