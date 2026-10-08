use super::*;

async fn read<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
    id: &SchemaValue<String>,
) -> AuthResult<Option<FieldMap>> {
    if target == Target::ApiKeyName {
        store.get_api_key_record(id).await
    } else {
        store.get_passkey_record(id).await
    }
}

// This extension follows Kysely withReturning source; the pinned fixture has no ID-update sample.
pub(super) async fn check<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, target: Target) -> TestResult {
    let state = policies::Shared::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(policies::Policy {
            target,
            defaults: false,
            state: state.clone(),
        })
        .build()
        .await?;
    let store = auth.store().as_ref();
    reset(store, target, &state).await?;
    let value = object("primary-key");
    let _ = create(store, target, value.clone()).await?;
    let old_id = ID.to_owned().into();
    let new_id = SchemaValue::from("display-json-moved".to_owned());
    let mut expected = read(store, target, &old_id)
        .await?
        .ok_or("Missing primary-key update seed")?;
    {
        let mut state = state.lock().expect("primary-key update state");
        state.events.clear();
        state.wrap_output = true;
    }
    let patch = FieldMap::from([("id".into(), new_id.field_value())]);
    let updated = if target == Target::ApiKeyName {
        store.update_api_key_record(&old_id, patch).await?
    } else {
        store.update_passkey_record(&old_id, patch).await?
    }
    .ok_or("MySQL must return the record under its updated primary key")?;
    let _ = expected.insert("id".into(), new_id.field_value());
    let _ = expected.insert(
        target.field().into(),
        FieldMap::from([("output".into(), value.clone())]).into(),
    );
    assert_eq!(updated, expected, "{target:?} complete updated record");
    let event = json!({
        "phase": "output",
        "field": target.field(),
        "value": values::observe(&value)?,
    });
    let events = std::mem::take(&mut state.lock().expect("primary-key update events").events);
    assert_eq!(
        events.as_slice(),
        std::slice::from_ref(&event),
        "The update must project the record once after reselecting the new primary key"
    );
    assert!(read(store, target, &old_id).await?.is_none());
    assert!(
        state
            .lock()
            .expect("missing primary-key events")
            .events
            .is_empty()
    );
    assert_eq!(read(store, target, &new_id).await?, Some(expected));
    assert_eq!(
        state.lock().expect("new primary-key events").events,
        [event],
        "The new primary key must resolve and project the moved record"
    );
    eprintln!(
        "MySQL primary-key update regression: target={target:?}; source-derived extension; no paired upstream ID-update fixture"
    );
    Ok(())
}
