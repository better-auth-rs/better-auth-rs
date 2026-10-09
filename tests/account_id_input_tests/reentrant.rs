use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Read {
    Found,
    Missing,
}

pub(super) async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    read: Read,
    id_first: bool,
) -> AuthResult<()> {
    let found = read == Read::Found;
    let existing = input("existing".into(), "existing", "existing");
    if found {
        let _ = base.create_account(existing.clone()).await?;
    }
    let target = Arc::new(OnceLock::<Weak<dyn AuthStore<S>>>::new());
    let callback_target = target.clone();
    let events = Events::default();
    let callback_events = events.clone();
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.advanced.database.generate_id = Some(if found {
        generator(&events, false)
    } else {
        IdGeneration::Uuid
    });
    let probe = UserFieldConfig {
        field_name: Some("scope".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = callback_target.clone();
                let events = callback_events.clone();
                async move {
                    event(&events, "probe-input", value.clone())?;
                    let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                        AuthError::internal("Reentrant Account store is unavailable")
                    })?;
                    let nested = store
                        .get_account("provider", if found { "existing" } else { "missing" })
                        .await?;
                    event(&events, "nested-read", visible(nested.as_ref())?)?;
                    Ok(value)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    if id_first {
        let _ = config
            .account
            .additional_fields
            .insert("id".into(), id_sentinel());
    }
    let _ = config
        .account
        .additional_fields
        .insert("probe".into(), probe);
    if !id_first {
        let _ = config
            .account
            .additional_fields
            .insert("id".into(), id_sentinel());
    }
    let reader = reader(base.as_ref(), config, &events)?;
    target
        .set(Arc::downgrade(&reader))
        .map_err(|_| AuthError::internal("Reentrant Account store was already assigned"))?;
    let supplied = if found {
        FieldValue::Undefined
    } else {
        "not-a-uuid".into()
    };
    let mut data = input(supplied, "subject", "before");
    let _ = data
        .additional_fields
        .insert("probe".into(), "outer".into());
    let result = reader.create_account_optional(data).await;
    let has_id = if found { id_first } else { !id_first };
    let final_id = if has_id {
        if found {
            "generated".into()
        } else {
            "not-a-uuid".into()
        }
    } else {
        FieldValue::Undefined
    };
    let succeeds = has_id || storage.is_memory();
    let mut raw = super::target(final_id.clone())?;
    let _ = raw.insert("scope".into(), "outer".into());
    let mut projected = raw.clone();
    let _ = projected.insert("id".into(), final_id);
    let _ = projected.insert("probe".into(), "outer".into());
    assert_created(result, succeeds.then_some(&projected))?;
    let mut trace_events = Vec::new();
    if found && id_first {
        trace_events.push(trace("generate", "account".into()));
    }
    trace_events.push(trace("probe-input", "outer".into()));
    let nested = if found {
        let mut fields = existing.fields()?;
        let _ = fields.insert("probe".into(), "read".into());
        fields.into()
    } else {
        FieldValue::Null
    };
    trace_events.push(trace("nested-read", nested));
    if succeeds {
        trace_events.push(trace("after-create", projected.into()));
    }
    let mut stored = vec![storage.expected(retained().fields()?)?];
    if found {
        stored.push(storage.expected(existing.fields()?)?);
    }
    if succeeds {
        stored.push(storage.expected(raw)?);
    }
    assert_eq!(observed(&events)?, trace_events, "{read:?}/{id_first}");
    assert_eq!(storage.read().await?, stored, "{read:?}/{id_first}");
    Ok(())
}

pub(super) async fn batch_output_reset<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
) -> AuthResult<()> {
    let second = input("second".into(), "second-subject", "second");
    let _ = base.create_account(second.clone()).await?;
    let target = Arc::new(OnceLock::<Weak<dyn AuthStore<S>>>::new());
    let events = Events::default();
    let input_target = target.clone();
    let input_events = events.clone();
    let output_target = target.clone();
    let output_events = events.clone();
    let probe = UserFieldConfig {
        field_name: Some("accessToken".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = input_target.clone();
                let events = input_events.clone();
                async move {
                    event(&events, "probe-input", value.clone())?;
                    if value.as_str() == Some("outer") {
                        let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                            AuthError::internal("Reentrant Account store is unavailable")
                        })?;
                        let rows = store
                            .get_user_accounts("owner")
                            .await?
                            .into_iter()
                            .map(|row| row.internal_fields().map(FieldValue::from))
                            .collect::<AuthResult<Vec<_>>>()?;
                        event(&events, "nested-list", rows.into())?;
                    }
                    Ok(value)
                }
            })),
            output: Some(UserFieldTransform::new_async(move |value| {
                let target = output_target.clone();
                let events = output_events.clone();
                async move {
                    event(&events, "probe-output", value.clone())?;
                    if value.as_str() == Some("retained") {
                        let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                            AuthError::internal("Reentrant Account store is unavailable")
                        })?;
                        event(&events, "missing-started", value.clone())?;
                        let rows = store.get_user_accounts("missing").await?;
                        // Awaiting the JavaScript query yields even when Memory completes immediately.
                        tokio::task::yield_now().await;
                        let rows = rows
                            .into_iter()
                            .map(|row| row.internal_fields().map(FieldValue::from))
                            .collect::<AuthResult<Vec<_>>>()?;
                        event(&events, "nested-missing", rows.into())?;
                    }
                    Ok(value)
                }
            })),
        }),
        ..Default::default()
    };
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.advanced.database.generate_id = Some(generator(&events, false));
    let _ = config
        .account
        .additional_fields
        .insert("probe".into(), probe);
    let _ = config
        .account
        .additional_fields
        .insert("id".into(), id_sentinel());
    let reader = reader(base.as_ref(), config, &events)?;
    target
        .set(Arc::downgrade(&reader))
        .map_err(|_| AuthError::internal("Reentrant Account store was already assigned"))?;
    let mut data = input(FieldValue::Undefined, "subject", "before");
    let _ = data
        .additional_fields
        .insert("probe".into(), "outer".into());
    let result = reader.create_account_optional(data).await;
    let mut raw = super::target(FieldValue::Undefined)?;
    let _ = raw.insert("accessToken".into(), "outer".into());
    let mut projected = raw.clone();
    let _ = projected.insert("id".into(), FieldValue::Undefined);
    let _ = projected.insert("probe".into(), "outer".into());
    assert_created(result, storage.is_memory().then_some(&projected))?;
    let nested = [(retained(), "retained"), (second.clone(), "second")]
        .into_iter()
        .map(|(row, label)| {
            let mut fields = row.fields()?;
            let _ = fields.insert("probe".into(), label.into());
            Ok(FieldValue::from(fields))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let mut expected = vec![
        trace("probe-input", "outer".into()),
        trace("probe-output", "retained".into()),
        trace("missing-started", "retained".into()),
        trace("probe-output", "second".into()),
        trace("nested-missing", Vec::<FieldValue>::new().into()),
        trace("nested-list", nested.into()),
    ];
    let mut stored = vec![
        storage.expected(retained().fields()?)?,
        storage.expected(second.fields()?)?,
    ];
    if storage.is_memory() {
        expected.push(trace("probe-output", "outer".into()));
        expected.push(trace("after-create", projected.into()));
        stored.push(storage.expected(raw)?);
    }
    assert_eq!(observed(&events)?, expected);
    assert_eq!(storage.read().await?, stored);
    Ok(())
}
