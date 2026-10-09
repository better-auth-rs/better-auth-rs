use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Found,
    Missing,
    Count,
    Nested,
}

impl Kind {
    pub(super) fn model(self) -> Model {
        if self == Self::Count {
            Model::Role
        } else {
            Model::Organization
        }
    }

    fn clears_input(self) -> bool {
        matches!(self, Self::Found | Self::Nested)
    }
}

pub(super) async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
    kind: Kind,
    id_first: bool,
) -> AuthResult<()> {
    let model = kind.model();
    let target = Arc::new(OnceLock::<Weak<dyn AuthStore<S>>>::new());
    let callback_target = target.clone();
    let events = Events::default();
    let callback_events = events.clone();
    let probe = UserFieldConfig {
        field_name: Some(if model == Model::Role { "role" } else { "name" }.into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = callback_target.clone();
                let events = callback_events.clone();
                async move {
                    event(&events, "probe-input", value.clone())?;
                    if value.as_str() != Some("outer") {
                        return Ok(value);
                    }
                    let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                        AuthError::internal("Reentrant Organization store is unavailable")
                    })?;
                    match kind {
                        Kind::Found | Kind::Missing => {
                            let result = if kind == Kind::Found {
                                store.get_organization_by_id("retained").await?
                            } else {
                                store.get_organization_by_slug("missing").await?
                            };
                            let value = result
                                .map(|row| row.field_values())
                                .transpose()?
                                .map_or(FieldValue::Null, Into::into);
                            event(&events, "nested-read", value)?;
                        }
                        Kind::Count => {
                            let count = store.count_organization_roles("parent").await?;
                            assert_eq!(count, 1);
                            event(&events, "nested-count", 1.into())?;
                        }
                        Kind::Nested => {
                            let nested = create_record(
                                store.as_ref(),
                                Entry::Create(model),
                                Some("nested".into()),
                                "nested",
                                [("probe".into(), "inner".into())].into(),
                            )
                            .await?;
                            event(&events, "nested-create", nested.into())?;
                        }
                    }
                    Ok(value)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut fields = UserConfig::default();
    if id_first {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    let _ = fields.fields_mut().insert("probe".into(), probe);
    if !id_first {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    let policy = if kind.clears_input() {
        generator(&events, false)
    } else {
        IdGeneration::Uuid
    };
    let reader = reader(base.as_ref(), model, policy, fields)?;
    target
        .set(Arc::downgrade(&reader))
        .map_err(|_| AuthError::internal("Reentrant Organization store was already assigned"))?;
    let supplied = (!kind.clears_input()).then(|| "not-a-uuid".into());
    let started = chrono::Utc::now();
    let result = create_record(
        reader.as_ref(),
        Entry::Create(model),
        supplied,
        "target",
        [("probe".into(), "outer".into())].into(),
    )
    .await;
    let has_id = if kind.clears_input() {
        id_first
    } else {
        !id_first
    };
    let id = if has_id {
        if kind.clears_input() {
            "generated".into()
        } else {
            "not-a-uuid".into()
        }
    } else {
        FieldValue::Undefined
    };
    let succeeds = has_id || storage.is_memory();
    let mut output = row(model, id.clone(), "target");
    let alias = if model == Model::Role { "role" } else { "name" };
    let _ = output.insert(alias.into(), "outer".into());
    let _ = output.insert("probe".into(), "outer".into());
    assert_created(result, succeeds.then_some(&output), model)?;
    let mut expected_events = Vec::new();
    if kind.clears_input() && id_first {
        expected_events.push(trace("generate", model.name().into()));
    }
    expected_events.push(trace("probe-input", "outer".into()));
    let mut appended = Vec::new();
    match kind {
        Kind::Found => {
            let mut nested = row(model, "retained".into(), "retained");
            let _ = nested.insert("probe".into(), "retained".into());
            expected_events.push(trace("nested-read", nested.into()));
        }
        Kind::Missing => expected_events.push(trace("nested-read", FieldValue::Null)),
        Kind::Count => expected_events.push(trace("nested-count", 1.into())),
        Kind::Nested => {
            expected_events.push(trace("probe-input", "inner".into()));
            let mut nested = row(model, "nested".into(), "nested");
            let _ = nested.insert("name".into(), "inner".into());
            appended.push(nested.clone());
            let _ = nested.insert("probe".into(), "inner".into());
            expected_events.push(trace("nested-create", nested.into()));
        }
    }
    if succeeds {
        let mut raw = row(model, id, "target");
        let _ = raw.insert(alias.into(), "outer".into());
        appended.push(raw);
    }
    assert_eq!(observed(&events)?, expected_events);
    let _ = storage
        .assert_appended(model, &baseline, &appended, started)
        .await?;
    Ok(())
}

pub(super) async fn batch_output_reset<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
) -> AuthResult<()> {
    let model = Model::Organization;
    let started = chrono::Utc::now();
    let second = create_record(
        base.as_ref(),
        Entry::Create(model),
        Some("second".into()),
        "second",
        FieldMap::new(),
    )
    .await?;
    assert_eq!(second, row(model, "second".into(), "second"));
    let baseline = storage
        .assert_appended(model, &baseline, &[second], started)
        .await?;
    let target = Arc::new(OnceLock::<Weak<dyn AuthStore<S>>>::new());
    let events = Events::default();
    let input_target = target.clone();
    let input_events = events.clone();
    let output_target = target.clone();
    let output_events = events.clone();
    let probe = UserFieldConfig {
        field_name: Some("name".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = input_target.clone();
                let events = input_events.clone();
                async move {
                    event(&events, "probe-input", value.clone())?;
                    if value.as_str() == Some("outer") {
                        let store = target.get().and_then(Weak::upgrade).ok_or_else(|| {
                            AuthError::internal("Reentrant Organization store is unavailable")
                        })?;
                        let rows = store
                            .list_organizations_by_ids(&["retained".into(), "second".into()])
                            .await?
                            .into_iter()
                            .map(|row| row.field_values().map(FieldValue::from))
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
                            AuthError::internal("Reentrant Organization store is unavailable")
                        })?;
                        event(&events, "missing-started", value.clone())?;
                        let result = store.get_organization_by_slug("missing").await?;
                        // Awaiting the JavaScript query yields even when Memory completes immediately.
                        tokio::task::yield_now().await;
                        let result = result
                            .map(|row| row.field_values())
                            .transpose()?
                            .map_or(FieldValue::Null, FieldValue::from);
                        event(&events, "nested-missing", result)?;
                    }
                    Ok(value)
                }
            })),
        }),
        ..Default::default()
    };
    let fields = UserConfig {
        additional_fields: Some([("probe".into(), probe), ("id".into(), id_sentinel())].into()),
    };
    let reader = reader(base.as_ref(), model, generator(&events, false), fields)?;
    target
        .set(Arc::downgrade(&reader))
        .map_err(|_| AuthError::internal("Reentrant Organization store was already assigned"))?;
    let started = chrono::Utc::now();
    let result = create_record(
        reader.as_ref(),
        Entry::Create(model),
        None,
        "target",
        [("probe".into(), "outer".into())].into(),
    )
    .await;
    let mut raw = row(model, FieldValue::Undefined, "target");
    let _ = raw.insert("name".into(), "outer".into());
    let mut output = raw.clone();
    let _ = output.insert("probe".into(), "outer".into());
    assert_created(result, storage.is_memory().then_some(&output), model)?;
    let nested = ["retained", "second"]
        .into_iter()
        .map(|label| {
            let mut row = row(model, label.into(), label);
            let _ = row.insert("probe".into(), label.into());
            FieldValue::from(row)
        })
        .collect::<Vec<_>>();
    let mut expected = vec![
        trace("probe-input", "outer".into()),
        trace("probe-output", "retained".into()),
        trace("missing-started", "retained".into()),
        trace("probe-output", "second".into()),
        trace("nested-missing", FieldValue::Null),
        trace("nested-list", nested.into()),
    ];
    if storage.is_memory() {
        expected.push(trace("probe-output", "outer".into()));
    }
    assert_eq!(observed(&events)?, expected);
    let appended = if storage.is_memory() {
        vec![raw]
    } else {
        Vec::new()
    };
    let _ = storage
        .assert_appended(model, &baseline, &appended, started)
        .await?;
    Ok(())
}
