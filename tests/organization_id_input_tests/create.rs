use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum Native {
    Absent,
    Undefined,
    Null,
    Seven,
    False,
    Zero,
}

impl Native {
    pub(super) const ALL: [Self; 6] = [
        Self::Absent,
        Self::Undefined,
        Self::Null,
        Self::Seven,
        Self::False,
        Self::Zero,
    ];

    fn value(self) -> Option<FieldValue> {
        match self {
            Self::Absent => None,
            Self::Undefined => Some(FieldValue::Undefined),
            Self::Null => Some(FieldValue::Null),
            Self::Seven => Some(7.into()),
            Self::False => Some(false.into()),
            Self::Zero => Some(0.into()),
        }
    }
}

pub(super) async fn native<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
    entry: Entry,
    native: Native,
) -> AuthResult<()> {
    let model = entry.model();
    let events = Events::default();
    let reader = reader(
        base.as_ref(),
        model,
        generator(&events, false),
        UserConfig::default(),
    )?;
    let started = chrono::Utc::now();
    let result = create_record(
        reader.as_ref(),
        entry,
        native.value(),
        "target",
        FieldMap::new(),
    )
    .await;
    let generated = matches!(native, Native::Absent | Native::Undefined | Native::Null);
    let raw_id = if generated {
        "generated".into()
    } else if matches!(native, Native::Seven) {
        7.into()
    } else {
        FieldValue::Undefined
    };
    let output_id = if matches!(native, Native::Seven) {
        "7".into()
    } else {
        raw_id.clone()
    };
    let succeeds = !raw_id.is_undefined() || storage.is_memory();
    let expected = row(model, output_id, "target");
    assert_created(result, succeeds.then_some(&expected), model)?;
    assert_eq!(
        observed(&events)?,
        if generated {
            vec![trace("generate", model.name().into())]
        } else {
            Vec::new()
        }
    );
    let appended = if succeeds {
        vec![row(model, raw_id, "target")]
    } else {
        Vec::new()
    };
    let _ = storage
        .assert_appended(model, &baseline, &appended, started)
        .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Slot {
    Implicit,
    BeforeAlias,
    AfterAlias,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Generated,
    Supplied,
    GeneratorError,
    FieldError,
}

fn alias(events: &Events, mode: Mode) -> UserFieldConfig {
    let input_events = events.clone();
    let output_events = events.clone();
    UserFieldConfig {
        field_name: Some("id".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                event(&input_events, "alias-input", value)?;
                if mode == Mode::FieldError {
                    return Err(AuthError::type_error("organization-field-input-rejected"));
                }
                Ok("alias".into())
            })),
            output: Some(UserFieldTransform::new(move |value| {
                event(&output_events, "alias-output", value.clone())?;
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

fn declarations(slot: Slot, events: &Events, mode: Mode) -> UserConfig {
    let mut fields = UserConfig::default();
    if slot == Slot::BeforeAlias {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    let _ = fields
        .fields_mut()
        .insert("aliasId".into(), alias(events, mode));
    if slot == Slot::AfterAlias {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    fields
}

pub(super) async fn slot<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
    entry: Entry,
    slot: Slot,
    mode: Mode,
) -> AuthResult<()> {
    let model = entry.model();
    let events = Events::default();
    let reader = reader(
        base.as_ref(),
        model,
        generator(&events, mode == Mode::GeneratorError),
        declarations(slot, &events, mode),
    )?;
    let supplied = (mode == Mode::Supplied).then(|| "supplied".into());
    let extras = [("aliasId".into(), "alias-source".into())].into();
    let started = chrono::Utc::now();
    let result = create_record(reader.as_ref(), entry, supplied, "target", extras).await;
    let mut events_expected = Vec::new();
    for is_id in if slot == Slot::BeforeAlias {
        [true, false]
    } else {
        [false, true]
    } {
        if is_id && mode != Mode::Supplied {
            events_expected.push(trace("generate", model.name().into()));
            if mode == Mode::GeneratorError {
                break;
            }
        } else if !is_id {
            events_expected.push(trace("alias-input", "alias-source".into()));
            if mode == Mode::FieldError {
                break;
            }
        }
    }
    let mut appended = Vec::new();
    if matches!(mode, Mode::GeneratorError | Mode::FieldError) {
        let expected = if mode == Mode::GeneratorError {
            "organization-id-generator-rejected"
        } else {
            "organization-field-input-rejected"
        };
        assert!(
            matches!(&result, Err(AuthError::TypeError(message)) if message == expected),
            "{result:?}"
        );
    } else {
        let id = if slot == Slot::BeforeAlias {
            "alias"
        } else if mode == Mode::Supplied {
            "supplied"
        } else {
            "generated"
        };
        let raw = row(model, id.into(), "target");
        let mut output = raw.clone();
        let _ = output.insert("aliasId".into(), id.into());
        assert_created(result, Some(&output), model)?;
        events_expected.push(trace("alias-output", id.into()));
        appended.push(raw);
    }
    assert_eq!(observed(&events)?, events_expected);
    let _ = storage
        .assert_appended(model, &baseline, &appended, started)
        .await?;
    Ok(())
}

pub(super) async fn serial<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
    model: Model,
    slot: Slot,
) -> AuthResult<()> {
    let events = Events::default();
    let reader = reader(
        base.as_ref(),
        model,
        IdGeneration::Serial,
        declarations(slot, &events, Mode::Supplied),
    )?;
    let started = chrono::Utc::now();
    let result = create_record(
        reader.as_ref(),
        Entry::Create(model),
        Some("00101".into()),
        "target",
        [("aliasId".into(), "alias-source".into())].into(),
    )
    .await;
    let raw_id: FieldValue = if storage.is_memory() {
        2.into()
    } else if slot == Slot::BeforeAlias {
        "alias".into()
    } else {
        "101".into()
    };
    let public_id = if storage.is_memory() {
        "2".into()
    } else {
        raw_id.clone()
    };
    let raw = row(model, raw_id.clone(), "target");
    let mut output = row(model, public_id.clone(), "target");
    let _ = output.insert("aliasId".into(), public_id);
    assert_created(result, Some(&output), model)?;
    assert_eq!(
        observed(&events)?,
        vec![
            trace("alias-input", "alias-source".into()),
            trace("alias-output", raw_id)
        ]
    );
    let _ = storage
        .assert_appended(model, &baseline, &[raw], started)
        .await?;
    Ok(())
}

pub(super) async fn output_error<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    baseline: Vec<FieldMap>,
    id_first: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let output_events = events.clone();
    let mut fields = UserConfig::default();
    if id_first {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    let _ = fields.fields_mut().insert(
        "outputProbe".into(),
        UserFieldConfig {
            field_name: Some("logo".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    event(&output_events, "probe-output", value.clone())?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    if !id_first {
        let _ = fields.fields_mut().insert("id".into(), id_sentinel());
    }
    let model = Model::Organization;
    let reader = reader(base.as_ref(), model, generator(&events, false), fields)?;
    let id = FieldValue::from(FieldMap::from([
        ("toString".into(), FieldValue::Null),
        ("valueOf".into(), FieldValue::Null),
    ]));
    let started = chrono::Utc::now();
    let result = create_record(
        reader.as_ref(),
        Entry::Insert(model),
        Some(id.clone()),
        "target",
        [("outputProbe".into(), "probe-source".into())].into(),
    )
    .await;
    assert!(
        matches!(&result, Err(AuthError::TypeError(message)) if message == "No default value"),
        "{result:?}"
    );
    assert_eq!(
        observed(&events)?,
        if id_first {
            Vec::new()
        } else {
            vec![trace("probe-output", "probe-source".into())]
        }
    );
    let mut raw = row(model, id, "target");
    let _ = raw.insert("logo".into(), "probe-source".into());
    let _ = storage
        .assert_appended(model, &baseline, &[raw], started)
        .await?;
    Ok(())
}
