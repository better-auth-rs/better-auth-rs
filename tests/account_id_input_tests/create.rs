use super::*;

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
                    return Err(AuthError::type_error("account-field-input-rejected"));
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

pub(super) async fn slot<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    slot: Slot,
    mode: Mode,
) -> AuthResult<()> {
    let events = Events::default();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(generator(&events, mode == Mode::GeneratorError));
    if slot == Slot::BeforeAlias {
        let _ = config
            .account
            .additional_fields
            .insert("id".into(), id_sentinel());
    }
    let _ = config
        .account
        .additional_fields
        .insert("aliasId".into(), alias(&events, mode));
    if slot == Slot::AfterAlias {
        let _ = config
            .account
            .additional_fields
            .insert("id".into(), id_sentinel());
    }
    let reader = reader(base.as_ref(), config, &events)?;
    let supplied = if mode == Mode::Supplied {
        "supplied".into()
    } else {
        FieldValue::Undefined
    };
    let mut data = input(supplied, "subject", "before");
    let _ = data
        .additional_fields
        .insert("aliasId".into(), "alias-source".into());
    let result = reader.create_account_optional(data).await;
    let mut trace_events = Vec::new();
    let mut stored = vec![storage.expected(retained().fields()?)?];
    for is_id in if slot == Slot::BeforeAlias {
        [true, false]
    } else {
        [false, true]
    } {
        if is_id && mode != Mode::Supplied {
            trace_events.push(trace("generate", "account".into()));
            if mode == Mode::GeneratorError {
                break;
            }
        } else if !is_id {
            trace_events.push(trace("alias-input", "alias-source".into()));
            if mode == Mode::FieldError {
                break;
            }
        }
    }
    if matches!(mode, Mode::GeneratorError | Mode::FieldError) {
        let message = if mode == Mode::GeneratorError {
            "account-id-generator-rejected"
        } else {
            "account-field-input-rejected"
        };
        assert!(
            matches!(&result, Err(AuthError::TypeError(actual)) if actual == message),
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
        let raw = target(id.into())?;
        let mut projected = raw.clone();
        let _ = projected.insert("aliasId".into(), id.into());
        assert_created(result, Some(&projected))?;
        trace_events.push(trace("alias-output", id.into()));
        trace_events.push(trace("after-create", projected.into()));
        stored.push(storage.expected(raw)?);
    }
    assert_eq!(observed(&events)?, trace_events, "{slot:?}/{mode:?}");
    assert_eq!(storage.read().await?, stored, "{slot:?}/{mode:?}");
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Native {
    Seven,
    False,
    Zero,
}

pub(super) async fn native<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    native: Native,
) -> AuthResult<()> {
    let value = match native {
        Native::Seven => FieldValue::Number(7.0),
        Native::False => FieldValue::Bool(false),
        Native::Zero => FieldValue::Number(0.0),
    };
    let events = Events::default();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(generator(&events, false));
    let reader = reader(base.as_ref(), config, &events)?;
    let result = reader
        .create_account_optional(input(value.clone(), "subject", "before"))
        .await;
    let truthy = matches!(native, Native::Seven);
    let succeeds = truthy || storage.is_memory();
    let mut projected = target(if truthy {
        "7".into()
    } else {
        FieldValue::Undefined
    })?;
    if !truthy {
        let _ = projected.insert("id".into(), FieldValue::Undefined);
    }
    assert_created(result, succeeds.then_some(&projected))?;
    let mut stored = vec![storage.expected(retained().fields()?)?];
    if succeeds {
        stored.push(storage.expected(target(if truthy {
            value
        } else {
            FieldValue::Undefined
        })?)?);
    }
    assert_eq!(storage.read().await?, stored, "{native:?}");
    assert_eq!(
        observed(&events)?,
        if succeeds {
            vec![trace("after-create", projected.into())]
        } else {
            Vec::new()
        },
        "{native:?}"
    );
    Ok(())
}
