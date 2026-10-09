use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Id {
    False,
    Zero,
    Empty,
    Serial,
}

pub(super) async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    id: Id,
    many: bool,
) -> AuthResult<()> {
    let serial = id == Id::Serial;
    let initial = if serial {
        FieldValue::Number(1.0)
    } else {
        "target".into()
    };
    let _ = base
        .create_account(input(initial, "subject", "before"))
        .await?;
    let events = Events::default();
    let mut config = AuthConfig::default();
    if serial {
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
    }
    let input_events = events.clone();
    let output_events = events.clone();
    let _ = config.account.additional_fields.insert(
        "accessToken".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    event(&input_events, "token-input", value.clone())?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    event(&output_events, "token-output", value.clone())?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let mut id_field = id_sentinel();
    id_field.field_name = None;
    let _ = config
        .account
        .additional_fields
        .insert("id".into(), id_field);
    let reader = reader(base.as_ref(), config, &events)?;
    let replacement = match id {
        Id::False => FieldValue::Bool(false),
        Id::Zero => FieldValue::Number(0.0),
        Id::Empty => "".into(),
        Id::Serial => "00101".into(),
    };
    let patch = UpdateAccount {
        id: SchemaValue::from_field(replacement),
        access_token: Some("after".into()).into(),
        updated_at: date(1).into(),
        ..Default::default()
    };
    let query = FieldValue::from(if serial { "001" } else { "target" });
    let mut projected = target(if serial {
        "101".into()
    } else {
        "target".into()
    })?;
    let _ = projected.insert("accessToken".into(), "after".into());
    let _ = projected.insert("updatedAt".into(), date(1).into());
    let mut trace_events = vec![trace("token-input", "after".into())];
    if many {
        let count = reader
            .update_accounts(&[("id".into(), query)].into(), patch)
            .await?;
        assert_eq!(count, Some(1));
        trace_events.push(trace("after-update", FieldValue::Number(1.0)));
    } else {
        let actual = reader
            .update_account_by_id_value(&query, patch)
            .await?
            .ok_or_else(|| AuthError::internal("Expected updated Account"))?;
        assert_eq!(actual.internal_fields()?, projected);
        trace_events.push(trace("token-output", "after".into()));
        trace_events.push(trace("after-update", projected.clone().into()));
    }
    let mut raw = projected;
    if serial {
        let _ = raw.insert("id".into(), FieldValue::Number(101.0));
    }
    assert_eq!(observed(&events)?, trace_events, "{id:?}/{many}");
    assert_eq!(
        storage.read().await?,
        [
            storage.expected(retained().fields()?)?,
            storage.expected(raw)?
        ],
        "{id:?}/{many}"
    );
    Ok(())
}
