use super::*;

async fn create_alias(slot: &'static str, serial: bool) -> AuthResult<JsonValue> {
    let trace = Events::default();
    let target = Target::default();
    let mut config = AuthConfig::default();
    let storage_slot = if slot == "before-alias" {
        "before-label"
    } else {
        "after-label"
    };
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        let trace = trace.clone();
        let target = target.clone();
        IdGeneration::Custom(IdGenerator::new(move |request| {
            let store = required(target.get().and_then(Weak::upgrade))?;
            record(
                &trace,
                json!(["generateId", {"model":request.model}, "G", memory(&store, storage_slot)?]),
            )?;
            Ok(Some("G".into()))
        }))
    });
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let alias = UserFieldConfig {
        field_name: Some("id".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(
                    &input_trace,
                    json!(["input", "aliasId", required(value.json()?)?]),
                )?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(
                    &output_trace,
                    json!(["output", "aliasId", required(value.json()?)?]),
                )?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    config.user.additional_fields = Some(
        if slot == "before-alias" {
            [("id".into(), id_policy()), ("aliasId".into(), alias)]
        } else {
            [("aliasId".into(), alias), ("id".into(), id_policy())]
        }
        .into(),
    );
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    target
        .set(Arc::downgrade(&store))
        .map_err(|_| AuthError::internal("User alias target already set"))?;
    let before = memory(&store, storage_slot)?;
    let mut input = user_input("alias")?;
    input.additional_fields = [("aliasId".into(), "A".into())].into();
    let mut request = user_request("alias");
    let request_fields = required(request["data"].as_object_mut())?;
    let _ = request_fields.remove("label");
    let _ = request_fields.insert("aliasId".into(), json!("A"));
    let user = store.create_user(input).await?;
    let stored = store.lock()?.users.snapshot()?;
    assert_eq!(stored.len(), 1);
    assert!(required(stored.first())?.additional_fields.is_empty());
    Ok(json!({
        "model":"user", "slot":slot, "operation":"create-id-alias",
        "idGeneration":if serial { "serial" } else { "custom" },
        "setup":[], "seedEvents":[], "before":before, "input":request,
        "events":events(&trace)?, "result":observe(user_fields(&user, storage_slot)?, false)?,
        "error":null, "after":memory(&store, storage_slot)?,
    }))
}

#[tokio::test]
async fn memory_user_create_id_aliases_match_complete_upstream_observations() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    let cases = required(fixture["cases"].as_array())?;
    for slot in ["before-alias", "after-alias"] {
        for serial in [false, true] {
            let expected = required(cases.iter().find(|case| {
                case["model"] == "user"
                    && case["slot"] == slot
                    && case["operation"] == "create-id-alias"
                    && case["idGeneration"] == if serial { "serial" } else { "custom" }
            }))?;
            assert_eq!(
                create_alias(slot, serial).await?,
                *expected,
                "{slot}, serial={serial}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_user_id_alias_reads_use_the_canonical_id_before_output_conversion() -> AuthResult<()>
{
    for field_type in [
        UserFieldType::String,
        UserFieldType::Json,
        UserFieldType::Date,
    ] {
        for (callback_value, expected) in [
            (Value::from("null"), Value::from("null")),
            (Value::from(7), Value::from("7")),
            (Value::Null, Value::Null),
            (Value::Undefined, Value::Undefined),
        ] {
            let trace = Events::default();
            let output_trace = trace.clone();
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id =
                Some(IdGeneration::Custom(IdGenerator::new(|_| {
                    Ok(Some("null".into()))
                })));
            let _ = config.user.fields_mut().insert(
                "aliasId".into(),
                UserFieldConfig {
                    field_type: field_type.clone(),
                    field_name: Some("id".into()),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            record(&output_trace, required(value.json()?)?)?;
                            Ok(callback_value.clone())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let store = EphemeralStore::new(Arc::new(config));
            let mut input = user_input("alias")?;
            input.additional_fields = [("aliasId".into(), "A".into())].into();
            let created = store.create_user(input).await?;
            assert_eq!(created.id.field_value(), Value::from("null"));
            assert_eq!(
                created.additional_fields,
                [("aliasId".into(), expected)].into()
            );
            let stored = store.lock()?.users.snapshot()?;
            assert_eq!(stored.len(), 1);
            assert!(required(stored.first())?.additional_fields.is_empty());
            assert_eq!(required(store.get_user_by_id("null").await?)?, created);
            assert_eq!(
                required(
                    store
                        .get_user_by_email("alias@adapter-id-slot.test")
                        .await?
                )?,
                created
            );
            assert_eq!(store.output_users(stored.clone()).await?, [created]);
            assert_eq!(store.lock()?.users.snapshot()?, stored);
            assert_eq!(events(&trace)?, vec![json!("null"); 4]);
        }
    }
    Ok(())
}
