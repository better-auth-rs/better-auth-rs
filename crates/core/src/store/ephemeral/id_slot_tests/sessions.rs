use super::*;
use crate::store::database_hooks::SessionUpdate;

fn input(label: &str) -> AuthResult<CreateSession> {
    Ok(CreateSession {
        inherited_fields: Default::default(),
        user_id: "ordinary-owner".into(),
        expires_at: date(EXPIRES_AT)?,
        ip_address: Some("198.51.100.4".into()),
        user_agent: Some("id-slot-test".into()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: [("label".into(), label.into())].into(),
    })
}

fn expected_session(
    observed: &SessionView,
    id: Option<&str>,
    label: &str,
) -> AuthResult<SessionView> {
    assert_eq!(observed.token.typed().unwrap().len(), 32);
    assert!(
        observed
            .token
            .typed()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    Ok(SessionView {
        field_order: [
            "expiresAt",
            "token",
            "createdAt",
            "updatedAt",
            "ipAddress",
            "userAgent",
            "userId",
            "label",
            "id",
        ]
        .map(str::to_owned)
        .into(),
        visible_fields: Some(Default::default()),
        id: id
            .map(str::to_owned)
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default(),
        expires_at: date(EXPIRES_AT)?.into(),
        token: observed.token.clone(),
        created_at: observed.created_at.clone(),
        updated_at: observed.updated_at.clone(),
        ip_address: Some("198.51.100.4".into()).into(),
        user_agent: Some("id-slot-test".into()).into(),
        user_id: "ordinary-owner".into(),
        impersonated_by: crate::SchemaValue::Undefined,
        active_organization_id: crate::SchemaValue::Undefined,
        active_team_id: crate::SchemaValue::Undefined,
        active: true,
        additional_fields: [("label".into(), label.into())].into(),
    })
}

#[tokio::test]
async fn memory_session_id_slot_nested_create_preserves_complete_runtime_records() -> AuthResult<()>
{
    for slot in ["before-label", "after-label"] {
        let trace = Events::default();
        let target = Target::default();
        let inner_result = Arc::new(OnceLock::<SessionView>::new());
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(generator(&trace, &target, slot));
        let input_trace = trace.clone();
        let output_trace = trace.clone();
        let input_target = target.clone();
        let input_inner = inner_result.clone();
        install_fields(
            config.session.fields_mut(),
            slot,
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new_async(move |value| {
                        let trace = input_trace.clone();
                        let target = input_target.clone();
                        let inner = input_inner.clone();
                        async move {
                            record(&trace, json!(["input", "label", required(value.json()?)?]))?;
                            if value.as_str() == Some("outer") {
                                let store = required(target.get().and_then(Weak::upgrade))?;
                                record(&trace, json!(["nested-create", memory(&store, slot)?]))?;
                                let created = store.create_session(input("inner")?).await?;
                                record(
                                    &trace,
                                    json!([
                                        "nested-created",
                                        observe(session_fields(&created, slot), false)?,
                                        memory(&store, slot)?
                                    ]),
                                )?;
                                inner.set(created).map_err(|_| {
                                    AuthError::internal("Nested Session already created")
                                })?;
                            }
                            Ok(value)
                        }
                    })),
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let trace = output_trace.clone();
                        async move {
                            record(&trace, json!(["output", "label", required(value.json()?)?]))?;
                            Ok(value)
                        }
                    })),
                }),
                ..Default::default()
            },
        );
        let store = Arc::new(EphemeralStore::new(Arc::new(config)));
        target
            .set(Arc::downgrade(&store))
            .map_err(|_| AuthError::internal("Session target already set"))?;
        let before = memory(&store, slot)?;
        let started = Utc::now().timestamp_millis() as f64;
        let outer = store.create_session(input("outer")?).await?;
        let inner = required(inner_result.get())?;
        let ended = Utc::now().timestamp_millis() as f64;
        // Session creation reads the clock separately for createdAt and updatedAt.
        assert!((started..=ended).contains(&outer.created_at.date_milliseconds().unwrap()));
        assert!((started..=ended).contains(&inner.created_at.date_milliseconds().unwrap()));
        assert!((started..=ended).contains(&outer.updated_at.date_milliseconds().unwrap()));
        assert!((started..=ended).contains(&inner.updated_at.date_milliseconds().unwrap()));
        assert_ne!(outer.token, inner.token);
        let inner_id = if slot == "before-label" {
            "session-generated-2"
        } else {
            "session-generated-1"
        };
        let expected_inner = expected_session(inner, Some(inner_id), "inner")?;
        let expected_outer = expected_session(
            &outer,
            (slot == "before-label").then_some("session-generated-1"),
            "outer",
        )?;
        assert_eq!(*inner, expected_inner);
        assert_eq!(outer, expected_outer);
        let mut raw_outer: FieldMap = expected_outer.clone().into();
        if expected_outer.id.is_undefined() {
            let _ = raw_outer.remove("id");
        }
        assert_eq!(
            store.lock()?.sessions.snapshot()?,
            vec![FieldMap::from(expected_inner.clone()), raw_outer]
        );
        let mut inner_memory = before.clone();
        inner_memory["session"] = json!([observe(session_fields(&expected_inner, slot), true)?]);
        let generate = |id| json!(["generateId", {"model":"session"}, id, before]);
        let mut expected = Vec::new();
        if slot == "before-label" {
            expected.push(generate("session-generated-1"));
        }
        expected.extend([
            json!(["input", "label", "outer"]),
            json!(["nested-create", before]),
        ]);
        if slot == "before-label" {
            expected.push(generate(inner_id));
        }
        expected.push(json!(["input", "label", "inner"]));
        if slot == "after-label" {
            expected.push(generate(inner_id));
        }
        expected.extend([
            json!(["output", "label", "inner"]),
            json!([
                "nested-created",
                observe(session_fields(&expected_inner, slot), false)?,
                inner_memory
            ]),
            json!(["output", "label", "outer"]),
        ]);
        assert_eq!(events(&trace)?, expected, "Session ID slot {slot}");
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_id_slot_live_writer_preserves_read_and_stored_records() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    let cases = required(fixture["cases"].as_array())?;
    for slot in ["before-label", "after-label"] {
        let expected = required(cases.iter().find(|case| {
            case["model"] == "session"
                && case["slot"] == slot
                && case["operation"] == "live-output-id-write"
        }))?;
        let changed_at = "2031-01-02T03:04:05.000Z";
        let updated_at = date(changed_at)?;
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let _ = config
            .session
            .fields_mut()
            .insert("id".into(), UserFieldConfig::default());
        let _ = config
            .session
            .fields_mut()
            .insert("label".into(), UserFieldConfig::default());
        let writer = Arc::new(EphemeralStore::new(Arc::new(config)));
        let mut owner = user_input("owner")?;
        owner.additional_fields.clear();
        let _ = writer.create_user(owner).await?;
        writer.lock()?.sessions.push(
            SessionView {
                field_order: Default::default(),
                visible_fields: Some(Default::default()),
                id: crate::SchemaValue::from_field(Value::Number(1.0)),
                expires_at: date(EXPIRES_AT)?.into(),
                token: "slot-selected".into(),
                created_at: date(CREATED_AT)?.into(),
                updated_at: date(CREATED_AT)?.into(),
                ip_address: None.into(),
                user_agent: None.into(),
                user_id: crate::SchemaValue::from_field(Value::Number(1.0)),
                impersonated_by: None.into(),
                active_organization_id: None.into(),
                active_team_id: None.into(),
                active: true,
                additional_fields: [("label".into(), "selected".into())].into(),
            }
            .into(),
        );
        let trace = Events::default();
        let output_trace = trace.clone();
        let output_writer = writer.clone();
        let mut config = (*writer.config).clone();
        config.session.additional_fields = None;
        install_fields(
            config.session.fields_mut(),
            slot,
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let trace = output_trace.clone();
                        let writer = output_writer.clone();
                        let updated_at = updated_at.clone();
                        async move {
                            record(&trace, json!(["output", "label", required(value.json()?)?]))?;
                            let request = json!({"token":"slot-selected", "update":{"id":"00101", "updatedAt":{"type":"date", "value":changed_at}}});
                            record(
                                &trace,
                                json!(["writer-update", request, memory(&writer, slot)?]),
                            )?;
                            let updated = required(
                                writer
                                    .update_session_with_writer(
                                        "slot-selected",
                                        SessionUpdate {
                                            id: Some("00101".into()),
                                            updated_at: Some(updated_at),
                                            ..Default::default()
                                        },
                                        None,
                                    )
                                    .await?,
                            )?;
                            record(
                                &trace,
                                json!([
                                    "writer-updated",
                                    observe(session_fields(&updated, "before-label"), false)?,
                                    memory(&writer, slot)?
                                ]),
                            )?;
                            Ok(format!("{}:out", required(value.as_str())?).into())
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let mut reader = EphemeralStore::new(Arc::new(config));
        reader.state = writer.state.clone();
        let before = memory(&writer, slot)?;
        assert_eq!(before, expected["before"]);
        let selected = required(reader.get_session("slot-selected").await?)?;
        assert_eq!(
            observe(session_fields(&selected, slot), false)?,
            expected["result"]
        );
        let mut after = before.clone();
        after["session"][0]["id"] = json!(101);
        after["session"][0]["updatedAt"] = json!({"type":"date", "value":changed_at});
        let mut updated = after["session"][0].clone();
        updated["id"] = json!("101");
        updated["userId"] = json!("1");
        assert_eq!(
            json!(events(&trace)?),
            json!([
                ["output", "label", "selected"],
                ["writer-update", {"token":"slot-selected", "update":{"id":"00101", "updatedAt":{"type":"date", "value":changed_at}}}, before],
                ["writer-updated", updated, after],
            ])
        );
        assert_eq!(memory(&writer, slot)?, after);
    }
    Ok(())
}
