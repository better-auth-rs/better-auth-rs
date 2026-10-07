use super::*;
use crate::store::database_hooks::{DatabaseHookContext, SessionUpdate};

fn input(label: Option<&str>) -> AuthResult<CreateSession> {
    Ok(CreateSession {
        user_id: "owner".into(),
        expires_at: date(EXPIRES_AT)?,
        ip_address: Some(String::new()),
        user_agent: Some(String::new()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: label
            .map(|label| [("label".into(), Value::from(label))].into())
            .unwrap_or_default(),
    })
}

struct ForcedId {
    value: Value,
    trace: Events,
    fail: bool,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for ForcedId {
    async fn before_create_session(
        &self,
        input: &mut crate::FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<crate::store::database_hooks::DatabaseHookUpdate<crate::FieldMap>> {
        record(&self.trace, json!(["hook", input.contains_key("id")]))?;
        let _ = input.insert("id".into(), self.value.clone());
        if self.fail {
            return Err(AuthError::bad_request("nested hook failure"));
        }
        Ok(crate::store::database_hooks::DatabaseHookUpdate::Continue)
    }
}

#[tokio::test]
async fn memory_session_create_hooks_resolve_supplied_ids_before_generation() -> AuthResult<()> {
    for (supplied, expected, generated) in [
        (Value::from("hook-id"), Value::from("hook-id"), false),
        (Value::Undefined, Value::from("generated-id"), true),
        (Value::Null, Value::from("generated-id"), true),
        (Value::Bool(false), Value::Undefined, false),
        (Value::Number(0.0), Value::Undefined, false),
        (Value::from(""), Value::Undefined, false),
    ] {
        let trace = Events::default();
        let generator_trace = trace.clone();
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                record(&generator_trace, json!(["generate", request.model]))?;
                Ok(Some("generated-id".into()))
            })));
        let store = EphemeralStore::new(Arc::new(config)).with_hooks(vec![Arc::new(ForcedId {
            value: supplied,
            trace: trace.clone(),
            fail: false,
        })]);
        let mut create = input(None)?;
        let _ = create
            .additional_fields
            .insert("id".into(), "request-id".into());
        let created = store.create_session(create).await?;
        assert_eq!(created.id.field_value(), expected);
        assert!(created.additional_fields.is_empty());
        assert_eq!(store.lock()?.sessions.snapshot()?, [created.clone()]);
        assert_eq!(required(store.get_session(&created.token).await?)?, created);
        let mut expected_events = vec![json!(["hook", false])];
        if generated {
            expected_events.push(json!(["generate", "session"]));
        }
        assert_eq!(events(&trace)?, expected_events);
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_create_aliases_share_the_physical_id_slot() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-id-slot-1.7.6.json"
    )))?;
    let cases = required(fixture["cases"].as_array())?;
    for serial in [false, true] {
        for id_first in [false, true] {
            let slot = if id_first {
                "before-alias"
            } else {
                "after-alias"
            };
            let trace = Events::default();
            let generator_trace = trace.clone();
            let target = Target::default();
            let generator_target = target.clone();
            let input_trace = trace.clone();
            let output_trace = trace.clone();
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id = Some(if serial {
                IdGeneration::Serial
            } else {
                IdGeneration::Custom(IdGenerator::new(move |request| {
                    let store = required(generator_target.get().and_then(Weak::upgrade))?;
                    record(
                        &generator_trace,
                        json!(["generateId", {"model":request.model}, "G", memory(&store, "after-label")?]),
                    )?;
                    Ok(Some("G".into()))
                }))
            });
            let alias = UserFieldConfig {
                field_name: Some("id".into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        record(&input_trace, json!(["input", "aliasId", value.json()?]))?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        record(&output_trace, json!(["output", "aliasId", value.json()?]))?;
                        Ok(value)
                    })),
                }),
                ..Default::default()
            };
            config.session.additional_fields = Some(
                if id_first {
                    [("id".into(), id_policy()), ("aliasId".into(), alias)]
                } else {
                    [("aliasId".into(), alias), ("id".into(), id_policy())]
                }
                .into(),
            );
            let store = Arc::new(EphemeralStore::new(Arc::new(config)));
            target
                .set(Arc::downgrade(&store))
                .map_err(|_| AuthError::internal("Session alias target already set"))?;
            let before = memory(&store, "after-label")?;
            let mut create = input(None)?;
            create.user_id = if serial { "001" } else { "owner" }.into();
            let _ = create
                .additional_fields
                .insert("aliasId".into(), "A".into());
            let started = Utc::now().timestamp_millis() as f64;
            let created = store.create_session(create).await?;
            let ended = Utc::now().timestamp_millis() as f64;
            assert!((started..=ended).contains(&created.created_at.milliseconds()));
            assert!((started..=ended).contains(&created.updated_at.milliseconds()));
            assert_eq!(created.token.len(), 32);
            assert!(
                created
                    .token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric())
            );
            let public_id = if serial {
                "1"
            } else if id_first {
                "A"
            } else {
                "G"
            };
            let raw_id = if serial {
                Value::Number(1.0)
            } else {
                public_id.into()
            };
            assert_eq!(created.id, public_id);
            assert_eq!(
                created.additional_fields,
                [("aliasId".into(), public_id.into())].into()
            );
            let mut stored = created.clone();
            stored.id = crate::SchemaValue::from_field(raw_id.clone());
            stored.additional_fields.clear();
            if serial {
                stored.user_id = crate::SchemaValue::from_field(Value::Number(1.0));
            }
            assert_eq!(store.lock()?.sessions.snapshot()?, [stored.clone()]);
            // The Store owns token and clock fields; normalize only those generated values for the adapter observation.
            let normalize = |mut row: SessionView| -> AuthResult<SessionView> {
                row.token = "slot-alias".into();
                row.created_at = date(CREATED_AT)?;
                row.updated_at = date(CREATED_AT)?;
                Ok(row)
            };
            let result = observe(normalize(created.clone())?.into(), false)?;
            let mut after = before.clone();
            after["session"] = json!([observe(normalize(stored)?.into(), true)?]);
            let request = json!({"model":"session", "data":{
                "token":"slot-alias", "userId":if serial { "001" } else { "owner" },
                "expiresAt":{"type":"date","value":EXPIRES_AT},
                "createdAt":{"type":"date","value":CREATED_AT},
                "updatedAt":{"type":"date","value":CREATED_AT},
                "ipAddress":"", "userAgent":"", "aliasId":"A"
            }});
            let actual = json!({
                "model":"session", "slot":slot, "operation":"create-id-alias",
                "idGeneration":if serial { "serial" } else { "custom" },
                "setup":[], "seedEvents":[], "before":before, "input":request,
                "events":events(&trace)?, "result":result, "error":null, "after":after,
            });
            let expected = required(cases.iter().find(|case| {
                case["model"] == "session"
                    && case["slot"] == slot
                    && case["operation"] == "create-id-alias"
                    && case["idGeneration"] == if serial { "serial" } else { "custom" }
            }))?;
            assert_eq!(actual, *expected, "{slot}, serial={serial}");
            assert_eq!(required(store.get_session(&created.token).await?)?, created);
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_failed_nested_create_retains_its_forced_uuid_policy() -> AuthResult<()> {
    for hook_failure in [false, true] {
        for id_first in [false, true] {
            let trace = Events::default();
            let callback_trace = trace.clone();
            let target = Target::default();
            let callback_target = target.clone();
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id = Some(IdGeneration::Uuid);
            let label = UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new_async(move |value| {
                        let target = callback_target.clone();
                        let trace = callback_trace.clone();
                        async move {
                            record(&trace, json!(["input", value.json()?]))?;
                            if value.as_str() == Some("inner") {
                                return Err(AuthError::bad_request("nested field failure"));
                            }
                            let store = required(target.get().and_then(Weak::upgrade))?;
                            let error = store
                                .create_session(input(Some("inner"))?)
                                .await
                                .err()
                                .ok_or_else(|| {
                                    AuthError::internal("Nested create unexpectedly succeeded")
                                })?;
                            record(&trace, json!(["failed", error.to_string()]))?;
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            };
            config.session.additional_fields = Some(
                if id_first {
                    [("id".into(), id_policy()), ("label".into(), label)]
                } else {
                    [("label".into(), label), ("id".into(), id_policy())]
                }
                .into(),
            );
            let store = Arc::new(
                EphemeralStore::new(Arc::new(config)).with_hooks(vec![Arc::new(ForcedId {
                    value: "nested-invalid".into(),
                    trace: trace.clone(),
                    fail: hook_failure,
                })]),
            );
            target
                .set(Arc::downgrade(&store))
                .map_err(|_| AuthError::internal("Session target already set"))?;
            let mut stored = super::session_updates::seed()?;
            stored.id = "7".into();
            stored.user_id = "owner".into();
            store.lock()?.sessions.push(stored.clone());
            let changed_at = date("2031-01-02T03:04:05.000Z")?;
            let updated = required(
                store
                    .update_session_with_writer(
                        &stored.token,
                        SessionUpdate {
                            id: Some("outer-invalid".into()),
                            updated_at: Some(changed_at.clone()),
                            additional_fields: [("label".into(), "outer".into())].into(),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?,
            )?;
            stored.id = if id_first || hook_failure {
                "outer-invalid"
            } else {
                "7"
            }
            .into();
            stored.updated_at = changed_at;
            stored.additional_fields = [("label".into(), "outer".into())].into();
            assert_eq!(updated, stored);
            assert_eq!(store.lock()?.sessions.snapshot()?, [stored]);
            let mut expected = vec![json!(["input", "outer"]), json!(["hook", false])];
            if !hook_failure {
                expected.push(json!(["input", "inner"]));
            }
            expected.push(json!([
                "failed",
                AuthError::bad_request(if hook_failure {
                    "nested hook failure"
                } else {
                    "nested field failure"
                })
                .to_string()
            ]));
            assert_eq!(events(&trace)?, expected);
        }
    }
    Ok(())
}
