#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete records, callback order, and persistence after failures"
)]

use super::*;
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHookControl, VerificationUpdate};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, Weak};

type Events = Arc<Mutex<Vec<JsonValue>>>;

fn event(events: &Events, value: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification output trace lock poisoned"))?
        .push(value);
    Ok(())
}

fn observed(events: &Events) -> AuthResult<Vec<JsonValue>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Verification output trace lock poisoned"))?
        .clone())
}

fn date(offset: i64) -> crate::FieldDate {
    crate::FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn input(identifier: &str, value: &str) -> CreateVerification {
    CreateVerification {
        id: "target".into(),
        identifier: identifier.into(),
        value: value.into(),
        expires_at: date(100).into(),
        created_at: date(0).into(),
        updated_at: date(0).into(),
        ..Default::default()
    }
}

fn expected(identifier: &str, value: &str, updated: i64) -> JsonValue {
    json!({
        "id": "target", "identifier": identifier, "value": value,
        "expiresAt": "2030-01-01T00:01:40.000Z", "createdAt": "2030-01-01T00:00:00.000Z",
        "updatedAt": if updated == 0 { "2030-01-01T00:00:00.000Z" } else { "2030-01-01T00:00:01.000Z" },
    })
}

struct AfterHooks(Events);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for AfterHooks {
    async fn after_create_verification(
        &self,
        row: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        event(&self.0, json!(["after-create", row]))
    }

    async fn after_update_verification(
        &self,
        row: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        event(&self.0, json!(["after-update", row]))
    }
}

fn reader(writer: &EphemeralStore, events: &Events, reject: bool, consume: bool) -> EphemeralStore {
    let mut config = (*writer.config).clone();
    let output_writer = writer.clone();
    let trace = events.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let _ = config.verification.additional_fields.insert(
        "identifier".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let writer = output_writer.clone();
                    let events = trace.clone();
                    let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    async move {
                        event(&events, json!(["identifier", value.json()?]))?;
                        if consume {
                            if call == 2 {
                                assert!(
                                    writer
                                        .get_verification_by_identifier("subject")
                                        .await?
                                        .is_none()
                                );
                                let replacement = writer
                                    .create_verification(input("replacement", "other"))
                                    .await?;
                                event(&events, json!(["replacement", replacement]))?;
                            }
                        } else {
                            let changed = writer
                                .update_verification(
                                    "subject",
                                    VerificationUpdate {
                                        value: "after".into(),
                                        updated_at: date(1).into(),
                                        ..Default::default()
                                    },
                                )
                                .await?;
                            event(&events, json!(["write", changed]))?;
                            if reject {
                                return Err(AuthError::type_error("verification-output-rejected"));
                            }
                        }
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let trace = events.clone();
    let _ = config.verification.additional_fields.insert(
        "value".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    event(&trace, json!(["value", value.json()?]))?;
                    let value = value.as_str().ok_or_else(|| {
                        AuthError::internal("Expected a string verification value")
                    })?;
                    Ok(format!("{value}:out").into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    EphemeralStore {
        config: Arc::new(config),
        hooks: vec![Arc::new(AfterHooks(events.clone()))],
        ..writer.clone()
    }
}

#[tokio::test]
async fn verification_output_reads_live_fields_after_awaited_writer_updates() -> AuthResult<()> {
    for path in ["create", "find", "update"] {
        for reject in [false, true] {
            let writer = EphemeralStore::default();
            if path != "create" {
                let _ = writer
                    .create_verification(input("subject", "before"))
                    .await?;
            }
            let events = Events::default();
            let reader = reader(&writer, &events, reject, false);
            let result = match path {
                "create" => {
                    reader
                        .create_verification_optional(input("subject", "before"))
                        .await
                }
                "find" => reader.get_verification_by_identifier("subject").await,
                _ => {
                    reader
                        .update_verification(
                            "subject",
                            VerificationUpdate {
                                value: "before".into(),
                                updated_at: date(0).into(),
                                ..Default::default()
                            },
                        )
                        .await
                }
            };
            let mut trace = vec![
                json!(["identifier", "subject"]),
                json!(["write", expected("subject", "after", 1)]),
            ];
            if reject {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "verification-output-rejected")
                );
            } else {
                let projected = expected("subject", "after:out", 1);
                assert_eq!(serde_json::to_value(result?)?, projected);
                trace.push(json!(["value", "after"]));
                if path != "find" {
                    trace.push(json!([format!("after-{path}"), projected]));
                }
            }
            assert_eq!(observed(&events)?, trace, "{path}/{reject}");
            assert_eq!(
                serde_json::to_value(writer.get_verification_by_identifier("subject").await?)?,
                expected("subject", "after", 1)
            );
            assert_eq!(
                serde_json::to_value(
                    writer
                        .lock()?
                        .verifications
                        .snapshot()?
                        .iter()
                        .map(FieldMap::json)
                        .collect::<AuthResult<Vec<_>>>()?
                )?,
                json!([expected("subject", "after", 1)])
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn verification_consumed_output_retains_the_detached_record_when_its_id_is_reused()
-> AuthResult<()> {
    let writer = EphemeralStore::default();
    let _ = writer
        .create_verification(input("subject", "before"))
        .await?;
    let (base, isolated, queue) = writer.begin_transaction()?;
    let events = Events::default();
    let reader = reader(&isolated, &events, false, true);
    let result = reader
        .consume_verification_including_expired("subject")
        .await?;
    assert_eq!(
        serde_json::to_value(result)?,
        expected("subject", "before:out", 0)
    );
    assert_eq!(
        observed(&events)?,
        vec![
            json!(["identifier", "subject"]),
            json!(["value", "before"]),
            json!(["identifier", "subject"]),
            json!(["replacement", expected("replacement", "other", 0)]),
            json!(["value", "before"]),
        ]
    );
    writer.commit_transaction(base, isolated, queue).await?;
    assert!(
        writer
            .get_verification_by_identifier("subject")
            .await?
            .is_none()
    );
    assert_eq!(
        serde_json::to_value(writer.get_verification_by_identifier("replacement").await?)?,
        expected("replacement", "other", 0)
    );
    assert_eq!(
        serde_json::to_value(
            writer
                .lock()?
                .verifications
                .snapshot()?
                .iter()
                .map(FieldMap::json)
                .collect::<AuthResult<Vec<_>>>()?
        )?,
        json!([expected("replacement", "other", 0)])
    );
    Ok(())
}

#[tokio::test]
async fn verification_reservation_rethrows_the_original_output_error_after_reentrant_deletion()
-> AuthResult<()> {
    let writer = EphemeralStore::default();
    let events = Events::default();
    let mut config = (*writer.config).clone();
    let output_writer = writer.clone();
    let trace = events.clone();
    let _ = config.verification.additional_fields.insert(
        "identifier".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let writer = output_writer.clone();
                    let events = trace.clone();
                    async move {
                        event(&events, json!(["identifier", value.json()?]))?;
                        writer.delete_verification_by_identifier("subject").await?;
                        event(&events, json!(["deleted"]))?;
                        Err(AuthError::type_error(
                            "verification-reservation-output-rejected",
                        ))
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let reader = EphemeralStore {
        config: Arc::new(config),
        ..writer.clone()
    };
    let result = reader
        .reserve_verification("target", input("subject", "before"))
        .await;
    assert!(
        matches!(result, Err(AuthError::TypeError(message)) if message == "verification-reservation-output-rejected")
    );
    assert_eq!(
        observed(&events)?,
        vec![json!(["identifier", "subject"]), json!(["deleted"])]
    );
    assert!(writer.lock()?.verifications.snapshot()?.is_empty());
    Ok(())
}

struct ConsumeHooks {
    events: Events,
    move_id: bool,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for ConsumeHooks {
    async fn before_delete_verification(
        &self,
        row: &VerificationView,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        event(&self.events, json!(["before", row]))?;
        let transaction = context
            .transaction
            .ok_or_else(|| AuthError::internal("Consume requires its active transaction"))?;
        if self.move_id {
            let updated = transaction
                .update_verification(
                    "subject",
                    VerificationUpdate {
                        id: "moved".into(),
                        updated_at: date(0).into(),
                        ..Default::default()
                    },
                )
                .await?;
            event(&self.events, json!(["write", updated]))?;
        }
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        row: &VerificationView,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        event(&self.events, json!(["after", row]))
    }
}

fn expected_id(id: &str, identifier: &str, value: &str) -> JsonValue {
    let mut row = expected(identifier, value, 0);
    row["id"] = id.into();
    row
}

#[tokio::test]
async fn verification_consumption_binds_projected_ids_without_raw_identity_fallback()
-> AuthResult<()> {
    for serial in [false, true] {
        for decoy in [false, true] {
            let mut config = AuthConfig::default();
            if serial {
                config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
            }
            let writer = EphemeralStore::new(Arc::new(config));
            let mut subject = input("subject", "before");
            subject.id = crate::SchemaValue::from_field(7.into());
            let mut inputs = vec![subject];
            if decoy {
                let mut collision = input("decoy", "other");
                collision.id = "7".into();
                inputs.push(collision);
            }
            let mut retained = input("retained", "keep");
            retained.id = "retained".into();
            inputs.push(retained);
            let mut physical = Vec::new();
            for (id, input) in (1_u32..).zip(inputs) {
                let mut raw = input.fields()?;
                if serial {
                    let _ = raw.insert("id".into(), Value::Number(f64::from(id)));
                }
                physical.push(raw);
                let _ = writer.create_verification(input).await?;
            }
            assert_eq!(writer.lock()?.verifications.snapshot()?, physical);
            let events = Events::default();
            let reader = writer.clone().with_hooks(vec![Arc::new(ConsumeHooks {
                events: events.clone(),
                move_id: false,
            })]);
            let result = reader.consume_verification_by_identifier("subject").await?;
            let selected = if serial {
                Some(expected_id("1", "subject", "before"))
            } else {
                decoy.then(|| expected_id("7", "decoy", "other"))
            };
            assert_eq!(serde_json::to_value(result)?, json!(selected));
            let mut trace = vec![json!([
                "before",
                expected_id(if serial { "1" } else { "7" }, "subject", "before")
            ])];
            if let Some(selected) = selected {
                trace.push(json!(["after", selected]));
            }
            assert_eq!(observed(&events)?, trace, "{serial}/{decoy}");
            let remaining = if serial {
                &physical[1..]
            } else if decoy {
                &physical[2..]
            } else {
                &physical[..]
            };
            assert_eq!(writer.lock()?.verifications.snapshot()?, remaining);
        }
    }
    Ok(())
}

type ConsumeWriter = Arc<OnceLock<Weak<EphemeralStore>>>;

fn moving_consumer(
    writer: &EphemeralStore,
    events: &Events,
    id_first: bool,
    move_in_hook: bool,
) -> (EphemeralStore, ConsumeWriter) {
    let mut config = (*writer.config).clone();
    if id_first {
        let _ = config
            .verification
            .additional_fields
            .insert("id".into(), UserFieldConfig::default());
    }
    let current = ConsumeWriter::default();
    let current_writer = current.clone();
    let trace = events.clone();
    let calls = AtomicUsize::new(0);
    let _ = config.verification.additional_fields.insert(
        "probe".into(),
        UserFieldConfig {
            field_name: Some("value".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let current = current_writer.clone();
                    let events = trace.clone();
                    let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    async move {
                        event(&events, json!(["probe", value.json()?]))?;
                        if first && !move_in_hook {
                            let writer =
                                current.get().and_then(Weak::upgrade).ok_or_else(|| {
                                    AuthError::internal("Expected active consume projection writer")
                                })?;
                            let updated = writer
                                .update_verification(
                                    "subject",
                                    VerificationUpdate {
                                        id: "moved".into(),
                                        updated_at: date(0).into(),
                                        ..Default::default()
                                    },
                                )
                                .await?;
                            event(&events, json!(["write", updated]))?;
                        }
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    if !id_first {
        let _ = config
            .verification
            .additional_fields
            .insert("id".into(), UserFieldConfig::default());
    }
    (
        EphemeralStore {
            config: Arc::new(config),
            hooks: vec![Arc::new(ConsumeHooks {
                events: events.clone(),
                move_id: move_in_hook,
            })],
            ..writer.clone()
        },
        current,
    )
}

#[tokio::test]
async fn verification_consumption_uses_the_id_projected_before_delete_hooks() -> AuthResult<()> {
    for (id_first, move_in_hook) in [(true, false), (false, false), (false, true)] {
        let writer = EphemeralStore::default();
        let subject = input("subject", "before");
        let mut retained = input("retained", "keep");
        retained.id = "retained".into();
        let _ = writer.create_verification(subject.clone()).await?;
        let _ = writer.create_verification(retained.clone()).await?;
        let events = Events::default();
        let (parent, current) = moving_consumer(&writer, &events, id_first, move_in_hook);
        let (base, isolated, queue) = parent.begin_transaction()?;
        let isolated = Arc::new(isolated);
        current
            .set(Arc::downgrade(&isolated))
            .map_err(|_| AuthError::internal("Consume projection writer already set"))?;
        let result = isolated
            .consume_verification_by_identifier("subject")
            .await?;
        let consumed = !id_first && !move_in_hook;
        let mut changed = expected_id("moved", "subject", "before");
        changed["probe"] = "before".into();
        let mut snapshot = changed.clone();
        if !consumed {
            snapshot["id"] = "target".into();
        }
        assert_eq!(
            serde_json::to_value(result)?,
            if consumed {
                changed.clone()
            } else {
                JsonValue::Null
            }
        );
        let mut trace = if move_in_hook {
            vec![
                json!(["probe", "before"]),
                json!(["before", snapshot]),
                json!(["probe", "before"]),
                json!(["write", changed]),
            ]
        } else {
            vec![
                json!(["probe", "before"]),
                json!(["probe", "before"]),
                json!(["write", changed]),
                json!(["before", snapshot]),
            ]
        };
        if consumed {
            trace.push(json!(["probe", "before"]));
        }
        assert_eq!(observed(&events)?, trace);
        assert_eq!(
            writer.lock()?.verifications.snapshot()?,
            [subject.fields()?, retained.fields()?],
            "The consume transaction must keep its writes isolated"
        );
        parent
            .commit_transaction(base, (*isolated).clone(), queue)
            .await?;
        if consumed {
            trace.push(json!(["after", changed]));
        }
        assert_eq!(observed(&events)?, trace, "{id_first}/{move_in_hook}");
        let mut remaining = vec![retained.fields()?];
        if !consumed {
            let mut moved = subject.fields()?;
            let _ = moved.insert("id".into(), "moved".into());
            remaining.push(moved);
        }
        assert_eq!(writer.lock()?.verifications.snapshot()?, remaining);
    }
    Ok(())
}
