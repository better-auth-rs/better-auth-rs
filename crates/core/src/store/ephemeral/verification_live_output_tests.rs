#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete records, callback order, and persistence after failures"
)]

use super::*;
use crate::store::database_hooks::{DatabaseHookContext, VerificationUpdate};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::atomic::{AtomicUsize, Ordering};

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
                serde_json::to_value(writer.lock()?.verifications.snapshot()?)?,
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
        serde_json::to_value(writer.lock()?.verifications.snapshot()?)?,
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
