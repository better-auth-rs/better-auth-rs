use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    error::DatabaseError,
    store::{StatelessSchema, schema::EntityRole},
};
use better_auth_seaorm::sea_orm::{DbBackend, Statement};
use sha2::{Digest, Sha256};
use std::sync::{OnceLock, Weak};

type Trace = Arc<Mutex<Vec<FieldValue>>>;

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite {
        database: DatabaseConnection,
        integer_id: bool,
    },
}

impl Storage {
    fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    async fn rows(&self) -> AuthResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => store.storage_rows(EntityRole::Verification),
            Self::Sqlite {
                database,
                integer_id,
            } => database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT * FROM verifications ORDER BY id",
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .into_iter()
                .map(|row| {
                    [
                        ("id", "id"),
                        ("identifier", "identifier"),
                        ("value", "value"),
                        ("expiresAt", "expires_at"),
                        ("createdAt", "created_at"),
                        ("updatedAt", "updated_at"),
                    ]
                    .into_iter()
                    .map(|(name, column)| {
                        let value = if name == "id" && *integer_id {
                            row.try_get::<i64>("", column).map(FieldValue::from)
                        } else {
                            row.try_get::<String>("", column).map(FieldValue::from)
                        }
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                        Ok((name.into(), value))
                    })
                    .collect()
                })
                .collect(),
        }
    }

    async fn assert_rows(&self, mut expected: Vec<FieldMap>) -> AuthResult<()> {
        if let Self::Sqlite { integer_id, .. } = self {
            for row in &mut expected {
                for name in ["expiresAt", "createdAt", "updatedAt"] {
                    let date = required(row.get(name).and_then(FieldValue::as_date))?;
                    let value = required(date.to_datetime()?)?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    let _ = row.insert(name.into(), value.into());
                }
            }
            if !*integer_id {
                expected.sort_by(|left, right| {
                    left.get("id")
                        .and_then(FieldValue::as_str)
                        .cmp(&right.get("id").and_then(FieldValue::as_str))
                });
            }
        }
        assert_eq!(self.rows().await?, expected);
        Ok(())
    }
}

fn reservation_id() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(b"reserve:subject"))
}

fn row(id: &str, identifier: &str, value: &str) -> CreateVerification {
    input(id, identifier, value, 0, 100)
}

fn trace(name: &str, value: FieldValue) -> FieldValue {
    vec![name.into(), value].into()
}

fn record(events: &Trace, value: FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification reservation trace lock poisoned"))?
        .push(value);
    Ok(())
}

fn observed(events: &Trace) -> AuthResult<Vec<FieldValue>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Verification reservation trace lock poisoned"))?
        .clone())
}

pub(super) fn pin_dates(config: &mut AuthConfig) {
    for name in ["createdAt", "updatedAt"] {
        let field = config
            .verification
            .additional_fields
            .entry(name.into())
            .or_insert_with(|| UserFieldConfig {
                field_type: UserFieldType::Date,
                ..Default::default()
            });
        field.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| Ok(date(0).into()))),
            output: None,
        });
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    pin_dates(&mut config);
    config
}

fn reader<S: AuthSchema>(
    base: &dyn AuthStore<S>,
    config: AuthConfig,
) -> AuthResult<Arc<dyn AuthStore<S>>> {
    base.with_runtime(Arc::new(config), Vec::new(), Default::default())
}

fn tracing_field(events: &Trace, reject_input: bool) -> UserFieldConfig {
    let input_events = events.clone();
    let output_events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(&input_events, trace("input", value.clone()))?;
                if reject_input {
                    return Err(AuthError::type_error(
                        "verification-reservation-input-rejected",
                    ));
                }
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(&output_events, trace("output", value.clone()))?;
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

async fn duplicates<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    serial: bool,
) -> AuthResult<()> {
    let events = Trace::default();
    let mut config = config();
    if serial {
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
    }
    let _ = config
        .verification
        .additional_fields
        .insert("value".into(), tracing_field(&events, false));
    let reader = reader(base.as_ref(), config)?;
    let id = reservation_id();
    let duplicate = !storage.is_memory() && !serial;
    assert_eq!(
        [
            reader
                .reserve_verification(&id, row("ignored", "subject", "first"))
                .await?,
            reader
                .reserve_verification(&id, row("ignored", "subject", "second"))
                .await?,
        ],
        [true, !duplicate]
    );
    assert_eq!(
        observed(&events)?,
        [
            trace("input", "first".into()),
            trace("output", "first".into()),
            trace("input", "second".into()),
            trace("output", if duplicate { "first" } else { "second" }.into()),
        ]
    );
    let mut first = row(&id, "subject", "first").fields()?;
    let mut second = row(&id, "subject", "second").fields()?;
    if serial {
        let _ = first.insert("id".into(), 1.into());
        let _ = second.insert("id".into(), 2.into());
    }
    let mut expected = vec![first];
    if !duplicate {
        expected.push(second);
    }
    storage.assert_rows(expected).await
}

async fn input_failure<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    existing: bool,
) -> AuthResult<()> {
    let id = reservation_id();
    let retained = row(&id, "different-identifier", "existing");
    if existing {
        assert_eq!(
            base.create_verification(retained.clone()).await?.fields()?,
            retained.fields()?
        );
    }
    let events = Trace::default();
    let mut config = config();
    let _ = config
        .verification
        .additional_fields
        .insert("value".into(), tracing_field(&events, true));
    let result = reader(base.as_ref(), config)?
        .reserve_verification(&id, row("ignored", "subject", "before"))
        .await;
    let mut expected = vec![trace("input", "before".into())];
    if existing {
        assert!(!result?);
        expected.push(trace("output", "existing".into()));
    } else {
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "verification-reservation-input-rejected")
        );
    }
    assert_eq!(observed(&events)?, expected);
    storage
        .assert_rows(if existing {
            vec![retained.fields()?]
        } else {
            vec![]
        })
        .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    Keep,
    Delete,
    Replace,
    RereadFailure,
}

async fn output_failure<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    mode: Recovery,
) -> AuthResult<()> {
    let events = Trace::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let id = reservation_id();
    let identifier_events = events.clone();
    let identifier_id = id.clone();
    let value_events = events.clone();
    let writer = base.clone();
    let mut config = config();
    let _ = config.verification.additional_fields.insert(
        "identifier".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let writer = writer.clone();
                    let events = identifier_events.clone();
                    let id = identifier_id.clone();
                    let calls = calls.clone();
                    async move {
                        record(&events, trace("identifier", value.clone()))?;
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            if matches!(mode, Recovery::Delete | Recovery::Replace) {
                                writer.delete_verification(&id).await?;
                                record(&events, vec![FieldValue::from("deleted")].into())?;
                            }
                            if mode == Recovery::Replace {
                                let replacement = writer
                                    .create_verification(row(&id, "replacement", "other"))
                                    .await?;
                                record(
                                    &events,
                                    trace("replacement", replacement.fields()?.into()),
                                )?;
                            }
                            return Err(AuthError::type_error(
                                "verification-reservation-output-rejected",
                            ));
                        }
                        if mode == Recovery::RereadFailure {
                            return Err(AuthError::type_error(
                                "verification-reservation-reread-rejected",
                            ));
                        }
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let _ = config.verification.additional_fields.insert(
        "value".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    record(&value_events, trace("value", value.clone()))?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let result = reader(base.as_ref(), config)?
        .reserve_verification(&id, row("ignored", "subject", "before"))
        .await;
    match mode {
        Recovery::Keep | Recovery::Replace => assert!(!result?),
        Recovery::Delete => assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "verification-reservation-output-rejected")
        ),
        Recovery::RereadFailure => assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "verification-reservation-reread-rejected")
        ),
    }
    let replacement = row(&id, "replacement", "other").fields()?;
    let mut expected = vec![trace("identifier", "subject".into())];
    if matches!(mode, Recovery::Delete | Recovery::Replace) {
        expected.push(vec![FieldValue::from("deleted")].into());
    }
    if mode == Recovery::Replace {
        expected.push(trace("replacement", replacement.clone().into()));
    }
    if mode != Recovery::Delete {
        expected.push(trace(
            "identifier",
            if mode == Recovery::Replace {
                "replacement"
            } else {
                "subject"
            }
            .into(),
        ));
    }
    if matches!(mode, Recovery::Keep | Recovery::Replace) {
        expected.push(trace(
            "value",
            if mode == Recovery::Replace {
                "other"
            } else {
                "before"
            }
            .into(),
        ));
    }
    assert_eq!(observed(&events)?, expected);
    storage
        .assert_rows(match mode {
            Recovery::Delete => vec![],
            Recovery::Replace => vec![replacement],
            _ => vec![row(&id, "subject", "before").fields()?],
        })
        .await
}

async fn id_reentry<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    id_first: bool,
) -> AuthResult<()> {
    let retained = row("retained", "retained", "retained-proof");
    assert_eq!(
        base.create_verification(retained.clone()).await?.fields()?,
        retained.fields()?
    );
    let target = Arc::new(OnceLock::<Weak<dyn AuthStore<S>>>::new());
    let input_target = target.clone();
    let events = Trace::default();
    let input_events = events.clone();
    let output_events = events.clone();
    let mut config = config();
    config.advanced.database.generate_id = Some(IdGeneration::Uuid);
    let probe = UserFieldConfig {
        field_name: Some("value".into()),
        default_value: Some("probe".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let target = input_target.clone();
                let events = input_events.clone();
                async move {
                    record(&events, trace("probe-input", value))?;
                    let reader = required(target.get().and_then(Weak::upgrade))?;
                    let nested =
                        required(reader.get_verification_by_identifier("retained").await?)?;
                    record(&events, trace("nested-read", nested.fields()?.into()))?;
                    Ok(FieldValue::Undefined)
                }
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(&output_events, trace("probe-output", value.clone()))?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    let sentinel = UserFieldConfig {
        field_name: Some("ignored".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::type_error(
                    "configured-reservation-id-input-called",
                ))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::type_error(
                    "configured-reservation-id-output-called",
                ))
            })),
        }),
        ..Default::default()
    };
    if id_first {
        let _ = config
            .verification
            .additional_fields
            .insert("id".into(), sentinel.clone());
    }
    let _ = config
        .verification
        .additional_fields
        .insert("probe".into(), probe);
    if !id_first {
        let _ = config
            .verification
            .additional_fields
            .insert("id".into(), sentinel);
    }
    let reader = reader(base.as_ref(), config)?;
    target
        .set(Arc::downgrade(&reader))
        .map_err(|_| AuthError::internal("Reservation reader was already assigned"))?;
    let id = reservation_id();
    let result = reader
        .reserve_verification(&id, row("ignored", "subject", "before"))
        .await;
    let succeeds = storage.is_memory() || !id_first;
    if succeeds {
        assert!(result?);
    } else {
        let Err(AuthError::Database(DatabaseError::Query(message))) = result else {
            return Err(AuthError::internal(format!(
                "Expected SQLite missing-ID error: {result:?}"
            )));
        };
        assert_eq!(
            message,
            "Query Error: error returned from database: (code: 1299) NOT NULL constraint failed: verifications.id"
        );
    }
    let mut nested = retained.fields()?;
    let _ = nested.insert("probe".into(), "retained-proof".into());
    let mut expected = vec![
        trace("probe-input", "probe".into()),
        trace("probe-output", "retained-proof".into()),
        trace("nested-read", nested.into()),
    ];
    if succeeds {
        expected.push(trace("probe-output", "before".into()));
    }
    assert_eq!(observed(&events)?, expected);
    let mut rows = vec![retained.fields()?];
    if succeeds {
        let mut created = row(&id, "subject", "before").fields()?;
        if id_first {
            let _ = created.remove("id");
        }
        rows.push(created);
    }
    storage.assert_rows(rows).await
}

async fn input_boundary<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
) -> AuthResult<()> {
    let events = Trace::default();
    let mut config = config();
    for name in ["createdAt", "updatedAt"] {
        let captured = events.clone();
        let field = required(config.verification.additional_fields.get_mut(name))?;
        field.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(
                    &captured,
                    trace(
                        if name == "createdAt" {
                            "created-input"
                        } else {
                            "updated-input"
                        },
                        value,
                    ),
                )?;
                Ok(date(0).into())
            })),
            output: None,
        });
    }
    for name in ["value", "probe"] {
        let input_events = events.clone();
        let output_events = events.clone();
        let _ = config.verification.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                field_name: (name == "probe").then(|| "value".into()),
                default_value: (name == "probe").then(|| "default-probe".into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        record(
                            &input_events,
                            trace(
                                if name == "value" {
                                    "value-input"
                                } else {
                                    "probe-input"
                                },
                                value.clone(),
                            ),
                        )?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        record(
                            &output_events,
                            trace(
                                if name == "value" {
                                    "value-output"
                                } else {
                                    "probe-output"
                                },
                                value.clone(),
                            ),
                        )?;
                        Ok(value)
                    })),
                }),
                ..Default::default()
            },
        );
    }
    let reader = reader(base.as_ref(), config)?;
    let id = reservation_id();
    let mut data = row("ignored", "subject", "before");
    let caller_created = date(-100);
    let caller_updated = date(-100);
    data.created_at = caller_created.clone().into();
    data.updated_at = caller_updated.clone().into();
    let _ = data
        .additional_fields
        .insert("probe".into(), "caller-probe".into());
    let started = chrono::Utc::now().timestamp_millis();
    assert!(reader.reserve_verification(&id, data).await?);
    let finished = chrono::Utc::now().timestamp_millis();
    let actual = observed(&events)?;
    let [created, updated] = [1, 2].map(|index| {
        let event = required(actual.get(index).and_then(FieldValue::as_array))?;
        let observed = required(event.get(1).and_then(FieldValue::as_date))?;
        let milliseconds = observed.milliseconds();
        assert!(milliseconds >= started as f64 && milliseconds <= finished as f64);
        Ok::<_, AuthError>(observed.clone())
    });
    let created = created?;
    let updated = updated?;
    assert!(!created.same_object(&updated));
    assert!(!created.same_object(&caller_created));
    assert!(!updated.same_object(&caller_updated));
    assert_eq!(
        actual,
        [
            trace("value-input", "before".into()),
            trace("created-input", created.into()),
            trace("updated-input", updated.into()),
            trace("probe-input", "default-probe".into()),
            trace("value-output", "default-probe".into()),
            trace("probe-output", "default-probe".into()),
        ]
    );
    storage
        .assert_rows(vec![row(&id, "subject", "default-probe").fields()?])
        .await
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Duplicate(bool),
    InputFailure(bool),
    OutputFailure(Recovery),
    IdReentry(bool),
    InputBoundary,
}

fn cases() -> [Case; 11] {
    [
        Case::Duplicate(false),
        Case::Duplicate(true),
        Case::InputFailure(false),
        Case::InputFailure(true),
        Case::OutputFailure(Recovery::Keep),
        Case::OutputFailure(Recovery::Delete),
        Case::OutputFailure(Recovery::Replace),
        Case::OutputFailure(Recovery::RereadFailure),
        Case::IdReentry(false),
        Case::IdReentry(true),
        Case::InputBoundary,
    ]
}

async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    match case {
        Case::Duplicate(serial) => duplicates(base, storage, serial).await,
        Case::InputFailure(existing) => input_failure(base, storage, existing).await,
        Case::OutputFailure(mode) => output_failure(base, storage, mode).await,
        Case::IdReentry(id_first) => id_reentry(base, storage, id_first).await,
        Case::InputBoundary => input_boundary(base, storage).await,
    }
    .map_err(|error| AuthError::internal(format!("{case:?}: {error}")))
}

#[tokio::test]
async fn memory_reservations_preserve_adapter_id_inputs_and_failure_rereads() -> AuthResult<()> {
    for case in cases() {
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        let base: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
        check(base, Storage::Memory(Box::new(store)), case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_reservations_preserve_adapter_id_inputs_and_failure_rereads() -> AuthResult<()> {
    for case in cases() {
        let (base, database) = sqlite(AuthConfig::default()).await?;
        let integer_id = matches!(case, Case::Duplicate(true));
        if integer_id {
            database.execute_unprepared("DROP TABLE verifications; CREATE TABLE verifications (id INTEGER PRIMARY KEY NOT NULL, identifier TEXT NOT NULL, value TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
                .await.map_err(|error| AuthError::internal(error.to_string()))?;
        }
        check(
            base,
            Storage::Sqlite {
                database,
                integer_id,
            },
            case,
        )
        .await?;
    }
    Ok(())
}
