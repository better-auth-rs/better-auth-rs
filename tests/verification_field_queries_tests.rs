#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts complete records, callback order, and atomic lifecycle outcomes"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateVerification, FieldDate,
    FieldMap, FieldValue, SchemaValue,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, database_hooks::VerificationUpdate, transaction},
    user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::task::JoinSet;

#[path = "verification_field_queries_tests/reservation.rs"]
mod reservation;

fn date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn input(
    id: &str,
    identifier: &str,
    value: &str,
    created: i64,
    expires: i64,
) -> CreateVerification {
    CreateVerification {
        id: id.into(),
        identifier: identifier.into(),
        value: value.into(),
        created_at: date(created).into(),
        expires_at: date(expires).into(),
        updated_at: date(0).into(),
        ..Default::default()
    }
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Verification contract record is missing"))
}

async fn sqlite(
    config: AuthConfig,
) -> AuthResult<(Arc<dyn AuthStore<BundledSchema>>, DatabaseConnection)> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok((
        Arc::new(SeaOrmStore::<BundledSchema>::new(config, database.clone())),
        database,
    ))
}

fn mapped() -> AuthConfig {
    let mut config = AuthConfig::default();
    for (logical, physical, field_type) in [
        ("identifier", "value", UserFieldType::String),
        ("value", "identifier", UserFieldType::String),
        ("createdAt", "expiresAt", UserFieldType::Date),
        ("expiresAt", "createdAt", UserFieldType::Date),
    ] {
        let _ = config.verification.additional_fields.insert(
            logical.into(),
            UserFieldConfig {
                field_name: Some(physical.into()),
                field_type,
                ..Default::default()
            },
        );
    }
    config
}

async fn mapped_lifecycle<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    double_where_mapping: bool,
) -> AuthResult<()> {
    let created = store
        .create_verification(input("first", "subject", "proof", 1, 100))
        .await?;
    let original_query = (!double_where_mapping).then_some(created.clone());
    assert_eq!(
        store.get_verification("subject", "proof").await?,
        original_query
    );
    assert_eq!(
        store.get_verification_by_identifier("subject").await?,
        original_query
    );
    assert_eq!(
        store.get_verification_by_value("proof").await?,
        original_query
    );
    assert_eq!(
        store.get_verification_including_expired("subject").await?,
        original_query
    );
    let (identifier_query, value_query) = if double_where_mapping {
        ("proof", "subject")
    } else {
        ("subject", "proof")
    };
    assert_eq!(
        required(
            store
                .get_verification(identifier_query, value_query)
                .await?
        )?,
        created
    );
    assert_eq!(
        required(
            store
                .get_verification_by_identifier(identifier_query)
                .await?
        )?,
        created
    );
    assert_eq!(
        required(store.get_verification_by_value(value_query).await?)?,
        created
    );
    assert_eq!(
        required(
            store
                .get_verification_including_expired(identifier_query)
                .await?
        )?,
        created
    );
    if double_where_mapping {
        assert!(
            store
                .update_verification(
                    "subject",
                    VerificationUpdate {
                        value: "new-proof".into(),
                        updated_at: date(3).into(),
                        ..Default::default()
                    }
                )
                .await?
                .is_none()
        );
        assert_eq!(
            required(store.get_verification_including_expired("proof").await?)?,
            created
        );
    }
    let updated = required(
        store
            .update_verification(
                identifier_query,
                VerificationUpdate {
                    value: "new-proof".into(),
                    updated_at: date(3).into(),
                    ..Default::default()
                },
            )
            .await?,
    )?;
    let mut expected = created.fields()?;
    let _ = expected.insert("value".into(), "new-proof".into());
    let _ = expected.insert("updatedAt".into(), date(3).into());
    assert_eq!(updated.fields()?, expected);
    let (updated_identifier, updated_value) = if double_where_mapping {
        ("new-proof", "subject")
    } else {
        ("subject", "new-proof")
    };
    assert_eq!(
        required(
            store
                .get_verification(updated_identifier, updated_value)
                .await?
        )?
        .fields()?,
        expected
    );
    if double_where_mapping {
        transaction(store.as_ref(), |tx| {
            Box::pin(async move { tx.delete_verification_by_identifier("subject").await })
        })
        .await?;
        assert_eq!(
            required(
                store
                    .get_verification_including_expired("new-proof")
                    .await?
            )?
            .fields()?,
            expected
        );
    }
    transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            tx.delete_verification_by_identifier(updated_identifier)
                .await
        })
    })
    .await?;
    assert!(
        store
            .get_verification_including_expired(updated_identifier)
            .await?
            .is_none()
    );

    let _ = store
        .create_verification(input(
            "expired",
            "expired",
            "expired-proof",
            -1_000_000_000,
            -1_000_000_000,
        ))
        .await?;
    let retained = store
        .create_verification(input("retained", "other", "retained-proof", 1, 100))
        .await?;
    assert_eq!(store.delete_expired_verifications().await?, 1);
    let expired_query = if double_where_mapping {
        "expired-proof"
    } else {
        "expired"
    };
    assert!(
        store
            .get_verification_including_expired(expired_query)
            .await?
            .is_none()
    );
    let retained_query = if double_where_mapping {
        "retained-proof"
    } else {
        "other"
    };
    assert_eq!(
        required(store.get_verification_by_identifier(retained_query).await?)?,
        retained
    );

    let old = store
        .create_verification(input("old", "shared", "old-proof", 1, 500))
        .await?;
    let latest = store
        .create_verification(input("new", "shared", "latest-proof", 2, 100))
        .await?;
    assert_eq!(
        store.get_verification_including_expired("shared").await?,
        (!double_where_mapping).then_some(latest.clone())
    );
    let latest_query = if double_where_mapping {
        "latest-proof"
    } else {
        "shared"
    };
    assert_eq!(
        required(
            store
                .get_verification_including_expired(latest_query)
                .await?
        )?,
        latest
    );
    assert!(
        store
            .consume_verification(latest_query, "wrong-proof")
            .await?
            .is_none()
    );
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let _ =
            tasks.spawn(async move { store.consume_verification_by_identifier("shared").await });
    }
    let mut consumed = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(row) = result.map_err(|error| AuthError::internal(error.to_string()))?? {
            consumed.push(row);
        }
    }
    assert_eq!(
        consumed,
        if double_where_mapping {
            vec![]
        } else {
            vec![latest.clone()]
        }
    );
    if double_where_mapping {
        assert_eq!(
            required(
                store
                    .get_verification_including_expired("old-proof")
                    .await?
            )?,
            old
        );
        assert_eq!(
            required(
                store
                    .get_verification_including_expired("latest-proof")
                    .await?
            )?,
            latest
        );
        for _ in 0..8 {
            let store = store.clone();
            let _ = tasks.spawn(async move {
                store
                    .consume_verification_by_identifier("latest-proof")
                    .await
            });
        }
        let mut consumed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Some(row) = result.map_err(|error| AuthError::internal(error.to_string()))?? {
                consumed.push(row);
            }
        }
        assert_eq!(consumed, vec![latest]);
        assert!(
            store
                .get_verification_including_expired("latest-proof")
                .await?
                .is_none()
        );
        assert_eq!(
            required(
                store
                    .get_verification_including_expired("old-proof")
                    .await?
            )?,
            old
        );
    }
    assert!(
        store
            .get_verification_including_expired("shared")
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_verification_by_identifier(retained_query).await?)?,
        retained
    );

    let mut config = mapped();
    reservation::pin_dates(&mut config);
    let store = store.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    let claim = input("ignored", "claim", "claimed-proof", 3, 100);
    assert!(
        store
            .reserve_verification("reservation", claim.clone())
            .await?
    );
    assert_eq!(
        store
            .reserve_verification("reservation", claim.clone())
            .await?,
        !double_where_mapping
    );
    let (claim_identifier, claim_value) = if double_where_mapping {
        ("claimed-proof", "claim")
    } else {
        ("claim", "claimed-proof")
    };
    let reserved = required(
        store
            .get_verification(claim_identifier, claim_value)
            .await?,
    )?;
    assert_eq!(reserved.id, "reservation");
    store.delete_verification("reservation").await?;
    assert!(store.reserve_verification("reservation", claim).await?);
    if double_where_mapping {
        assert!(
            store
                .consume_verification_by_identifier("claim")
                .await?
                .is_none()
        );
        assert_eq!(
            required(
                store
                    .get_verification_including_expired(claim_identifier)
                    .await?
            )?,
            reserved
        );
    }
    assert_eq!(
        required(
            store
                .consume_verification_by_identifier(claim_identifier)
                .await?
        )?,
        reserved
    );
    assert!(
        store
            .get_verification_including_expired(claim_identifier)
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_verification_by_identifier(retained_query).await?)?,
        retained
    );
    Ok(())
}

#[tokio::test]
async fn verification_mapping_drives_crud_sorting_cleanup_and_atomic_consumption() -> AuthResult<()>
{
    mapped_lifecycle(Arc::new(EphemeralStore::new(Arc::new(mapped()))), false).await?;
    let (store, database) = sqlite(mapped()).await?;
    mapped_lifecycle(store, true).await?;
    let rows = database
        .query_all_raw(better_auth_seaorm::sea_orm::Statement::from_string(
            better_auth_seaorm::sea_orm::DbBackend::Sqlite,
            "SELECT * FROM verifications ORDER BY id",
        ))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let mut physical = Vec::new();
    for row in rows {
        let mut fields = FieldMap::new();
        for name in [
            "id",
            "identifier",
            "value",
            "created_at",
            "expires_at",
            "updated_at",
        ] {
            let value = row
                .try_get::<String>("", name)
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let _ = fields.insert(name.into(), value.into());
        }
        physical.push(fields);
    }
    assert_eq!(
        physical,
        [
            FieldMap::from([
                ("id".into(), "old".into()),
                ("identifier".into(), "old-proof".into()),
                ("value".into(), "shared".into()),
                ("created_at".into(), "2030-01-01T00:08:20.000Z".into()),
                ("expires_at".into(), "2030-01-01T00:00:01.000Z".into()),
                ("updated_at".into(), "2030-01-01T00:00:00.000Z".into()),
            ]),
            FieldMap::from([
                ("id".into(), "retained".into()),
                ("identifier".into(), "retained-proof".into()),
                ("value".into(), "other".into()),
                ("created_at".into(), "2030-01-01T00:01:40.000Z".into()),
                ("expires_at".into(), "2030-01-01T00:00:01.000Z".into()),
                ("updated_at".into(), "2030-01-01T00:00:00.000Z".into()),
            ]),
        ]
    );
    Ok(())
}

async fn dynamic_query<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    value: FieldValue,
    query: &str,
    calls: &AtomicUsize,
) -> AuthResult<()> {
    let mut create = input("41", "unused", "payload", 0, 100);
    create.identifier = SchemaValue::from_field(value);
    create.expires_at = SchemaValue::from_field("not-a-date".into());
    let created = store.create_verification(create).await?;
    assert_eq!(
        created.expires_at.field_value(),
        FieldValue::from("not-a-date")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let found = required(store.get_verification_including_expired(query).await?)?;
    assert_eq!(found, created);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let consumed = required(store.consume_verification_by_identifier(query).await?)?;
    assert_eq!(consumed, created);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        store
            .get_verification_including_expired(query)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn verification_replacement_types_and_id_references_keep_query_and_output_semantics()
-> AuthResult<()> {
    for (kind, value, query, reference) in [
        (
            UserFieldType::Number,
            FieldValue::Number(16.0),
            "0x10",
            false,
        ),
        (
            UserFieldType::Boolean,
            FieldValue::Bool(true),
            "true",
            false,
        ),
        (
            UserFieldType::String,
            FieldValue::from("0x10"),
            "1.6e1",
            true,
        ),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = calls.clone();
        let mut config = AuthConfig::default();
        if reference {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
        }
        let _ = config.verification.additional_fields.insert(
            "identifier".into(),
            UserFieldConfig {
                field_type: kind,
                references: reference.then(|| UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        let _ = captured.fetch_add(1, Ordering::SeqCst);
                        Ok(value)
                    })),
                    output: None,
                }),
                ..Default::default()
            },
        );
        let _ = config
            .verification
            .additional_fields
            .insert("expiresAt".into(), UserFieldConfig::default());
        dynamic_query(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            value.clone(),
            query,
            &calls,
        )
        .await?;
        calls.store(0, Ordering::SeqCst);
        dynamic_query(sqlite(config).await?.0, value, query, &calls).await?;
    }
    Ok(())
}

type Events = Arc<Mutex<Vec<&'static str>>>;
fn push(events: &Events, event: &'static str) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?
        .push(event);
    Ok(())
}

fn id_order_config(events: &Events, id_first: bool, reject: bool) -> AuthConfig {
    let generated = events.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            push(&generated, "generate")?;
            Ok(Some("generated".into()))
        })));
    let input = events.clone();
    let output = events.clone();
    let shadow = UserFieldConfig {
        field_name: Some("id".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                push(&input, "input")?;
                if reject {
                    return Err(AuthError::internal("verification-input-rejected"));
                }
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                push(&output, "output")?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    let id = UserFieldConfig {
        field_name: Some("ignored".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-input-called"))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-output-called"))
            })),
        }),
        ..Default::default()
    };
    config.verification.additional_fields.extend(if id_first {
        [("id".into(), id), ("shadow".into(), shadow)]
    } else {
        [("shadow".into(), shadow), ("id".into(), id)]
    });
    config
}

async fn id_order<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    events: Events,
    id_first: bool,
    reject: bool,
) -> AuthResult<()> {
    let mut create = input("unused", "subject", "payload", 0, 100);
    create.id = Default::default();
    create.additional_fields = FieldMap::from([("shadow".into(), "shadow-id".into())]);
    let result = store.create_verification(create).await;
    let expected = if reject {
        assert!(
            matches!(&result, Err(AuthError::Internal(message)) if message == "verification-input-rejected")
        );
        if id_first {
            vec!["generate", "input"]
        } else {
            vec!["input"]
        }
    } else {
        let created = result?;
        assert_eq!(created.id, if id_first { "shadow-id" } else { "generated" });
        assert_eq!(
            created.additional_fields.get("shadow"),
            Some(&created.id.field_value())
        );
        if id_first {
            vec!["generate", "input", "output"]
        } else {
            vec!["input", "generate", "output"]
        }
    };
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?,
        expected
    );
    assert_eq!(
        store
            .get_verification_including_expired("subject")
            .await?
            .is_some(),
        !reject
    );
    Ok(())
}

#[tokio::test]
async fn verification_id_slot_keeps_alias_order_and_callback_failures() -> AuthResult<()> {
    for id_first in [false, true] {
        for reject in [false, true] {
            let events = Events::default();
            id_order(
                Arc::new(EphemeralStore::new(Arc::new(id_order_config(
                    &events, id_first, reject,
                )))),
                events,
                id_first,
                reject,
            )
            .await?;
            let events = Events::default();
            id_order(
                sqlite(id_order_config(&events, id_first, reject)).await?.0,
                events,
                id_first,
                reject,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_verification_update_changes_all_matches_before_output() -> AuthResult<()> {
    for reject in [false, true] {
        let events = Events::default();
        let input_events = events.clone();
        let output_events = events.clone();
        let reject_output = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_rejected = reject_output.clone();
        let mut config = mapped();
        required(config.verification.additional_fields.get_mut("value"))?.transform =
            Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    push(&input_events, "input")?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    push(&output_events, "output")?;
                    if output_rejected.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("verification-output-rejected"));
                    }
                    Ok(value)
                })),
            });
        let store: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
            Arc::new(EphemeralStore::new(Arc::new(config)));
        let first = store
            .create_verification(input("first", "shared", "first-proof", 1, 100))
            .await?;
        let second = store
            .create_verification(input("second", "shared", "second-proof", 2, 100))
            .await?;
        let retained = store
            .create_verification(input("retained", "other", "retained-proof", 3, 100))
            .await?;
        let mut expected_first = first.fields()?;
        let mut expected_second = second.fields()?;
        for expected in [&mut expected_first, &mut expected_second] {
            let _ = expected.insert("value".into(), "new-proof".into());
            let _ = expected.insert("updatedAt".into(), date(3).into());
        }
        events
            .lock()
            .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?
            .clear();
        reject_output.store(reject, Ordering::SeqCst);
        let result = store
            .update_verification(
                "shared",
                VerificationUpdate {
                    value: "new-proof".into(),
                    updated_at: date(3).into(),
                    ..Default::default()
                },
            )
            .await;
        if reject {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "verification-output-rejected")
            );
        } else {
            assert_eq!(required(result?)?.fields()?, expected_first);
        }
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?,
            ["input", "output"]
        );
        reject_output.store(false, Ordering::SeqCst);
        assert_eq!(
            required(store.get_verification_by_identifier("shared").await?)?.fields()?,
            expected_first
        );
        assert_eq!(
            required(store.get_verification_including_expired("shared").await?)?.fields()?,
            expected_second
        );
        assert_eq!(
            required(store.get_verification_by_identifier("other").await?)?,
            retained
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_verification_latest_and_consume_place_null_below_negative_numbers() -> AuthResult<()>
{
    let events = Events::default();
    let output_events = events.clone();
    let mut config = mapped();
    let created_at = required(config.verification.additional_fields.get_mut("createdAt"))?;
    created_at.field_type = UserFieldType::Number;
    created_at.transform = Some(FieldTransforms {
        input: None,
        output: Some(UserFieldTransform::new(move |value| {
            push(&output_events, "output")?;
            Ok(value)
        })),
    });
    let store: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
        Arc::new(EphemeralStore::new(Arc::new(config)));
    let mut null = input("null", "shared", "null-proof", 0, 100);
    null.created_at = SchemaValue::from_field(FieldValue::Null);
    let _ = store.create_verification(null).await?;
    let mut negative = input("negative", "shared", "negative-proof", 0, 100);
    negative.created_at = SchemaValue::from_field(FieldValue::Number(-1.0));
    let latest = store.create_verification(negative).await?;
    let retained = store
        .create_verification(input("retained", "other", "retained-proof", 3, 100))
        .await?;
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?
        .clear();
    assert_eq!(
        required(store.get_verification_including_expired("shared").await?)?,
        latest
    );
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?,
        ["output"]
    );
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?
        .clear();
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let _ =
            tasks.spawn(async move { store.consume_verification_by_identifier("shared").await });
    }
    let mut consumed = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(row) = result.map_err(|error| AuthError::internal(error.to_string()))?? {
            consumed.push(row);
        }
    }
    assert_eq!(consumed, [latest]);
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Verification trace lock poisoned"))?,
        ["output", "output"]
    );
    assert!(
        store
            .get_verification_by_identifier("shared")
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_verification_by_identifier("other").await?)?,
        retained
    );
    Ok(())
}
