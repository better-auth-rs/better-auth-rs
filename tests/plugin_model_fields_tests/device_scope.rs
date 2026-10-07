use super::*;
use better_auth_core::{CreateDeviceCode, DeviceCode, SchemaValue, UpdateDeviceCode};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Default)]
struct Trace {
    events: Vec<String>,
    projected: FieldValue,
}

fn describe(value: &Option<Value>) -> String {
    presence::describe(value)
}

#[expect(
    clippy::expect_used,
    reason = "The onUpdate trace must remain unpoisoned so the contract retains every callback event"
)]
fn policy(trace: Arc<Mutex<Trace>>, failure: Arc<AtomicU8>) -> UserFieldConfig {
    let update_trace = trace.clone();
    let output_trace = trace.clone();
    let output_failure = failure.clone();
    UserFieldConfig {
        required: Some(false),
        default_value: Some(" Default ".into()),
        on_update: Some(Arc::new(move || {
            update_trace
                .lock()
                .expect("Device scope update trace lock poisoned")
                .events
                .push("onUpdate".into());
            Ok(" Renewed ".into())
        })),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&trace)?
                    .events
                    .push(format!("input:{}", describe(&value.json()?)));
                if failure.load(Ordering::SeqCst) == 1 {
                    return Err(AuthError::internal("ordinary scope input error"));
                }
                Ok(match value {
                    FieldValue::String(text) => text.trim().into(),
                    other => other,
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let mut trace = trace_lock(&output_trace)?;
                trace
                    .events
                    .push(format!("output:{}", describe(&value.json()?)));
                if output_failure.load(Ordering::SeqCst) == 2 {
                    return Err(AuthError::internal("ordinary scope output error"));
                }
                let projected = match value {
                    FieldValue::String(text) => format!("{text}:out").into(),
                    other => other,
                };
                trace.projected.clone_from(&projected);
                Ok(projected)
            })),
        }),
        ..Default::default()
    }
}

fn input(label: &str, scope: SchemaValue<Option<String>>) -> AuthResult<CreateDeviceCode> {
    Ok(CreateDeviceCode {
        additional_fields: Default::default(),
        device_code: format!("ordinary-device:{label}"),
        user_code: format!("ordinary-user:{label}"),
        user_id: None,
        expires_at: chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .map_err(|error| AuthError::internal(format!("Invalid fixture timestamp: {error}")))?
            .with_timezone(&chrono::Utc)
            .into(),
        status: "pending".into(),
        last_polled_at: None,
        polling_interval: None,
        client_id: None,
        scope,
    })
}

fn observation(name: &str, row: Option<&DeviceCode>, trace: &Mutex<Trace>) -> AuthResult<Value> {
    let trace = std::mem::take(&mut *trace_lock(trace)?);
    // Boolean store methods expose projection through the callback, not their return value.
    let scope = match row {
        Some(row) => row.scope.json()?,
        None => trace.projected.json()?,
    };
    Ok(json!({"name": name, "scope": describe(&scope), "events": trace.events}))
}

async fn stored_scope<S: AuthSchema>(raw: &dyn AuthStore<S>, label: &str) -> AuthResult<String> {
    let row = raw
        .get_device_code_by_device_code(&format!("ordinary-device:{label}"))
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    Ok(describe(&row.scope.json()?))
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, backend: &str) -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let failure = Arc::new(AtomicU8::new(0));
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(
            EntityRole::DeviceCode,
            fields("scope", policy(trace.clone(), failure.clone())),
        )]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "scope-owner").await?;
    let store = auth.store();
    let mut cases = Vec::new();
    let mut rows = Vec::new();
    for (name, scope) in [
        ("supplied", Some(" Read ".into()).into()),
        ("omitted", SchemaValue::Undefined),
        ("null", None.into()),
    ] {
        let row = store.create_device_code(input(name, scope)?).await?;
        let mut case = observation(&format!("create {name}"), Some(&row), &trace)?;
        let _ = required(case.as_object_mut(), "Expected a model observation object")?.insert(
            "stored".to_owned(),
            json!(stored_scope(raw.as_ref(), name).await?),
        );
        cases.push(case);
        rows.push(row);
    }
    let id = required(rows.first(), "Expected the supplied Device scope case")?
        .id
        .clone();
    let found = store
        .get_device_code_by_device_code("ordinary-device:supplied")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    cases.push(observation("find deviceCode", Some(&found), &trace)?);
    let found = store
        .get_device_code_by_user_code("ordinary-user:supplied")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    cases.push(observation("find userCode", Some(&found), &trace)?);
    for (name, update) in [
        (
            "supplied",
            UpdateDeviceCode {
                scope: Some(" Changed ".into()).into(),
                ..Default::default()
            },
        ),
        (
            "omitted",
            UpdateDeviceCode {
                last_polled_at: Some(Some(
                    chrono::DateTime::parse_from_rfc3339("2029-01-01T00:00:00Z")
                        .map_err(|error| {
                            AuthError::internal(format!("Invalid fixture timestamp: {error}"))
                        })?
                        .with_timezone(&chrono::Utc)
                        .into(),
                )),
                ..Default::default()
            },
        ),
        (
            "null",
            UpdateDeviceCode {
                scope: None.into(),
                ..Default::default()
            },
        ),
    ] {
        let row = store.update_device_code(&id, update).await?;
        let mut case = observation(&format!("update {name}"), Some(&row), &trace)?;
        let _ = required(case.as_object_mut(), "Expected a model observation object")?.insert(
            "stored".to_owned(),
            json!(stored_scope(raw.as_ref(), "supplied").await?),
        );
        cases.push(case);
    }
    let success = store.claim_device_code(&id, &owner).await?;
    let mut case = observation("claim", None, &trace)?;
    let _ = required(case.as_object_mut(), "Expected a model observation object")?
        .insert("success".to_owned(), json!(success));
    let _ = required(case.as_object_mut(), "Expected a model observation object")?.insert(
        "stored".to_owned(),
        json!(stored_scope(raw.as_ref(), "supplied").await?),
    );
    cases.push(case);
    for name in ["conditional update", "conditional no match"] {
        let success = store
            .update_device_code_if_status(
                &id,
                "pending",
                UpdateDeviceCode {
                    status: Some("approved".into()),
                    ..Default::default()
                },
            )
            .await?;
        let mut case = observation(name, None, &trace)?;
        let _ = required(case.as_object_mut(), "Expected a model observation object")?
            .insert("success".to_owned(), json!(success));
        let _ = required(case.as_object_mut(), "Expected a model observation object")?.insert(
            "stored".to_owned(),
            json!(stored_scope(raw.as_ref(), "supplied").await?),
        );
        cases.push(case);
    }
    for (mode, stage) in [(1, "input"), (2, "output")] {
        failure.store(mode, Ordering::SeqCst);
        let error = store
            .update_device_code(
                &id,
                UpdateDeviceCode {
                    scope: Some(format!(" {stage} value ")).into(),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?;
        let same_error = matches!(error, AuthError::Internal(message) if message == format!("ordinary scope {stage} error"));
        let events = std::mem::take(&mut *trace_lock(&trace)?).events;
        cases.push(json!({
            "name": format!("{stage} error"), "sameError": same_error,
            "stored": stored_scope(raw.as_ref(), "supplied").await?, "events": events,
        }));
    }
    let fixture: Value = serde_json::from_str(include_str!("../fixtures/device-scope-1.7.6.json"))?;
    let expected = required(
        fixture.get("backends").and_then(Value::as_array),
        "Expected captured Device scope backends",
    )?
    .iter()
    .find(|item| item.get("backend") == Some(&json!(backend)))
    .ok_or_else(|| AuthError::internal("Missing captured Device scope backend"))?;
    assert_eq!(
        &json!(cases),
        required(
            expected.get("cases"),
            "Expected captured Device scope cases"
        )?
    );
    Ok(())
}

async fn awaited_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let (sender, mut calls) = mpsc::unbounded_channel();
    let policy = UserFieldConfig {
        required: Some(false),
        on_update: Some(Arc::new(|| Ok("Renewed".into()))),
        transform: Some(FieldTransforms {
            input: Some(awaited(sender.clone(), "input")),
            output: Some(awaited(sender, "output")),
        }),
        ..Default::default()
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(
            EntityRole::DeviceCode,
            fields("scope", policy),
        )]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "scope-await-owner").await?;
    let store = auth.store().clone();
    let pending = tokio::spawn(async move {
        store
            .create_device_code(input("await", Some("Waiting".into()).into())?)
            .await
    });
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(
        (call.stage, call.value),
        ("input", FieldValue::from("Waiting"))
    );
    assert!(
        raw.get_device_code_by_device_code("ordinary-device:await")
            .await?
            .is_none()
    );
    assert!(!pending.is_finished());
    call.reply
        .send(Ok(FieldValue::from("Stored")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(
        (call.stage, call.value),
        ("output", FieldValue::from("Stored"))
    );
    assert_eq!(stored_scope(raw.as_ref(), "await").await?, "\"Stored\"");
    assert!(!pending.is_finished());
    call.reply
        .send(Ok(FieldValue::from("Projected")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let row = pending
        .await
        .map_err(|error| AuthError::internal(format!("Model field task failed: {error}")))??;
    assert_eq!(row.scope.json()?, Some(json!("Projected")));

    for (claim, previous, stored) in [(true, "Stored", "Claimed"), (false, "Claimed", "Changed")] {
        let store = auth.store().clone();
        let id = row.id.clone();
        let owner = owner.clone();
        let pending = tokio::spawn(async move {
            if claim {
                store.claim_device_code(&id, &owner).await
            } else {
                store
                    .update_device_code_if_status(
                        &id,
                        "pending",
                        UpdateDeviceCode {
                            status: Some("approved".into()),
                            ..Default::default()
                        },
                    )
                    .await
            }
        });
        let call = required(calls.recv().await, "Expected the next field callback")?;
        assert_eq!(
            (call.stage, call.value),
            ("input", FieldValue::from("Renewed"))
        );
        assert_eq!(
            stored_scope(raw.as_ref(), "await").await?,
            json!(previous).to_string()
        );
        assert!(!pending.is_finished());
        call.reply
            .send(Ok(FieldValue::from(stored)))
            .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
        let call = required(calls.recv().await, "Expected the next field callback")?;
        assert_eq!(
            (call.stage, call.value),
            ("output", FieldValue::from(stored))
        );
        assert_eq!(
            stored_scope(raw.as_ref(), "await").await?,
            json!(stored).to_string()
        );
        assert!(!pending.is_finished());
        call.reply
            .send(Ok(FieldValue::from("Projected")))
            .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
        assert!(
            pending.await.map_err(|error| AuthError::internal(format!(
                "Model field task failed: {error}"
            )))??
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_scope_matches_pinned_adapter_contract() -> AuthResult<()> {
    contract(memory(), "memory").await
}

#[tokio::test]
async fn sqlite_device_scope_matches_pinned_adapter_contract() -> AuthResult<()> {
    contract(sqlite().await?, "sqlite").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_device_scope_preserves_storage_and_projection()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait};

    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_device_scope_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let _ = database
        .execute_unprepared(&format!("SET search_path TO {schema}"))
        .await?;
    let worker = database.clone();
    let result = tokio::spawn(async move {
        migrator::run_migrations(&worker).await?;
        let raw: Arc<dyn AuthStore<BundledSchema>> =
            Arc::new(SeaOrmStore::<BundledSchema>::new(config(), worker));
        // Reuse the captured SQL contract without claiming an upstream PostgreSQL capture.
        contract(raw.clone(), "sqlite").await?;
        super::device_consumption::contract(raw.clone()).await?;
        awaited_contract(raw).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let _ = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    database.close().await?;
    result??;
    Ok(())
}

#[tokio::test]
async fn memory_device_scope_callbacks_await_outside_storage_locks() -> AuthResult<()> {
    awaited_contract(memory()).await
}

#[tokio::test]
async fn sqlite_device_scope_callbacks_surround_real_storage() -> AuthResult<()> {
    awaited_contract(sqlite().await?).await
}

#[tokio::test]
async fn unsupported_device_scope_declarations_fail_at_initialization() {
    let result = BetterAuth::new(config())
        .store_arc(memory())
        .plugin(Fields(vec![(
            EntityRole::DeviceCode,
            fields(
                "scope",
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    required: Some(false),
                    ..Default::default()
                },
            ),
        )]))
        .build()
        .await;
    assert!(matches!(result, Err(AuthError::Config(_))));
}
