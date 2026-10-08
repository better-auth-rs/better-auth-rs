use super::*;
use better_auth_core::{CreateApiKey, UpdateApiKey, store::ApiKeyUsageWrite};

pub(super) fn policy(events: Arc<Mutex<Vec<String>>>) -> UserFieldConfig {
    let output = events.clone();
    UserFieldConfig {
        required: Some(true),
        default_value: Some("Fallback".into()),
        on_update: Some(Arc::new(|| Ok("Renewed".into()))),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&events)?.push(format!(
                    "input:{}",
                    required(value.json()?, "Expected a present JSON callback value")?
                ));
                if value == FieldValue::from("input-error") {
                    return Err(AuthError::internal("ordinary API Key input error"));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => required(value.as_str(), "Expected a string field callback value")?
                        .trim()
                        .into(),
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output)?.push(format!(
                    "output:{}",
                    required(value.json()?, "Expected a present JSON callback value")?
                ));
                if value == FieldValue::from("output-error") {
                    return Err(AuthError::internal("ordinary API Key output error"));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!(
                        "{}:out",
                        required(value.as_str(), "Expected a string field callback value")?
                    )
                    .into(),
                })
            })),
        }),
        ..Default::default()
    }
}

pub(super) fn input(name: Option<&str>, hash: &str) -> CreateApiKey {
    CreateApiKey {
        additional_fields: Default::default(),
        reference_id: "ordinary-owner".into(),
        config_id: "default".into(),
        name: name.map(str::to_owned).into(),
        key_hash: hash.into(),
        start: None,
        prefix: None,
        expires_at: None,
        remaining: Some(10.0),
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000.0),
        rate_limit_max: Some(3.0),
        refill_interval: None,
        refill_amount: None,
        permissions: None.into(),
        metadata: None,
        enabled: true.into(),
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(
            EntityRole::ApiKey,
            fields("name", policy(events.clone())),
        )]))
        .build()
        .await?;
    let store = auth.store();
    let created = store
        .create_api_key(input(Some("  Desk  "), "ordinary-first"))
        .await?;
    assert_eq!(created.name.typed()?.as_deref(), Some("Desk:out"));
    assert_eq!(
        *trace_lock(&events)?,
        ["input:\"  Desk  \"", "output:\"Desk\""]
    );
    assert_eq!(
        raw.get_api_key_by_hash("ordinary-first")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Desk")
    );
    assert_eq!(created.key_hash, "ordinary-first");
    assert_eq!(created.reference_id, "ordinary-owner");
    let fallback = store
        .create_api_key(input(None, "ordinary-default"))
        .await?;
    assert_eq!(fallback.name.typed()?.as_deref(), Some("Fallback:out"));
    assert_eq!(
        raw.get_api_key_by_hash("ordinary-default")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Fallback")
    );
    let updated = store
        .update_api_key(
            &created.id,
            UpdateApiKey {
                name: Some(Some("  Mobile  ".into()).into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.name.typed()?.as_deref(), Some("Mobile:out"));
    for found in [
        store
            .get_api_key_by_id(created.id.typed()?)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?,
        store
            .get_api_key_by_id_value(&created.id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?,
        store
            .get_api_key_by_hash("ordinary-first")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?,
    ] {
        assert_eq!(found.name.typed()?.as_deref(), Some("Mobile:out"));
    }
    trace_lock(&events)?.clear();
    let list = store
        .find_api_keys_by_reference("ordinary-owner", Some(("name", "asc")))
        .await?;
    assert_eq!(
        list.iter()
            .map(|key| key.name.typed().map(|name| name.as_deref()))
            .collect::<AuthResult<Vec<_>>>()?,
        [Some("Fallback:out"), Some("Mobile:out")]
    );
    assert_eq!(
        *trace_lock(&events)?,
        ["output:\"Fallback\"", "output:\"Mobile\""]
    );
    trace_lock(&events)?.clear();
    assert_eq!(
        store.count_api_keys_by_reference("ordinary-owner").await?,
        2
    );
    assert!(trace_lock(&events)?.is_empty());

    let now = chrono::Utc::now();
    let writes = [
        (ApiKeyUsageWrite::Decrement, 9.0, 0.0, false),
        (
            ApiKeyUsageWrite::StartWindow {
                previous_before: None,
                at: now,
            },
            9.0,
            1.0,
            true,
        ),
        (
            ApiKeyUsageWrite::IncrementWindow {
                previous_after: (now - chrono::Duration::seconds(1)).into(),
                maximum: 3.0.into(),
                at: now,
            },
            9.0,
            2.0,
            true,
        ),
        (ApiKeyUsageWrite::LastRequest(now), 9.0, 2.0, true),
        (ApiKeyUsageWrite::UpdatedAt(now), 9.0, 2.0, true),
        (
            ApiKeyUsageWrite::Refill {
                previous: FieldValue::Null,
                remaining: 8.0,
                at: now,
            },
            8.0,
            2.0,
            true,
        ),
    ];
    for (write, remaining, count, set) in writes {
        trace_lock(&events)?.clear();
        let row = store
            .write_api_key_usage(&created.id, write)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
        assert_eq!(row.remaining, Some(remaining));
        assert_eq!(row.request_count, Some(count));
        assert_eq!(row.key_hash, created.key_hash);
        assert_eq!(row.reference_id, created.reference_id);
        if set {
            assert_eq!(row.name.typed()?.as_deref(), Some("Renewed:out"));
            assert_eq!(
                *trace_lock(&events)?,
                ["input:\"Renewed\"", "output:\"Renewed\""]
            );
        } else {
            assert_eq!(row.name.typed()?.as_deref(), Some("Mobile:out"));
            assert_eq!(*trace_lock(&events)?, ["output:\"Mobile\""]);
        }
        let stored = raw
            .get_api_key_by_hash("ordinary-first")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
        assert_eq!(stored.remaining, Some(remaining));
        assert_eq!(stored.request_count, Some(count));
        assert_eq!(
            stored.name.typed()?.as_deref(),
            Some(if set { "Renewed" } else { "Mobile" })
        );
    }
    original_error(
        store
            .update_api_key(
                &created.id,
                UpdateApiKey {
                    name: Some(Some("input-error".into()).into()),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary API Key input error",
    );
    assert_eq!(
        raw.get_api_key_by_hash("ordinary-first")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Renewed")
    );
    original_error(
        store
            .update_api_key(
                &created.id,
                UpdateApiKey {
                    name: Some(Some("output-error".into()).into()),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary API Key output error",
    );
    let stored = raw
        .get_api_key_by_hash("ordinary-first")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    assert_eq!(stored.name.typed()?.as_deref(), Some("output-error"));
    assert_eq!(
        (*stored.remaining.typed()?, *stored.request_count.typed()?),
        (Some(8.0), Some(2.0))
    );
    original_error(
        store
            .create_api_key(input(Some("input-error"), "ordinary-input-error"))
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary API Key input error",
    );
    assert!(
        raw.get_api_key_by_hash("ordinary-input-error")
            .await?
            .is_none()
    );
    original_error(
        store
            .create_api_key(input(Some("output-error"), "ordinary-output-error"))
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary API Key output error",
    );
    assert_eq!(
        raw.get_api_key_by_hash("ordinary-output-error")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("output-error")
    );
    Ok(())
}

async fn awaited_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let (sender, mut calls) = mpsc::unbounded_channel();
    let policy = UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(awaited(sender.clone(), "input")),
            output: Some(awaited(sender, "output")),
        }),
        ..Default::default()
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(EntityRole::ApiKey, fields("name", policy))]))
        .build()
        .await?;
    let store = auth.store().clone();
    let pending = tokio::spawn(async move {
        store
            .create_api_key(input(Some("Waiting"), "ordinary-await"))
            .await
    });
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(
        (call.stage, call.value),
        ("input", FieldValue::from("Waiting"))
    );
    assert!(raw.get_api_key_by_hash("ordinary-await").await?.is_none());
    call.reply
        .send(Ok(FieldValue::from("Stored")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(
        (call.stage, call.value),
        ("output", FieldValue::from("Stored"))
    );
    assert_eq!(
        raw.get_api_key_by_hash("ordinary-await")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .name
            .typed()?
            .as_deref(),
        Some("Stored")
    );
    call.reply
        .send(Ok(FieldValue::from("Projected")))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    assert_eq!(
        pending
            .await
            .map_err(|error| AuthError::internal(format!("Model field task failed: {error}")))??
            .name
            .typed()?
            .as_deref(),
        Some("Projected")
    );
    Ok(())
}

#[tokio::test]
async fn memory_api_key_names_use_real_storage_and_preserve_usage_writes() -> AuthResult<()> {
    contract(memory()).await
}
#[tokio::test]
async fn sqlite_api_key_names_use_real_storage_and_preserve_usage_writes() -> AuthResult<()> {
    contract(sqlite().await?).await
}
#[tokio::test]
async fn memory_api_key_names_await_outside_storage_locks() -> AuthResult<()> {
    awaited_contract(memory()).await
}
#[tokio::test]
async fn sqlite_api_key_names_await_at_the_storage_boundary() -> AuthResult<()> {
    awaited_contract(sqlite().await?).await
}
