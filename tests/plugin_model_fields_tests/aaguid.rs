use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const FIRST: &str = "EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4";
const UPDATED: &str = "DD4EC289-E01D-41C9-BB89-70FA845D4BF2";

fn policy(
    field: &'static str,
    trace: Arc<Mutex<Vec<String>>>,
    failure: Arc<AtomicUsize>,
) -> UserFieldConfig {
    let output_trace = trace.clone();
    let output_failure = failure.clone();
    UserFieldConfig {
        required: Some(true),
        default_value: (field == "aaguid").then(|| FIRST.into()),
        on_update: (field == "aaguid").then(|| {
            Arc::new(|| Ok(UPDATED.into())) as Arc<dyn Fn() -> AuthResult<FieldValue> + Send + Sync>
        }),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&trace)?.push(format!("input:{field}"));
                if field == "aaguid" && failure.load(Ordering::SeqCst) == 1 {
                    return Err(AuthError::internal("ordinary AAGUID input error"));
                }
                let text = required(value.as_str(), "Expected a string field callback value")?
                    .trim()
                    .to_owned();
                Ok(if field == "aaguid" {
                    text.to_ascii_lowercase()
                } else {
                    text
                }
                .into())
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let text =
                    required(value.as_str(), "Expected a string field callback value")?.to_owned();
                trace_lock(&output_trace)?.push(format!("output:{field}:{text}"));
                if field == "aaguid" && output_failure.load(Ordering::SeqCst) == 2 {
                    return Err(AuthError::internal("ordinary AAGUID output error"));
                }
                Ok(if field == "aaguid" {
                    text.to_ascii_uppercase()
                } else {
                    format!("{text}:out")
                }
                .into())
            })),
        }),
        ..Default::default()
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let failure = Arc::new(AtomicUsize::new(0));
    let config_fields = UserConfig {
        additional_fields: Some(
            [
                (
                    "aaguid".into(),
                    policy("aaguid", trace.clone(), failure.clone()),
                ),
                (
                    "name".into(),
                    policy("name", trace.clone(), failure.clone()),
                ),
            ]
            .into(),
        ),
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(EntityRole::Passkey, config_fields)]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "aaguid").await?;
    let mut data = input(&owner, " Desk ");
    data.aaguid = Some(format!(" {FIRST} ")).into();
    let created = auth.store().create_passkey(data).await?;
    assert_eq!(created.name.typed()?.as_deref(), Some("Desk:out"));
    assert_eq!(created.aaguid.typed()?.as_deref(), Some(FIRST));
    assert_eq!(
        *trace_lock(&trace)?,
        [
            "input:name".into(),
            "input:aaguid".into(),
            "output:name:Desk".into(),
            format!("output:aaguid:{}", FIRST.to_ascii_lowercase())
        ]
    );
    let id = created.id.typed()?.clone();
    let stored = raw
        .get_passkey_by_id(&id)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    assert_eq!(stored.aaguid, Some(FIRST.to_ascii_lowercase()));
    assert_eq!(stored.credential, created.credential);

    let defaulted = auth
        .store()
        .create_passkey(input(&owner, " Default "))
        .await?;
    assert_eq!(defaulted.aaguid.typed()?.as_deref(), Some(FIRST));
    trace_lock(&trace)?.clear();
    let updated = auth.store().update_passkey_name(&id, " Mobile ").await?;
    assert_eq!(updated.aaguid.typed()?.as_deref(), Some(UPDATED));
    assert_eq!(
        *trace_lock(&trace)?,
        [
            "input:name".into(),
            "input:aaguid".into(),
            "output:name:Mobile".into(),
            format!("output:aaguid:{}", UPDATED.to_ascii_lowercase())
        ]
    );
    trace_lock(&trace)?.clear();
    let updated = auth
        .store()
        .update_passkey_authentication(
            &created.id,
            UpdatePasskeyAuthentication::Legacy {
                credential: created.credential.typed()?.clone(),
                counter: 1,
                backed_up: *created.backed_up.typed()?,
                device_type: created.device_type.typed()?.clone(),
            },
        )
        .await?;
    assert_eq!(updated.counter, 1);
    assert_eq!(updated.name.typed()?.as_deref(), Some("Mobile:out"));
    assert_eq!(
        *trace_lock(&trace)?,
        [
            "input:aaguid".into(),
            "output:name:Mobile".into(),
            format!("output:aaguid:{}", UPDATED.to_ascii_lowercase())
        ]
    );
    for found in [
        auth.store()
            .get_passkey_by_id(&id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?,
        auth.store()
            .get_passkey_by_credential_id(created.credential_id.typed()?)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?,
    ] {
        assert_eq!(found.aaguid.typed()?.as_deref(), Some(UPDATED));
    }
    trace_lock(&trace)?.clear();
    let rows = auth.store().list_passkeys_by_user(&owner).await?;
    assert_eq!(rows.len(), 2);
    let expected_names: Vec<_> = rows
        .iter()
        .map(|row| {
            if row.id == created.id {
                "Mobile"
            } else {
                assert_eq!(row.id, defaulted.id);
                "Default"
            }
        })
        .collect();
    let expected_aaguids: Vec<_> = rows
        .iter()
        .map(|row| if row.id == created.id { UPDATED } else { FIRST })
        .collect();
    let expected: Vec<_> = expected_names
        .iter()
        .map(|name| format!("output:name:{name}"))
        .chain(
            expected_aaguids
                .iter()
                .map(|value| format!("output:aaguid:{}", value.to_ascii_lowercase())),
        )
        .collect();
    assert_eq!(*trace_lock(&trace)?, expected);
    for ((row, name), aaguid) in rows.iter().zip(expected_names).zip(expected_aaguids) {
        assert_eq!(row.name, Some(format!("{name}:out")));
        assert_eq!(row.aaguid.typed()?.as_deref(), Some(aaguid));
    }

    let rollback_owner = owner.clone();
    let rollback: AuthResult<()> =
        better_auth_core::store::transaction(auth.store().as_ref(), |tx| {
            Box::pin(async move {
                let row = tx
                    .create_passkey(input(&rollback_owner, "AaguidRollback"))
                    .await?;
                assert_eq!(row.aaguid.typed()?.as_deref(), Some(FIRST));
                Err(AuthError::internal("ordinary AAGUID rollback"))
            })
        })
        .await;
    original_error(
        rollback
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary AAGUID rollback",
    );
    assert!(
        raw.get_passkey_by_credential_id("credential:AaguidRollback")
            .await?
            .is_none()
    );
    failure.store(1, Ordering::SeqCst);
    original_error(
        auth.store()
            .update_passkey_name(&id, "Input failure")
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary AAGUID input error",
    );
    let stored = raw
        .get_passkey_by_id(&id)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    assert_eq!(stored.name.typed()?.as_deref(), Some("Mobile"));
    assert_eq!(stored.counter, 1);
    failure.store(2, Ordering::SeqCst);
    original_error(
        auth.store()
            .update_passkey_name(&id, " Output ")
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the model operation to fail"))?,
        "ordinary AAGUID output error",
    );
    let stored = raw
        .get_passkey_by_id(&id)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
    assert_eq!(stored.name.typed()?.as_deref(), Some("Output"));
    assert_eq!(stored.aaguid, Some(UPDATED.to_ascii_lowercase()));
    assert_eq!(stored.counter, 1);
    failure.store(0, Ordering::SeqCst);

    for selected in ["name", "aaguid"] {
        let auth = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(Fields(vec![(
                EntityRole::Passkey,
                fields(selected, policy(selected, trace.clone(), failure.clone())),
            )]))
            .build()
            .await?;
        let mut data = input(&owner, &format!(" Solo {selected} "));
        data.aaguid = Some(FIRST.into()).into();
        let expected_name = if selected == "name" {
            format!("Solo {selected}:out")
        } else {
            format!(" Solo {selected} ")
        };
        let row = auth.store().create_passkey(data).await?;
        assert_eq!(row.name, Some(expected_name));
        assert_eq!(row.aaguid.typed()?.as_deref(), Some(FIRST));
    }
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
        .plugin(Fields(vec![(
            EntityRole::Passkey,
            fields("aaguid", policy),
        )]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "aaguid-await").await?;
    let store = auth.store().clone();
    let pending = tokio::spawn(async move {
        let mut data = input(&owner, "AaguidAwait");
        data.aaguid = Some(FIRST.into()).into();
        store.create_passkey(data).await
    });
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!((call.stage, call.value), ("input", FieldValue::from(FIRST)));
    assert!(
        raw.get_passkey_by_credential_id("credential:AaguidAwait")
            .await?
            .is_none()
    );
    let stored_aaguid = FieldValue::from(FIRST.to_ascii_lowercase());
    call.reply
        .send(Ok(stored_aaguid))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let call = required(calls.recv().await, "Expected the next field callback")?;
    assert_eq!(
        (call.stage, call.value),
        ("output", FieldValue::from(FIRST.to_ascii_lowercase()))
    );
    assert_eq!(
        raw.get_passkey_by_credential_id("credential:AaguidAwait")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored model record"))?
            .aaguid,
        Some(FIRST.to_ascii_lowercase())
    );
    call.reply
        .send(Ok(FieldValue::from(FIRST)))
        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
    let row = pending
        .await
        .map_err(|error| AuthError::internal(format!("Model field task failed: {error}")))??;
    assert_eq!(row.name.typed()?.as_deref(), Some("AaguidAwait"));
    assert_eq!(row.aaguid.typed()?.as_deref(), Some(FIRST));
    Ok(())
}

#[tokio::test]
async fn memory_aaguid_policies_preserve_typed_patches_and_batch_order() -> AuthResult<()> {
    contract(memory()).await
}
#[tokio::test]
async fn sqlite_aaguid_policies_preserve_typed_patches_and_batch_order() -> AuthResult<()> {
    contract(sqlite().await?).await
}
#[tokio::test]
async fn memory_aaguid_callbacks_run_outside_storage_locks() -> AuthResult<()> {
    awaited_contract(memory()).await
}
#[tokio::test]
async fn sqlite_aaguid_callbacks_surround_actual_storage() -> AuthResult<()> {
    awaited_contract(sqlite().await?).await
}
