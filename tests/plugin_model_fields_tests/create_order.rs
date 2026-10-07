use super::*;
use better_auth_core::id::{IdGeneration, IdGenerator};
use chrono::Utc;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let (sender, mut calls) = mpsc::unbounded_channel();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let policy = UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new_async(move |value| {
                let sender = sender.clone();
                let trace = input_trace.clone();
                async move {
                    trace_lock(&trace)?.push("name:input".to_owned());
                    let entered_at = Utc::now();
                    let (reply, result) = oneshot::channel();
                    sender
                        .send((entered_at, reply))
                        .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
                    result
                        .await
                        .map_err(|_| AuthError::internal("Creation callback reply missing"))?;
                    Ok(match value {
                        FieldValue::Undefined => FieldValue::Undefined,
                        value => {
                            required(value.as_str(), "Expected a string field callback value")?
                                .trim()
                                .into()
                        }
                    })
                }
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output_trace)?.push("name:output".to_owned());
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
    };
    let mut config = config();
    let generator_trace = trace.clone();
    let sequence = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            trace_lock(&generator_trace)?.push(format!("id:{}", request.model));
            Ok(Some(format!(
                "ordinary-create-{}",
                sequence.fetch_add(1, Ordering::SeqCst)
            )))
        })));
    let auth = BetterAuth::new(config)
        .store_arc(raw.clone())
        .plugin(Fields(vec![
            (EntityRole::Passkey, fields("name", policy.clone())),
            (EntityRole::ApiKey, fields("name", policy)),
        ]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "create-order").await?;
    for role in [EntityRole::Passkey, EntityRole::ApiKey] {
        trace_lock(&trace)?.clear();
        let store = auth.store().clone();
        let owner = owner.clone();
        let pending = tokio::spawn(async move {
            if role == EntityRole::Passkey {
                let row = store.create_passkey(input(&owner, " Desk ")).await?;
                Ok((
                    row.created_at.typed()?.clone().ok_or_else(|| {
                        AuthError::internal("Legacy passkey creation must return createdAt")
                    })?,
                    row.name,
                ))
            } else {
                let row = store
                    .create_api_key(api_key::input(Some(" Desk "), "ordinary-order"))
                    .await?;
                Ok::<_, AuthError>((row.created_at, row.name))
            }
        });
        let (entered_at, reply) = required(calls.recv().await, "Expected the next field callback")?;
        assert_eq!(*trace_lock(&trace)?, ["name:input"]);
        if role == EntityRole::Passkey {
            assert!(
                raw.get_passkey_by_credential_id("credential: Desk ")
                    .await?
                    .is_none()
            );
        } else {
            assert!(raw.get_api_key_by_hash("ordinary-order").await?.is_none());
        }
        reply
            .send(())
            .map_err(|_| AuthError::internal("Field callback receiver closed"))?;
        let (created_at, name) = pending
            .await
            .map_err(|error| AuthError::internal(format!("Model field task failed: {error}")))??;
        assert!(
            created_at.milliseconds() <= entered_at.timestamp_millis() as f64,
            "creation timestamp must precede the awaited name callback"
        );
        assert_eq!(name.typed()?.as_deref(), Some("Desk:out"));
        let model = if role == EntityRole::Passkey {
            "passkey"
        } else {
            "apikey"
        };
        assert_eq!(
            *trace_lock(&trace)?,
            [
                "name:input".to_owned(),
                format!("id:{model}"),
                "name:output".to_owned()
            ]
        );
        if role == EntityRole::Passkey {
            let stored = raw
                .get_passkey_by_credential_id("credential: Desk ")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
            assert_eq!(
                stored
                    .created_at
                    .typed()?
                    .clone()
                    .ok_or_else(|| AuthError::internal(
                        "Legacy passkey storage must retain createdAt"
                    ))?,
                created_at
            );
            assert_eq!(stored.name.typed()?.as_deref(), Some("Desk"));
        } else {
            let stored = raw
                .get_api_key_by_hash("ordinary-order")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the stored model record"))?;
            assert_eq!(stored.created_at, created_at);
            assert_eq!(stored.name.typed()?.as_deref(), Some("Desk"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_creation_samples_timestamps_before_names_and_generates_ids_after_names()
-> AuthResult<()> {
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_creation_samples_timestamps_before_names_and_generates_ids_after_names()
-> AuthResult<()> {
    contract(sqlite().await?).await
}
