use super::*;
use better_auth_core::id::{IdGeneration, IdGenerator};
use chrono::{DateTime, Utc};
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
                    trace.lock().unwrap().push("name:input".to_owned());
                    let entered_at = Utc::now();
                    let (reply, result) = oneshot::channel();
                    sender.send((entered_at, reply)).unwrap();
                    result.await.unwrap();
                    Ok(value.map(|value| json!(value.as_str().unwrap().trim())))
                }
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output_trace.lock().unwrap().push("name:output".to_owned());
                Ok(value.map(|value| json!(format!("{}:out", value.as_str().unwrap()))))
            })),
        }),
        ..Default::default()
    };
    let mut config = config();
    let generator_trace = trace.clone();
    let sequence = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            generator_trace
                .lock()
                .unwrap()
                .push(format!("id:{}", request.model));
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
        trace.lock().unwrap().clear();
        let store = auth.store().clone();
        let owner = owner.clone();
        let pending = tokio::spawn(async move {
            if role == EntityRole::Passkey {
                let row = store.create_passkey(input(&owner, " Desk ")).await?;
                Ok((row.created_at, row.name))
            } else {
                let row = store
                    .create_api_key(api_key::input(Some(" Desk "), "ordinary-order"))
                    .await?;
                Ok::<_, AuthError>((
                    DateTime::parse_from_rfc3339(&row.created_at)
                        .unwrap()
                        .to_utc(),
                    row.name,
                ))
            }
        });
        let (entered_at, reply) = calls.recv().await.unwrap();
        assert_eq!(*trace.lock().unwrap(), ["name:input"]);
        if role == EntityRole::Passkey {
            assert!(
                raw.get_passkey_by_credential_id("credential: Desk ")
                    .await?
                    .is_none()
            );
        } else {
            assert!(raw.get_api_key_by_hash("ordinary-order").await?.is_none());
        }
        reply.send(()).unwrap();
        let (created_at, name) = pending.await.unwrap()?;
        assert!(
            created_at <= entered_at,
            "creation timestamp must precede the awaited name callback"
        );
        assert_eq!(name.as_deref(), Some("Desk:out"));
        let model = if role == EntityRole::Passkey {
            "passkey"
        } else {
            "apikey"
        };
        assert_eq!(
            *trace.lock().unwrap(),
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
                .unwrap();
            assert_eq!(stored.created_at, created_at);
            assert_eq!(stored.name.as_deref(), Some("Desk"));
        } else {
            let stored = raw.get_api_key_by_hash("ordinary-order").await?.unwrap();
            assert_eq!(
                DateTime::parse_from_rfc3339(&stored.created_at)
                    .unwrap()
                    .to_utc(),
                created_at
            );
            assert_eq!(stored.name.as_deref(), Some("Desk"));
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
