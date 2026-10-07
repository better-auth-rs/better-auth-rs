use super::*;
use better_auth_core::{
    CreateDeviceCode, DeviceCodeOwnership, UpdateDeviceCode, store::transaction,
};
use std::sync::atomic::{AtomicBool, Ordering};

fn input(label: &str, owner: Option<String>) -> CreateDeviceCode {
    CreateDeviceCode {
        additional_fields: Default::default(),
        device_code: format!("ordinary-device-consumption:{label}"),
        user_code: format!("ordinary-user-consumption:{label}"),
        user_id: owner,
        expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
        status: "approved".into(),
        last_polled_at: None,
        polling_interval: Some(5000.0),
        client_id: Some("ordinary-client".into()),
        scope: Some("Initial".into()).into(),
    }
}

pub(super) async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let failure = Arc::new(AtomicBool::new(false));
    let output_events = events.clone();
    let output_failure = failure.clone();
    let field = UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                output_events.lock().unwrap().push(value.clone());
                if output_failure.load(Ordering::SeqCst) {
                    return Err(AuthError::internal("ordinary Device scope output error"));
                }
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!("{}:out", value.as_str().unwrap()).into(),
                })
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(
            EntityRole::DeviceCode,
            fields("scope", field),
        )]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "device-consumption-owner").await?;
    let ownership = DeviceCodeOwnership::ClientId("ordinary-client".into());

    let initial = raw
        .create_device_code(input("current-row", Some(owner.clone())))
        .await?;
    let expected = auth
        .store()
        .get_device_code_by_device_code(&initial.device_code)
        .await?
        .unwrap();
    let polled = chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let _ = auth
        .store()
        .update_device_code(
            &initial.id,
            UpdateDeviceCode {
                scope: Some("Current".into()).into(),
                last_polled_at: Some(Some(polled.into())),
                ..Default::default()
            },
        )
        .await?;
    events.lock().unwrap().clear();
    let consumed = auth
        .store()
        .consume_device_code(&expected, &ownership)
        .await?
        .unwrap();
    assert_eq!(consumed.scope.json()?, Some(json!("Current:out")));
    assert_eq!(consumed.last_polled_at, Some(polled.into()));
    assert_eq!(*events.lock().unwrap(), [FieldValue::from("Current")]);
    assert!(
        raw.get_device_code_by_device_code(&initial.device_code)
            .await?
            .is_none()
    );

    let expected = raw
        .create_device_code(input("normal-output-error", Some(owner.clone())))
        .await?;
    failure.store(true, Ordering::SeqCst);
    original_error(
        auth.store()
            .consume_device_code(&expected, &ownership)
            .await
            .unwrap_err(),
        "ordinary Device scope output error",
    );
    assert!(
        raw.get_device_code_by_device_code(&expected.device_code)
            .await?
            .is_none()
    );
    failure.store(false, Ordering::SeqCst);

    let expected = raw
        .create_device_code(input("transaction-output-error", Some(owner.clone())))
        .await?;
    let rollback = expected.clone();
    let rollback_ownership = ownership.clone();
    failure.store(true, Ordering::SeqCst);
    let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
        Box::pin(async move {
            let _ = tx
                .consume_device_code(&rollback, &rollback_ownership)
                .await?;
            Ok(())
        })
    })
    .await;
    original_error(result.unwrap_err(), "ordinary Device scope output error");
    failure.store(false, Ordering::SeqCst);
    assert_eq!(
        raw.get_device_code_by_device_code(&expected.device_code)
            .await?,
        Some(expected)
    );

    let committed = transaction(auth.store().as_ref(), move |tx| {
        Box::pin(async move {
            let mut create = input("created-in-transaction", None);
            create.status = "pending".into();
            let created = tx.create_device_code(create).await?;
            assert!(tx.claim_device_code(&created.id, &owner).await?);
            assert!(
                tx.update_device_code_if_status(
                    &created.id,
                    "pending",
                    UpdateDeviceCode {
                        status: Some("approved".into()),
                        ..Default::default()
                    }
                )
                .await?
            );
            let expected = tx
                .get_device_code_by_user_code(&created.user_code)
                .await?
                .unwrap();
            let _ = tx
                .update_device_code(
                    &created.id,
                    UpdateDeviceCode {
                        scope: Some("Inside transaction".into()).into(),
                        ..Default::default()
                    },
                )
                .await?;
            let consumed = tx
                .consume_device_code(&expected, &ownership)
                .await?
                .unwrap();
            assert_eq!(
                consumed.scope.json()?,
                Some(json!("Inside transaction:out"))
            );
            assert!(
                tx.get_device_code_by_device_code(&created.device_code)
                    .await?
                    .is_none()
            );
            let survivor = tx
                .create_device_code(input("committed-survivor", Some(owner)))
                .await?;
            Ok((consumed, survivor))
        })
    })
    .await?;
    assert!(
        raw.get_device_code_by_device_code(&committed.0.device_code)
            .await?
            .is_none()
    );
    assert!(
        raw.get_device_code_by_device_code(&committed.1.device_code)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn memory_device_consumption_returns_current_projection_and_preserves_transaction_errors()
-> AuthResult<()> {
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_device_consumption_returns_current_projection_and_preserves_transaction_errors()
-> AuthResult<()> {
    contract(sqlite().await?).await
}
