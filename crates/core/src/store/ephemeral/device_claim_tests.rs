use super::*;
use crate::store::transaction;
use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn claim_rejects_transformed_empty_owner_before_storage_or_output() -> AuthResult<()> {
    for transactional in [false, true] {
        let mut store = EphemeralStore::default();
        let id: crate::SchemaValue<String> = "claim-device".to_owned().into();
        let mut owner = UserFieldConfig {
            field_name: Some("stored_owner".into()),
            required: Some(false),
            ..Default::default()
        };
        store.model_fields.register(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some([("userId".into(), owner.clone())].into()),
            },
        )?;
        let _ = store
            .create_device_code_record(
                [
                    ("id".into(), id.field_value()),
                    ("deviceCode".into(), "claim-code".into()),
                    ("userCode".into(), "claim-user-code".into()),
                    ("status".into(), "pending".into()),
                    ("userId".into(), Value::Null),
                ]
                .into(),
            )
            .await?;
        let stored = store.plugin_storage_rows(EntityRole::DeviceCode)?;
        let inputs = Arc::new(AtomicUsize::new(0));
        let outputs = Arc::new(AtomicUsize::new(0));
        let observed_input = inputs.clone();
        let observed_output = outputs.clone();
        owner.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                assert_eq!(value, Value::from("owner"));
                let _ = observed_input.fetch_add(1, Ordering::SeqCst);
                Ok(Value::Undefined)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let _ = observed_output.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })),
        });
        store.model_fields.register(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some([("userId".into(), owner)].into()),
            },
        )?;
        let result = if transactional {
            let id = id.clone();
            transaction(&store, move |tx| {
                Box::pin(async move { tx.claim_device_code(&id, &"owner".into()).await })
            })
            .await
        } else {
            store.claim_device_code(&id, &"owner".into()).await
        };
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message
            == "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.")
        );
        assert_eq!(store.plugin_storage_rows(EntityRole::DeviceCode)?, stored);
        assert_eq!(inputs.load(Ordering::SeqCst), 1);
        assert_eq!(outputs.load(Ordering::SeqCst), 0);

        assert!(
            store
                .update_device_code_if_status(
                    &id,
                    "pending",
                    UpdateDeviceCode {
                        user_id: Some(Some("owner".into()).into()),
                        ..Default::default()
                    },
                )
                .await?
        );
        assert_eq!(store.plugin_storage_rows(EntityRole::DeviceCode)?, stored);
        assert_eq!(inputs.load(Ordering::SeqCst), 2);
        assert_eq!(outputs.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
