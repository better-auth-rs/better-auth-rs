use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::{UserStore, transaction};
use better_auth_core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform,
};
use better_auth_core::{AuthConfig, AuthInitContext, CreateUser, DeviceCodeOwnership, FieldValue};
use sea_orm::Database;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn consumption_uses_original_storage_and_rejects_changed_public_bindings() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Device owner")
                .with_email("device-record@example.test"),
        )
        .await?;
    let reader = store.clone();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::DeviceCode,
        UserConfig {
            additional_fields: Some(
                ["deviceCode", "clientId", "userId", "status"]
                    .into_iter()
                    .map(|name| {
                        (
                            name.to_owned(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new(move |value| {
                                        Ok(match name {
                                            "deviceCode" => 17.0.into(),
                                            "clientId" => true.into(),
                                            "userId" => {
                                                FieldMap::from([("owner".into(), value)]).into()
                                            }
                                            _ if value == FieldValue::from("pending") => {
                                                "approved".into()
                                            }
                                            _ => "projected-approved".into(),
                                        })
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    let ownership = DeviceCodeOwnership::ClientId("original-client".into());
    for status in ["approved", "pending"] {
        let input = FieldMap::from([
            ("id".into(), status.into()),
            ("deviceCode".into(), status.into()),
            ("userCode".into(), status.into()),
            ("userId".into(), owner.id.field_value()),
            ("expiresAt".into(), chrono::Utc::now().into()),
            ("status".into(), status.into()),
            ("clientId".into(), "original-client".into()),
        ]);
        let created = store.create_device_code_record(input).await?;
        let record = store
            .get_device_code_by_device_code(status)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored Device code"))?;
        assert_eq!(record.device_code.field_value(), FieldValue::Number(17.0));
        assert_eq!(record.client_id.field_value(), FieldValue::Bool(true));
        assert_eq!(
            record.user_id.field_value(),
            FieldValue::from(FieldMap::from([("owner".into(), owner.id.field_value())]))
        );
        assert_eq!(
            created.get("deviceCode"),
            Some(&record.device_code.field_value())
        );
        if status == "pending" {
            assert_eq!(record.status.typed()?, "approved");
            assert!(
                store
                    .consume_device_code(&record, &ownership)
                    .await?
                    .is_none()
            );
            assert!(reader.get_device_code_record(&record.id).await?.is_some());
            continue;
        }
        assert_eq!(record.status.typed()?, "projected-approved");
        for name in ["id", "deviceCode", "clientId", "userId", "status"] {
            let mut changed = record.clone();
            match name {
                "id" => changed.id = "changed".to_owned().into(),
                "deviceCode" => changed.device_code = "changed".to_owned().into(),
                "clientId" => changed.client_id = Some("changed".to_owned()).into(),
                "userId" => changed.user_id = Some("changed".to_owned()).into(),
                _ => changed.status = "changed".to_owned().into(),
            }
            assert!(
                store
                    .consume_device_code(&changed, &ownership)
                    .await?
                    .is_none(),
                "{name}"
            );
        }
        let stored = reader
            .get_device_code_by_device_code(status)
            .await?
            .ok_or_else(|| {
                AuthError::internal("Rejected consumption must retain the Device code")
            })?;
        assert_eq!(stored.status.typed()?, "approved");
        assert_eq!(
            stored.client_id.typed()?.as_deref(),
            Some("original-client")
        );
        assert_eq!(stored.user_id.typed()?.as_ref(), Some(owner.id.typed()?));
        let consumed = store
            .consume_device_code(&record, &ownership)
            .await?
            .ok_or_else(|| {
                AuthError::internal("Unchanged projections must consume the stored code")
            })?;
        assert_eq!(
            consumed.device_code.field_value(),
            record.device_code.field_value()
        );
        assert!(
            store
                .consume_device_code(&record, &ownership)
                .await?
                .is_none()
        );
        assert!(reader.get_device_code_record(&record.id).await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn claim_rejects_discarded_owner_in_direct_and_explicit_transactions() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let id: SchemaValue<String> = "empty-owner".into();
    let _ = store
        .create_device_code_record(FieldMap::from([
            ("id".into(), id.field_value()),
            ("deviceCode".into(), "empty-owner-device".into()),
            ("userCode".into(), "empty-owner-user".into()),
            ("userId".into(), FieldValue::Null),
            ("expiresAt".into(), chrono::Utc::now().into()),
            ("status".into(), "pending".into()),
        ]))
        .await?;
    let reader = store.clone();
    let before = reader.get_device_code_record(&id).await?;
    let inputs = Arc::new(AtomicUsize::new(0));
    let outputs = Arc::new(AtomicUsize::new(0));
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::DeviceCode,
        UserConfig {
            additional_fields: Some(
                [(
                    "userId".into(),
                    UserFieldConfig {
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new({
                                let inputs = inputs.clone();
                                move |value| {
                                    assert_eq!(value, FieldValue::from("owner"));
                                    let _ = inputs.fetch_add(1, Ordering::SeqCst);
                                    Ok(FieldValue::Undefined)
                                }
                            })),
                            output: Some(UserFieldTransform::new({
                                let outputs = outputs.clone();
                                move |value| {
                                    let _ = outputs.fetch_add(1, Ordering::SeqCst);
                                    Ok(value)
                                }
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    for transactional in [false, true] {
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
        assert_eq!(outputs.load(Ordering::SeqCst), 0);
        assert_eq!(reader.get_device_code_record(&id).await?, before);
    }
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    Ok(())
}
