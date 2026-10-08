use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::UserStore;
use better_auth_core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform,
};
use better_auth_core::{AuthConfig, AuthInitContext, CreateUser, FieldValue};
use sea_orm::Database;
use std::sync::Arc;

const NATIVE_FIELDS: [&str; 10] = [
    "name",
    "publicKey",
    "userId",
    "credentialID",
    "counter",
    "deviceType",
    "backedUp",
    "transports",
    "createdAt",
    "aaguid",
];

async fn store() -> AuthResult<(SeaOrmStore<BundledSchema>, String)> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    );
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Passkey owner")
                .with_email("passkey-record@example.test"),
        )
        .await?;
    Ok((store, owner.id.typed()?.clone()))
}

#[tokio::test]
async fn raw_passkey_records_exclude_undeclared_legacy_fields() -> AuthResult<()> {
    let (store, owner) = store().await?;
    let created = store
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: owner.into(),
            name: Some("Before".into()).into(),
            credential_id: "legacy-credential-id".into(),
            public_key: "public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            credential: PasskeyCredentialState::Legacy("opaque-credential".into()),
            aaguid: None.into(),
        })
        .await?;
    assert_eq!(created.credential.typed()?, "opaque-credential");
    let timestamp = created.updated_at.typed()?.clone();
    let expected_keys = NATIVE_FIELDS.into_iter().chain(["id"]).collect::<Vec<_>>();
    let original = store
        .get_passkey_record(&created.id)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the raw Passkey record"))?;
    assert_eq!(
        original.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_keys
    );
    let mut expected = original.clone();
    let _ = expected.insert("name".into(), "After".into());
    let updated = store
        .update_passkey_record(
            &created.id,
            FieldMap::from([("name".into(), "After".into())]),
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected the updated raw Passkey record"))?;
    assert_eq!(updated, expected);
    assert_eq!(
        updated.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_keys
    );
    let typed = store
        .get_passkey_by_id(created.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the typed Passkey record"))?;
    assert_eq!(typed.name.typed()?.as_deref(), Some("After"));
    assert_eq!(typed.credential.typed()?, "opaque-credential");
    assert_eq!(typed.updated_at.typed()?, &timestamp);
    let typed_update = store
        .update_passkey(
            &created.id,
            UpdatePasskey {
                name: Some("Typed update".into()).into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(typed_update.name.typed()?.as_deref(), Some("Typed update"));
    assert_eq!(typed_update.credential.typed()?, "opaque-credential");
    assert!(typed_update.updated_at.typed()?.to_datetime()?.is_some());
    Ok(())
}

#[tokio::test]
async fn declared_legacy_fields_follow_raw_and_typed_output_policies() -> AuthResult<()> {
    let (mut store, owner) = store().await?;
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::Passkey,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "credential".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(|value| {
                                    assert_eq!(value, FieldValue::from("opaque-credential"));
                                    Ok("projected-credential".into())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "updatedAt".into(),
                        UserFieldConfig {
                            field_name: Some("updated_at".into()),
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(|value| {
                                    assert!(matches!(value, FieldValue::String(_)));
                                    Ok(17.0.into())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    let at = Utc::now();
    let created = store
        .create_passkey_record(FieldMap::from([
            ("id".into(), "declared-passkey".into()),
            ("publicKey".into(), "public-key".into()),
            ("userId".into(), owner.into()),
            ("credentialID".into(), "declared-credential-id".into()),
            ("counter".into(), 0.0.into()),
            ("deviceType".into(), "singleDevice".into()),
            ("backedUp".into(), false.into()),
            ("createdAt".into(), at.into()),
            ("credential".into(), "opaque-credential".into()),
            ("updatedAt".into(), at.to_rfc3339().into()),
        ]))
        .await?
        .ok_or_else(|| AuthError::internal("Expected the created Passkey record"))?;
    let expected_keys = NATIVE_FIELDS
        .into_iter()
        .chain(["credential", "updatedAt", "id"])
        .collect::<Vec<_>>();
    assert_eq!(
        created.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_keys
    );
    assert_eq!(
        created.get("credential"),
        Some(&"projected-credential".into())
    );
    assert_eq!(created.get("updatedAt"), Some(&17.0.into()));
    assert_eq!(
        store
            .get_passkey_record(&"declared-passkey".to_owned().into())
            .await?,
        Some(created)
    );
    let typed = store
        .get_passkey_by_id("declared-passkey")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the declared Passkey record"))?;
    assert_eq!(typed.credential.typed()?, "projected-credential");
    assert_eq!(typed.updated_at.field_value(), FieldValue::Number(17.0));
    Ok(())
}
