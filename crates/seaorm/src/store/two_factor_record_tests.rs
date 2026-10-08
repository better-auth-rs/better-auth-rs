use super::*;
use crate::store::{bundled_schema::BundledSchema, entities, migrator::run_migrations};
use better_auth_core::store::UserStore;
use better_auth_core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use better_auth_core::{AuthConfig, AuthInitContext, CreateUser};
use sea_orm::Database;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod replacement {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "two_factor", native_two_factor)]
    #[sea_orm(table_name = "replacement_two_factor")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub secret: Option<f64>,
        pub user_id: String,
        pub verified: Option<String>,
        pub failed_verification_count: Option<f64>,
        pub locked_until: Option<DateTimeUtc>,
        pub created_at: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[tokio::test]
async fn replaced_columns_keep_dynamic_values_and_transformed_backup_cas() -> AuthResult<()> {
    type Plugins = crate::PluginModels<
        entities::api_key::Model,
        entities::device_code::Model,
        entities::passkey::Model,
        replacement::Model,
    >;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = database
        .execute_unprepared(
            "CREATE TABLE replacement_two_factor (
            id TEXT PRIMARY KEY, secret REAL, user_id TEXT NOT NULL, verified TEXT,
            failed_verification_count REAL, locked_until TEXT, created_at TEXT
        )",
        )
        .await
        .map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database,
    )
    .with_plugin_schema::<Plugins>();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::TwoFactor,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "secret".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            required: Some(false),
                            ..Default::default()
                        },
                    ),
                    (
                        "backupCodes".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            field_name: Some("secret".into()),
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|value| {
                                    Ok((better_auth_core::query::field_number(&value)? + 10.0)
                                        .into())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "verified".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(|value| {
                                    Ok(FieldMap::from([("projected".into(), value)]).into())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    ("createdAt".into(), UserFieldConfig::default()),
                ]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    store.validate_two_factor_fields()?;
    let id = "replacement-factor".into();
    let created = store
        .create_two_factor_record(FieldMap::from([
            ("id".into(), "replacement-factor".into()),
            ("secret".into(), 2.0.into()),
            ("backupCodes".into(), 4.0.into()),
            ("userId".into(), "owner".into()),
            ("verified".into(), "yes".into()),
            ("createdAt".into(), "application timestamp".into()),
        ]))
        .await?
        .ok_or_else(|| AuthError::internal("Expected the created TwoFactor record"))?;
    assert_eq!(created.get("secret"), Some(&14.0.into()));
    assert_eq!(created.get("backupCodes"), Some(&14.0.into()));
    assert!(!created.contains_key("updatedAt"));
    let factor = store
        .get_two_factor_by_user_id("owner")
        .await?
        .ok_or_else(|| AuthError::internal("Expected the replacement TwoFactor"))?;
    assert_eq!(factor.secret.field_value(), FieldValue::Number(14.0));
    assert_eq!(factor.backup_codes.field_value(), FieldValue::Number(14.0));
    assert_eq!(
        factor.verified.json()?,
        Some(serde_json::json!({"projected":"yes"}))
    );
    assert_eq!(
        factor.created_at.field_value(),
        FieldValue::from("application timestamp")
    );
    assert!(factor.updated_at.is_undefined());
    assert!(
        store
            .compare_exchange_two_factor_backup_codes(&id, &14.0.into(), 6.0.into())
            .await?
    );
    assert!(
        !store
            .compare_exchange_two_factor_backup_codes(&id, &14.0.into(), 9.0.into())
            .await?
    );
    let updated = store
        .get_two_factor_record(&id)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the updated TwoFactor"))?;
    assert_eq!(updated.get("secret"), Some(&16.0.into()));
    assert_eq!(updated.get("backupCodes"), Some(&16.0.into()));
    let raw = replacement::Entity::find_by_id("replacement-factor")
        .one(store.connection())
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| AuthError::internal("Expected the physical TwoFactor row"))?;
    assert_eq!(raw.secret, Some(16.0));
    assert_eq!(
        raw.record()?.created_at.field_value(),
        FieldValue::from("application timestamp")
    );
    Ok(())
}

#[tokio::test]
async fn failure_increment_skips_input_and_checks_raw_count_before_locking() -> AuthResult<()> {
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
                .with_name("TwoFactor owner")
                .with_email("two-factor-record@example.test"),
        )
        .await?;
    let factor = store
        .create_two_factor(CreateTwoFactor {
            additional_fields: Default::default(),
            user_id: owner.id.typed()?.clone(),
            secret: "secret".into(),
            backup_codes: "codes".into(),
            verified: true,
        })
        .await?;
    let reader = store.clone();
    let count_inputs = Arc::new(AtomicUsize::new(0));
    let lock_inputs = Arc::new(AtomicUsize::new(0));
    let updates = Arc::new(AtomicUsize::new(0));
    let inputs = count_inputs.clone();
    let locks = lock_inputs.clone();
    let factories = updates.clone();
    let reset_lock = FieldDate::from_milliseconds(1_900_000_000_000.0);
    let transformed_lock = reset_lock.clone();
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::TwoFactor,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "failedVerificationCount".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |value| {
                                    let _ = inputs.fetch_add(1, Ordering::SeqCst);
                                    Ok((better_auth_core::query::field_number(&value)? + 7.0)
                                        .into())
                                })),
                                output: Some(UserFieldTransform::new(|_| Ok(100.0.into()))),
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "lockedUntil".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Date,
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |value| {
                                    let _ = locks.fetch_add(1, Ordering::SeqCst);
                                    Ok(if value.is_null() {
                                        transformed_lock.clone().into()
                                    } else {
                                        value
                                    })
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "secret".into(),
                        UserFieldConfig {
                            on_update: Some(Arc::new(move || {
                                let _ = factories.fetch_add(1, Ordering::SeqCst);
                                Ok("updated by factory".into())
                            })),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    )?;
    store.model_fields = init.into_parts().plugin_fields;
    let callbacks = AtomicUsize::new(0);
    let deadline = || {
        let _ = callbacks.fetch_add(1, Ordering::SeqCst);
        Ok(FieldDate::from_milliseconds(2_000_000_000_000.0))
    };
    store
        .record_two_factor_failure(&factor.id, 101, &deadline)
        .await?;
    assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(count_inputs.load(Ordering::SeqCst), 0);
    assert_eq!(lock_inputs.load(Ordering::SeqCst), 0);
    assert_eq!(updates.load(Ordering::SeqCst), 0);
    store
        .record_two_factor_failure(&factor.id, 5, &deadline)
        .await?;
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    assert_eq!(count_inputs.load(Ordering::SeqCst), 0);
    assert_eq!(lock_inputs.load(Ordering::SeqCst), 1);
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    let persisted = reader
        .get_two_factor_by_user_id(owner.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the factor after failed lock guard"))?;
    assert_eq!(persisted.failed_verification_count, Some(2.0));
    assert_eq!(persisted.locked_until, None);
    assert_eq!(persisted.secret, "secret");
    store.reset_two_factor_failures(&factor.id, None).await?;
    assert_eq!(count_inputs.load(Ordering::SeqCst), 1);
    assert_eq!(lock_inputs.load(Ordering::SeqCst), 2);
    assert_eq!(updates.load(Ordering::SeqCst), 2);
    let reset = reader
        .get_two_factor_by_user_id(owner.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the reset TwoFactor"))?;
    assert_eq!(reset.failed_verification_count, Some(7.0));
    assert_eq!(reset.locked_until, Some(reset_lock));
    assert_eq!(reset.secret, "updated by factory");
    Ok(())
}

#[tokio::test]
async fn atomic_setters_reject_discarded_fields_before_legacy_timestamps() -> AuthResult<()> {
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
                .with_name("Empty setter owner")
                .with_email("empty-setter@example.test"),
        )
        .await?;
    let factor = store
        .create_two_factor(CreateTwoFactor {
            additional_fields: Default::default(),
            user_id: owner.id.typed()?.clone(),
            secret: "secret".into(),
            backup_codes: "codes".into(),
            verified: true,
        })
        .await?;
    let before = entities::two_factor::Entity::find_by_id(factor.id.typed()?.clone())
        .one(store.connection())
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| AuthError::internal("Expected the original TwoFactor"))?;
    let outputs = Arc::new(AtomicUsize::new(0));
    let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
    init.register_model_fields(
        EntityRole::TwoFactor,
        UserConfig {
            additional_fields: Some(
                ["backupCodes", "failedVerificationCount", "lockedUntil"]
                    .into_iter()
                    .map(|name| {
                        let outputs = outputs.clone();
                        (
                            name.into(),
                            UserFieldConfig {
                                field_type: match name {
                                    "failedVerificationCount" => UserFieldType::Number,
                                    "lockedUntil" => UserFieldType::Date,
                                    _ => UserFieldType::String,
                                },
                                transform: Some(FieldTransforms {
                                    input: Some(UserFieldTransform::new(|_| {
                                        Ok(FieldValue::Undefined)
                                    })),
                                    output: Some(UserFieldTransform::new(move |value| {
                                        let _ = outputs.fetch_add(1, Ordering::SeqCst);
                                        Ok(value)
                                    })),
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
    let assert_empty = |error: AuthError| {
        assert!(matches!(error, AuthError::Internal(message) if message
            == "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away."));
    };
    for previous in ["codes", "stale-codes"] {
        assert_empty(
            store
                .compare_exchange_two_factor_backup_codes(
                    &factor.id,
                    &previous.into(),
                    "replacement".into(),
                )
                .await
                .unwrap_err(),
        );
    }
    assert_empty(
        store
            .reset_two_factor_failures(&factor.id, Some(chrono::Utc::now().into()))
            .await
            .unwrap_err(),
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 0);
    assert_eq!(
        entities::two_factor::Entity::find_by_id(factor.id.typed()?.clone())
            .one(store.connection())
            .await
            .map_err(map_db_err)?,
        Some(before.clone())
    );

    assert_empty(
        store
            .record_two_factor_failure(&factor.id, 1, &|| Ok(chrono::Utc::now().into()))
            .await
            .unwrap_err(),
    );
    let mut incremented = before;
    incremented.failed_verification_count = 1;
    assert_eq!(
        entities::two_factor::Entity::find_by_id(factor.id.typed()?.clone())
            .one(store.connection())
            .await
            .map_err(map_db_err)?,
        Some(incremented)
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 3);
    let ordinary = store
        .update_two_factor_backup_codes(owner.id.typed()?, "replacement")
        .await?;
    assert_eq!(ordinary.backup_codes, "codes");
    Ok(())
}
