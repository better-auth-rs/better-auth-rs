use super::server_catalog::TestResult;
use better_auth::{
    AuthConfig, AuthSchema,
    prelude::{
        AuthUser, CreateTwoFactor, CreateUser, TwoFactor, TwoFactorStorage, UpdateTwoFactor,
        UpdateUser, UserView,
    },
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel,
        SeaOrmPluginSchema, SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel,
        SeaOrmVerificationModel,
        sea_orm::{
            ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
            sea_query::Expr,
        },
    },
    store::AuthStore,
};
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn owner_value(owner: &UserView, id: &str) -> TestResult<Value> {
    assert_eq!(owner.id.typed()?, id);
    let metadata = better_auth::__private_core::plugin::MetadataMap::from_iter([(
        "two_factor.enabled".to_owned(),
        json!(true),
    )]);
    let owner = UserView::with_fields(owner, &Default::default(), &metadata).await?;
    let mut value = serde_json::to_value(owner)?;
    value
        .as_object_mut()
        .ok_or("Expected a complete User record")?
        .insert("id".into(), json!("<owner-id>"));
    Ok(value)
}

fn factor_value(factor: &TwoFactor, id: &str, owner: &str) -> TestResult<Value> {
    assert_eq!(factor.id.typed()?, id);
    assert_eq!(factor.user_id, owner);
    assert!(factor.created_at.is_undefined());
    assert!(factor.updated_at.is_undefined());
    let mut value = serde_json::to_value(factor)?;
    let object = value
        .as_object_mut()
        .ok_or("Expected a complete TwoFactor record")?;
    object.insert("id".into(), json!("<two-factor-id>"));
    object.insert("userId".into(), json!("<owner-id>"));
    Ok(value)
}

async fn stored<P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    id: &str,
) -> TestResult<TwoFactor> {
    Ok(<P::TwoFactor as SeaOrmPluginModel>::Entity::find()
        .filter(P::TwoFactor::column("id")?.eq(id.to_owned()))
        .one(database)
        .await?
        .ok_or("Missing stored Native TwoFactor")?
        .record()?)
}

// Increment methods return different types; compare complete stored records after each operation.
pub(super) async fn check<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
) -> TestResult<Value>
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let mut config = AuthConfig::default();
    config.telemetry.enabled = false;
    let store = SeaOrmStore::<S>::new(config, database.clone()).with_plugin_schema::<P>();
    let store: &dyn AuthStore<S> = &store;
    assert_eq!(P::TwoFactor::two_factor_storage(), TwoFactorStorage::Native);
    let mut owner_input = CreateUser::new()
        .with_name("TwoFactor catalog owner")
        .with_email("owner@two-factor-catalog.test")
        .with_email_verified(false);
    owner_input.image = Option::<String>::None.into();
    owner_input.created_at = Some("2030-01-02T03:04:05.123Z".parse()?);
    owner_input.updated_at = owner_input.created_at;
    let owner = store.create_user(owner_input).await?;
    let owner_id = owner.id.typed()?.clone();
    assert!(!owner_id.is_empty());
    assert_eq!(owner.two_factor_enabled, Some(false));
    let owner_created = owner_value(&owner, &owner_id).await?;
    let owner_read = owner_value(
        &store
            .get_user_by_id(&owner_id)
            .await?
            .ok_or("Missing TwoFactor owner")?,
        &owner_id,
    )
    .await?;
    let created = store
        .create_two_factor(CreateTwoFactor {
            user_id: owner_id.clone(),
            secret: "ordinary-encrypted-secret".into(),
            backup_codes: "ordinary-encrypted-codes".into(),
            verified: false,
        })
        .await?;
    let id = created.id.typed()?.clone();
    assert!(!id.is_empty());
    let mut expected = TwoFactor {
        id: created.id.clone(),
        user_id: owner_id.clone(),
        secret: "ordinary-encrypted-secret".into(),
        backup_codes: "ordinary-encrypted-codes".into(),
        verified: Some(false),
        failed_verification_count: Some(0),
        locked_until: None,
        created_at: Default::default(),
        updated_at: Default::default(),
    };
    assert_eq!(created, expected);
    assert_eq!(
        store.get_two_factor_by_user_id(&owner_id).await?,
        Some(expected.clone())
    );
    let created_value = factor_value(&created, &id, &owner_id)?;

    let changed = <S::User as SeaOrmUserModel>::Entity::update_many()
        .col_expr(
            S::User::field_column("two_factor_enabled")?,
            Expr::value(None::<bool>),
        )
        .filter(S::User::id_column().eq(S::User::parse_id(&owner_id)?))
        .exec(database)
        .await?;
    assert_eq!(changed.rows_affected, 1);
    let nullable_owner = store
        .get_user_by_id(&owner_id)
        .await?
        .ok_or("Missing nullable owner")?;
    assert_eq!(nullable_owner.two_factor_enabled, None);
    assert!(!nullable_owner.two_factor_enabled());
    let nullable_owner_value = owner_value(&nullable_owner, &owner_id).await?;
    let model = <P::TwoFactor as SeaOrmPluginModel>::Entity::find()
        .filter(P::TwoFactor::column("id")?.eq(id.clone()))
        .one(database)
        .await?
        .ok_or("Missing Native TwoFactor before NULL update")?;
    let mut active = model.into_active_model();
    P::TwoFactor::apply_fields(
        &mut active,
        Map::from_iter([
            ("verified".into(), Value::Null),
            ("failed_verification_count".into(), Value::Null),
        ]),
    )?;
    let nullable = active.update(database).await?.record()?;
    expected.verified = None;
    expected.failed_verification_count = None;
    assert_eq!(nullable, expected);
    let nullable_value = factor_value(&nullable, &id, &owner_id)?;
    let lock: chrono::DateTime<chrono::Utc> = "2030-01-02T03:19:05.123Z".parse()?;
    let calls = AtomicUsize::new(0);
    let deadline = || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(lock)
    };
    store
        .record_two_factor_failure(&created.id, 100, &deadline)
        .await?;
    let nullable_increment = stored::<P>(database, &id).await?;
    assert_eq!(nullable_increment, expected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "SQL NULL + 1 must not invoke the lock callback"
    );
    let nullable_read = store
        .get_two_factor_by_user_id(&owner_id)
        .await?
        .ok_or("Missing nullable factor after increment")?;
    store.reset_two_factor_failures(&created.id, None).await?;
    expected.failed_verification_count = Some(0);
    let reset = stored::<P>(database, &id).await?;
    assert_eq!(reset, expected);
    let mut increments = Vec::new();
    for count in [1, 2] {
        store
            .record_two_factor_failure(&created.id, 100, &deadline)
            .await?;
        expected.failed_verification_count = Some(count);
        let increment = stored::<P>(database, &id).await?;
        assert_eq!(increment, expected);
        increments.push(factor_value(&increment, &id, &owner_id)?);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let updated = store
        .update_two_factor(
            &created.id,
            UpdateTwoFactor {
                backup_codes: Some("replacement-encrypted-codes".into()),
                verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    expected.backup_codes = "replacement-encrypted-codes".into();
    expected.verified = Some(true);
    assert_eq!(updated, expected);
    let updated_read = store
        .get_two_factor_by_user_id(&owner_id)
        .await?
        .ok_or("Missing updated TwoFactor")?;
    assert_eq!(
        owner_value(
            &store
                .get_user_by_id(&owner_id)
                .await?
                .ok_or("Missing owner after factor update")?,
            &owner_id,
        )
        .await?,
        nullable_owner_value
    );
    let observed = json!({
        "ownerCreated": owner_created, "ownerRead": owner_read,
        "created": created_value, "nullableOwner": nullable_owner_value,
        "nullable": nullable_value,
        "nullableIncrement": factor_value(&nullable_increment, &id, &owner_id)?,
        "nullableRead": factor_value(&nullable_read, &id, &owner_id)?,
        "reset": factor_value(&reset, &id, &owner_id)?, "increments": increments,
        "updated": factor_value(&updated, &id, &owner_id)?,
        "updatedRead": factor_value(&updated_read, &id, &owner_id)?,
    });

    let other_owner = store
        .create_user(
            CreateUser::new()
                .with_name("Other owner")
                .with_email("other@two-factor-catalog.test"),
        )
        .await?;
    let other_factor = store
        .create_two_factor(CreateTwoFactor {
            user_id: other_owner.id.typed()?.clone(),
            secret: "other-encrypted-secret".into(),
            backup_codes: "other-encrypted-codes".into(),
            verified: true,
        })
        .await?;
    assert!(
        store
            .compare_exchange_two_factor_backup_codes(
                &created.id,
                &expected.backup_codes,
                "consumed-codes"
            )
            .await?
    );
    assert!(
        !store
            .compare_exchange_two_factor_backup_codes(
                &created.id,
                &expected.backup_codes,
                "stale-codes"
            )
            .await?
    );
    expected.backup_codes = "consumed-codes".into();
    assert_eq!(stored::<P>(database, &id).await?, expected);

    store.reset_two_factor_failures(&created.id, None).await?;
    expected.failed_verification_count = Some(0);
    assert_eq!(stored::<P>(database, &id).await?, expected);
    store
        .record_two_factor_failure(&created.id, 2, &deadline)
        .await?;
    expected.failed_verification_count = Some(1);
    assert_eq!(stored::<P>(database, &id).await?, expected);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    store
        .record_two_factor_failure(&created.id, 2, &deadline)
        .await?;
    expected.failed_verification_count = Some(2);
    expected.locked_until = Some(lock);
    assert_eq!(stored::<P>(database, &id).await?, expected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    store
        .reset_two_factor_failures(&created.id, Some(lock - chrono::Duration::seconds(1)))
        .await?;
    assert_eq!(stored::<P>(database, &id).await?, expected);
    store
        .reset_two_factor_failures(&created.id, Some(lock))
        .await?;
    expected.failed_verification_count = Some(0);
    expected.locked_until = None;
    assert_eq!(stored::<P>(database, &id).await?, expected);

    let updated_owner = store
        .update_user(
            &owner_id,
            UpdateUser {
                two_factor_enabled: Some(true),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated_owner.two_factor_enabled, Some(true));
    assert!(updated_owner.two_factor_enabled());
    assert_eq!(updated_owner.id, owner.id);
    assert_eq!(updated_owner.email, owner.email);
    assert_eq!(
        serde_json::to_value(&updated_owner)?.get("twoFactorEnabled"),
        Some(&json!(true))
    );
    assert_eq!(
        store
            .get_user_by_id(&owner_id)
            .await?
            .ok_or("Missing updated owner")?
            .two_factor_enabled,
        Some(true)
    );
    assert_eq!(
        stored::<P>(database, other_factor.id.typed()?).await?,
        other_factor
    );
    Ok(observed)
}
