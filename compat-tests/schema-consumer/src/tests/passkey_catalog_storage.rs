use super::server_catalog::TestResult;
use better_auth::{
    AuthConfig, AuthSchema,
    prelude::{
        CreatePasskey, CreateUser, Passkey, PasskeyCredentialState, PasskeyStorage,
        UpdatePasskeyAuthentication,
    },
    seaorm::{
        DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel, SeaOrmPluginSchema,
        SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter},
    },
    store::AuthStore,
};
use serde_json::{Map, Value};

// This is a Rust storage contract. The catalog fixture does not establish signature or session behavior.
pub(super) async fn check<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
) -> TestResult
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
    assert_eq!(store.passkey_storage(), PasskeyStorage::Native);
    assert_eq!(P::Passkey::passkey_storage(), PasskeyStorage::Native);
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Passkey catalog owner")
                .with_email("owner@passkey-catalog.test")
                .with_email_verified(false),
        )
        .await?;
    let owner_id = owner.id.typed()?.clone();
    assert!(!owner_id.is_empty());
    let input = CreatePasskey {
        user_id: owner_id.clone(),
        name: Some("Personal key".to_owned()).into(),
        credential_id: "b3JkaW5hcnktcGFzc2tleQ".into(),
        public_key: "ordinary-storage-public-key".into(),
        counter: 7,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: Some("internal,hybrid".into()),
        credential: PasskeyCredentialState::Native,
        aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()).into(),
    };
    let created = store.create_passkey(input.clone()).await?;
    let id = created.id.typed()?.clone();
    assert!(!id.is_empty());
    assert!(created.created_at.typed()?.is_some());
    let mut expected = Passkey {
        id: created.id.clone(),
        user_id: input.user_id,
        name: input.name,
        public_key: input.public_key,
        credential_id: input.credential_id,
        counter: input.counter,
        device_type: input.device_type,
        backed_up: input.backed_up,
        transports: input.transports,
        created_at: created.created_at.clone(),
        updated_at: Default::default(),
        aaguid: input.aaguid,
        credential: Default::default(),
    };
    assert_eq!(created, expected);
    assert_eq!(store.get_passkey_by_id(&id).await?, Some(expected.clone()));
    assert_eq!(
        store
            .get_passkey_by_credential_id(&expected.credential_id)
            .await?,
        Some(expected.clone())
    );
    assert_eq!(
        store.list_passkeys_by_user(&owner_id).await?,
        vec![expected.clone()]
    );
    let updated = store
        .update_passkey_authentication(
            &created.id,
            UpdatePasskeyAuthentication::Native { counter: 9 },
        )
        .await?;
    expected.counter = 9;
    assert_eq!(updated, expected);
    assert_eq!(store.get_passkey_by_id(&id).await?, Some(expected.clone()));
    let renamed = store.update_passkey_name(&id, "Renamed key").await?;
    expected.name = Some("Renamed key".to_owned()).into();
    assert_eq!(renamed, expected);
    assert_eq!(store.get_passkey_by_id(&id).await?, Some(expected.clone()));

    let model = <P::Passkey as SeaOrmPluginModel>::Entity::find()
        .filter(P::Passkey::column("id")?.eq(id.clone()))
        .one(database)
        .await?
        .ok_or("Missing stored Native passkey")?;
    let mut active = model.into_active_model();
    P::Passkey::apply_fields(
        &mut active,
        Map::from_iter([("created_at".to_owned(), Value::Null)]),
    )?;
    let nullable = active.update(database).await?.record()?;
    expected.created_at = None.into();
    assert_eq!(nullable, expected);
    assert_eq!(store.get_passkey_by_id(&id).await?, Some(expected.clone()));
    assert_eq!(
        store
            .get_passkey_by_credential_id(&expected.credential_id)
            .await?,
        Some(expected.clone())
    );
    assert_eq!(
        store.list_passkeys_by_user(&owner_id).await?,
        vec![expected]
    );
    assert_eq!(
        store
            .get_user_by_id(&owner_id)
            .await?
            .ok_or("Missing Passkey owner")?
            .id
            .typed()?,
        &owner_id
    );
    Ok(())
}
