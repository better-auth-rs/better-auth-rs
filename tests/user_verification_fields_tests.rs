#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession, CreateUser,
    UpdateUser, UserView,
    store::{
        EphemeralStore, RuntimeStore,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, EntityTrait, Schema},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Patch {
    update: UpdateUser,
    after: Arc<AtomicUsize>,
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Patch {
    async fn before_update_user(
        &self,
        _: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        Ok(DatabaseHookUpdate::Patch(self.update.clone()))
    }

    async fn after_update_user(
        &self,
        _: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn seed_access<S: AuthSchema>(store: &dyn AuthStore<S>) -> String {
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("proof@fields.test")
                .with_name("Initial"),
        )
        .await
        .unwrap();
    let id = user.id.typed().unwrap().clone();
    let _ = store
        .create_account(CreateAccount {
            user_id: id.clone().into(),
            account_id: id.clone().into(),
            provider_id: "credential".into(),
            password: Some("unproven".into()).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let _ = store
        .create_session(CreateSession {
            user_id: id.clone().into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    id
}

async fn verify_scalars<S: AuthSchema>(store: Arc<dyn AuthStore<S>>, name: Value, image: Value) {
    let id = seed_access(store.as_ref()).await;
    let verified = store
        .verify_user_and_revoke_unproven_access(&id)
        .await
        .unwrap()
        .unwrap();
    assert!(verified.email_verified);
    assert_eq!(verified.name.json().unwrap(), Some(name));
    assert_eq!(verified.image.json().unwrap(), Some(image));
    let stored = store.get_user_by_id(&id).await.unwrap().unwrap();
    assert_eq!(stored.name, verified.name);
    assert_eq!(stored.image, verified.image);
    assert!(stored.email_verified);
    assert!(store.get_user_accounts(&id).await.unwrap().is_empty());
    assert!(store.get_user_sessions(&id).await.unwrap().is_empty());
    let repeated = store
        .verify_user_and_revoke_unproven_access(&id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repeated.name, verified.name);
}

#[tokio::test]
async fn verification_hooks_use_memory_and_sqlite_record_binding() {
    let config = Arc::new(AuthConfig::default());
    let after = Arc::new(AtomicUsize::new(0));
    let patch = || Patch {
        update: serde_json::from_value(json!({"name":7,"image":false})).unwrap(),
        after: after.clone(),
    };
    let memory = EphemeralStore::new(config.clone())
        .with_runtime(config.clone(), vec![Arc::new(patch())])
        .unwrap();
    verify_scalars(memory, json!(7), json!(false)).await;
    assert_eq!(after.load(Ordering::SeqCst), 1);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let sqlite = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
        .with_runtime(config, vec![Arc::new(patch())])
        .unwrap();
    verify_scalars(sqlite, json!("7"), json!("0")).await;
    assert_eq!(after.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_verification_field_conversion_rolls_back_cleanup() {
    let config = Arc::new(AuthConfig::default());
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let after = Arc::new(AtomicUsize::new(0));
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
        .with_runtime(
            config,
            vec![Arc::new(Patch {
                update: serde_json::from_value(json!({"name":null})).unwrap(),
                after: after.clone(),
            })],
        )
        .unwrap();
    let id = seed_access(store.as_ref()).await;
    let error = store
        .verify_user_and_revoke_unproven_access(&id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("NOT NULL"), "{error}");
    let user = store.get_user_by_id(&id).await.unwrap().unwrap();
    assert!(!user.email_verified);
    assert_eq!(user.name.json().unwrap(), Some(json!("Initial")));
    assert_eq!(store.get_user_accounts(&id).await.unwrap().len(), 1);
    assert_eq!(store.get_user_sessions(&id).await.unwrap().len(), 1);
    assert_eq!(after.load(Ordering::SeqCst), 0);
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model types")]
mod mapped_user {
    use better_auth::seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    use serde::Serialize;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[serde(rename = "storedName")]
        #[sea_orm(column_name = "display_name")]
        pub name: Json,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<Json>,
        #[serde(rename = "storedSponsor")]
        pub sponsor: Option<i64>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct MappedSchema;
impl AuthSchema for MappedSchema {
    type User = mapped_user::Model;
    type Session = <BundledSchema as AuthSchema>::Session;
    type Account = <BundledSchema as AuthSchema>::Account;
    type Verification = <BundledSchema as AuthSchema>::Verification;
}

#[tokio::test]
async fn verification_uses_mapped_fields_and_transforms_serial_references_once() {
    use better_auth_core::{
        id::IdGeneration,
        user_fields::{UserFieldConfig, UserFieldReference},
    };
    use better_auth_seaorm::{SeaOrmAccountModel, SeaOrmSessionModel};
    let inputs = Arc::new(AtomicUsize::new(0));
    let observed = inputs.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let _ = config.user.additional_fields.insert(
        "name".into(),
        UserFieldConfig {
            field_name: Some("storedName".into()),
            input_transform: Some(Arc::new(move |value| {
                let _ = observed.fetch_add(1, Ordering::SeqCst);
                Ok(value.map(|value| json!({"stored":value})))
            })),
            ..Default::default()
        },
    );
    let _ = config.user.additional_fields.insert(
        "sponsor".into(),
        UserFieldConfig {
            field_name: Some("storedSponsor".into()),
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            input_transform: Some(Arc::new(|value| {
                Ok(value.map(|value| {
                    assert_eq!(value, json!("sponsor"));
                    json!("1.6e1")
                }))
            })),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(mapped_user::Entity),
        schema.create_table_from_entity(
            <<MappedSchema as AuthSchema>::Account as SeaOrmAccountModel>::Entity::default(),
        ),
        schema.create_table_from_entity(
            <<MappedSchema as AuthSchema>::Session as SeaOrmSessionModel>::Entity::default(),
        ),
    ] {
        let _ = database.execute(&statement).await.unwrap();
    }
    let after = Arc::new(AtomicUsize::new(0));
    let store = SeaOrmStore::<MappedSchema>::new(config.clone(), database.clone())
        .with_runtime(
            config,
            vec![Arc::new(Patch {
                update: UpdateUser {
                    name: Some("Before mapping".into()).into(),
                    image: better_auth_core::SchemaValue::from_json(Some(json!({"source":"hook"}))),
                    additional_fields: [
                        ("name".into(), json!("Final")),
                        ("sponsor".into(), json!("sponsor")),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                },
                after: after.clone(),
            })],
        )
        .unwrap();
    for id in ["16", "17"] {
        let mut input = CreateUser::new().with_name("Initial");
        input.id = Some(id.into());
        let _ = store.create_user(input).await.unwrap();
    }
    inputs.store(0, Ordering::SeqCst);
    let verified = store
        .verify_user_and_revoke_unproven_access("17")
        .await
        .unwrap()
        .unwrap();
    assert!(verified.email_verified);
    assert_eq!(
        verified.name.json().unwrap(),
        Some(json!({"stored":"Final"}))
    );
    assert_eq!(
        verified.image.json().unwrap(),
        Some(json!({"source":"hook"}))
    );
    assert_eq!(
        verified.additional_fields.get("sponsor"),
        Some(&json!("16"))
    );
    assert_eq!(inputs.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    let physical = mapped_user::Entity::find_by_id("17")
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(physical.sponsor, Some(16));
    assert_eq!(physical.name, json!({"stored":"Final"}));
    assert_eq!(physical.image, Some(json!({"source":"hook"})));
    let ordinary = store
        .update_user(
            "16",
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ordinary.name, verified.name);
    assert_eq!(ordinary.image, verified.image);
    assert_eq!(ordinary.additional_fields, verified.additional_fields);
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 2);
}
