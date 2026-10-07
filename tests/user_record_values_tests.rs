#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::store::UserStore;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateUser, FieldMap, UpdateUser,
    UserView,
    store::{
        EphemeralStore, RuntimeStore,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<Value>>>);

impl Trace {
    fn lock(&self) -> AuthResult<MutexGuard<'_, Vec<Value>>> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("User record trace lock poisoned"))
    }
}

fn required<T>(value: Option<T>, context: &str) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal(context))
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Trace {
    async fn before_update_user(
        &self,
        patch: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.lock()?.push(json!({"before":fields(patch)?}));
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        row: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.lock()?
            .push(json!({"after":row.map(fields).transpose()?}));
        Ok(())
    }
}

fn fields(value: impl serde::Serialize) -> AuthResult<Value> {
    let value = serde_json::to_value(value)?;
    let mut fields = serde_json::Map::new();
    for key in ["name", "image"] {
        if let Some(value) = value.get(key) {
            let _ = fields.insert(key.into(), value.clone());
        }
    }
    Ok(Value::Object(fields))
}

async fn matrix<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    trace: Trace,
    sqlite: bool,
) -> AuthResult<()> {
    for (index, patch) in [
        json!({"name":7,"image":false}),
        json!({"name":{},"image":"marker"}),
        json!({"name":[],"image":"marker"}),
        json!({"name":["x"]}),
        json!({"name":"marker","image":{}}),
        json!({"name":"marker","image":[]}),
        json!({"image":null}),
    ]
    .into_iter()
    .enumerate()
    {
        let user = store
            .create_user(
                CreateUser::new()
                    .with_email(format!("{index}@record.test"))
                    .with_name("Initial"),
            )
            .await?;
        let id = user.id.typed()?;
        trace.lock()?.clear();
        let result = store
            .update_user_optional(id, serde_json::from_value(patch.clone())?)
            .await;
        let stored = required(
            store.get_user_by_id(id).await?,
            "Patched user must remain stored",
        )?;
        let before = json!({"before":patch});
        if sqlite && [1, 2, 3, 4, 5].contains(&index) {
            assert!(result.is_err());
            assert_eq!(fields(&stored)?, json!({"name":"Initial","image":null}));
            assert_eq!(*trace.lock()?, vec![before]);
        } else {
            let returned = required(result?, "Successful user update must return a row")?;
            let mut expected = fields(&user)?;
            required(
                expected.as_object_mut(),
                "User field projection must be an object",
            )?
            .extend(required(patch.as_object(), "User field patch must be an object")?.clone());
            if sqlite && index == 0 {
                expected = json!({"name":"7","image":"0"});
            }
            assert_eq!(fields(&returned)?, expected);
            assert_eq!(fields(&stored)?, expected);
            assert_eq!(*trace.lock()?, vec![before, json!({"after":expected})]);
            let roundtrip: UserView = serde_json::from_value(serde_json::to_value(&returned)?)?;
            assert_eq!(fields(roundtrip)?, expected);
        }
    }
    Ok(())
}

#[tokio::test]
async fn raw_user_fields_keep_memory_values_and_sqlite_column_binding_results() -> AuthResult<()> {
    let config = Arc::new(AuthConfig::default());
    let trace = Trace::default();
    let store = EphemeralStore::new(config.clone()).with_runtime(
        config.clone(),
        vec![Arc::new(trace.clone())],
        Default::default(),
    )?;
    matrix(store, trace, false).await?;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!(
                "Cannot connect user record SQLite fixture: {error}"
            ))
        })?;
    migrator::run_migrations(&database).await.map_err(|error| {
        AuthError::internal(format!(
            "Cannot migrate user record SQLite fixture: {error}"
        ))
    })?;
    let trace = Trace::default();
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database).with_runtime(
        config,
        vec![Arc::new(trace.clone())],
        Default::default(),
    )?;
    matrix(store, trace, true).await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The identity binding contract must assert the original rejection and unchanged user records"
)]
async fn sqlite_record_array_cannot_replace_the_authenticated_identity_binding() -> AuthResult<()> {
    let config = Arc::new(AuthConfig::default());
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!(
                "Cannot connect identity binding SQLite fixture: {error}"
            ))
        })?;
    migrator::run_migrations(&database).await.map_err(|error| {
        AuthError::internal(format!(
            "Cannot migrate identity binding SQLite fixture: {error}"
        ))
    })?;
    let store = SeaOrmStore::<BundledSchema>::new(config, database);
    let a = store
        .create_user(CreateUser::new().with_email("a@record.test").with_name("A"))
        .await?;
    let b = store
        .create_user(CreateUser::new().with_email("b@record.test").with_name("B"))
        .await?;
    let error = required(
        store
            .update_user_optional(
                a.id.typed()?,
                serde_json::from_value(json!({"name":["Changed",0,b.id]}))?,
            )
            .await
            .err(),
        "Array update must fail the SQLite identity binding",
    )?;
    assert!(
        matches!(error,better_auth_core::AuthError::Internal(message) if message=="Binding expected string, TypedArray, boolean, number, bigint or null")
    );
    for user in [a, b] {
        let stored = required(
            store.get_user_by_id(user.id.typed()?).await?,
            "Rejected array update must preserve each user",
        )?;
        assert_eq!(stored.name, user.name);
        assert_eq!(stored.updated_at, user.updated_at);
    }
    for name in [None, Some(Value::Null)] {
        let mut input = CreateUser::new().with_email("missing@record.test");
        input.name = better_auth_core::SchemaValue::from_json(name)?;
        let error = required(
            store.create_user(input).await.err(),
            "Missing or null name must fail the SQLite constraint",
        )?;
        assert!(error.to_string().contains("NOT NULL"));
    }
    Ok(())
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model types")]
mod json_user {
    use better_auth::seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "mapped_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[serde(rename = "storedName")]
        #[sea_orm(column_name = "display_name")]
        pub name: Json,
        pub email: Option<String>,
        pub email_verified: bool,
        #[serde(rename = "storedImage")]
        #[sea_orm(column_name = "avatar_value")]
        pub image: Option<Json>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct JsonSchema;
impl AuthSchema for JsonSchema {
    type User = json_user::Model;
    type Session = <BundledSchema as AuthSchema>::Session;
    type Account = <BundledSchema as AuthSchema>::Account;
    type Verification = <BundledSchema as AuthSchema>::Verification;
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The mapped column contract must assert raw values, callback counts, and rollback preservation"
)]
async fn mapped_json_columns_preserve_raw_values_and_apply_each_storage_transform_once()
-> AuthResult<()> {
    use better_auth_core::user_fields::UserFieldConfig;
    use better_auth_seaorm::sea_orm::{ConnectionTrait, EntityTrait, Schema};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let inputs = Arc::new(AtomicUsize::new(0));
    let outputs = Arc::new(AtomicUsize::new(0));
    let mut config = AuthConfig::default();
    let input_count = inputs.clone();
    let output_count = outputs.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            field_name: Some("storedName".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let _ = input_count.fetch_add(1, Ordering::SeqCst);
                    Ok(if value.is_undefined() {
                        value
                    } else {
                        FieldMap::from_iter([("stored".into(), value)]).into()
                    })
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let _ = output_count.fetch_add(1, Ordering::SeqCst);
                    Ok(if value.is_undefined() {
                        value
                    } else {
                        FieldMap::from_iter([("shown".into(), value)]).into()
                    })
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!(
                "Cannot connect mapped column SQLite fixture: {error}"
            ))
        })?;
    let backend = database.get_database_backend();
    let _ = database
        .execute_raw(
            backend.build(&Schema::new(backend).create_table_from_entity(json_user::Entity)),
        )
        .await
        .map_err(|error| {
            AuthError::internal(format!("Cannot create mapped user table: {error}"))
        })?;
    let store = SeaOrmStore::<JsonSchema>::new(config, database.clone());
    let created = store
        .create_user(
            CreateUser::new()
                .with_email("mapped@record.test")
                .with_name("Initial"),
        )
        .await?;
    assert_eq!(
        created.name.json()?,
        Some(json!({"shown":{"stored":"Initial"}}))
    );
    assert_eq!(inputs.load(Ordering::SeqCst), 1);
    assert_eq!(outputs.load(Ordering::SeqCst), 1);
    let updated = store
        .update_user(
            created.id.typed()?,
            serde_json::from_value(json!({"name":[1,false],"image":{"raw":null}}))?,
        )
        .await?;
    assert_eq!(
        updated.name.json()?,
        Some(json!({"shown":{"stored":[1,false]}}))
    );
    assert_eq!(updated.image.json()?, Some(json!({"raw":null})));
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    assert_eq!(outputs.load(Ordering::SeqCst), 2);
    let physical = required(
        json_user::Entity::find_by_id(created.id.typed()?)
            .one(&database)
            .await
            .map_err(|error| {
                AuthError::internal(format!("Cannot read mapped user row: {error}"))
            })?,
        "Mapped user row must remain stored",
    )?;
    assert_eq!(physical.name, json!({"stored":[1,false]}));
    assert_eq!(physical.image, Some(json!({"raw":null})));
    let reread = required(
        store.get_user_by_id(created.id.typed()?).await?,
        "Mapped user must remain readable",
    )?;
    assert_eq!(fields(reread)?, fields(&updated)?);
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    assert_eq!(outputs.load(Ordering::SeqCst), 3);
    let id = created.id.typed()?.clone();
    let result: AuthResult<()> = better_auth_core::store::transaction(&store, move |tx| {
        Box::pin(async move {
            let updated = tx
                .update_user(
                    &id,
                    serde_json::from_value(json!({"name":{"rolled":"back"},"image":[1,2]}))?,
                )
                .await?;
            assert_eq!(updated.image.json()?, Some(json!([1, 2])));
            Err(better_auth_core::AuthError::internal("rollback raw fields"))
        })
    })
    .await;
    assert!(
        matches!(result,Err(better_auth_core::AuthError::Internal(message)) if message=="rollback raw fields")
    );
    let reread = required(
        store.get_user_by_id(created.id.typed()?).await?,
        "Rolled back mapped user must remain readable",
    )?;
    assert_eq!(fields(reread)?, fields(&updated)?);
    let physical_after = required(
        json_user::Entity::find_by_id(created.id.typed()?)
            .one(&database)
            .await
            .map_err(|error| {
                AuthError::internal(format!("Cannot read mapped user after rollback: {error}"))
            })?,
        "Rollback must preserve the mapped user row",
    )?;
    assert_eq!(physical_after.name, physical.name);
    assert_eq!(physical_after.image, physical.image);
    Ok(())
}
