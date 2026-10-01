#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::store::UserStore;
use better_auth_core::{
    AuthConfig, AuthResult, AuthSchema, AuthStore, CreateUser, UpdateUser, UserView,
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
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<Value>>>);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Trace {
    async fn before_update_user(
        &self,
        patch: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.0.lock().unwrap().push(json!({"before":fields(patch)}));
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        row: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"after":row.map(fields)}));
        Ok(())
    }
}

fn fields(value: impl serde::Serialize) -> Value {
    let value = serde_json::to_value(value).unwrap();
    let mut fields = serde_json::Map::new();
    for key in ["name", "image"] {
        if let Some(value) = value.get(key) {
            let _ = fields.insert(key.into(), value.clone());
        }
    }
    Value::Object(fields)
}

async fn matrix<S: AuthSchema>(store: Arc<dyn AuthStore<S>>, trace: Trace, sqlite: bool) {
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
            .await
            .unwrap();
        let id = user.id.typed().unwrap();
        trace.0.lock().unwrap().clear();
        let result = store
            .update_user_optional(id, serde_json::from_value(patch.clone()).unwrap())
            .await;
        let stored = store.get_user_by_id(id).await.unwrap().unwrap();
        let before = json!({"before":patch});
        if sqlite && [1, 2, 3, 4, 5].contains(&index) {
            assert!(result.is_err());
            assert_eq!(fields(&stored), json!({"name":"Initial","image":null}));
            assert_eq!(*trace.0.lock().unwrap(), vec![before]);
        } else {
            let returned = result.unwrap().unwrap();
            let mut expected = fields(&user);
            expected
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            if sqlite && index == 0 {
                expected = json!({"name":"7","image":"0"});
            }
            assert_eq!(fields(&returned), expected);
            assert_eq!(fields(&stored), expected);
            assert_eq!(
                *trace.0.lock().unwrap(),
                vec![before, json!({"after":expected})]
            );
            let roundtrip: UserView =
                serde_json::from_value(serde_json::to_value(&returned).unwrap()).unwrap();
            assert_eq!(fields(roundtrip), expected);
        }
    }
}

#[tokio::test]
async fn raw_user_fields_keep_memory_values_and_sqlite_column_binding_results() {
    let config = Arc::new(AuthConfig::default());
    let trace = Trace::default();
    let store = EphemeralStore::new(config.clone())
        .with_runtime(
            config.clone(),
            vec![Arc::new(trace.clone())],
            Default::default(),
        )
        .unwrap();
    matrix(store, trace, false).await;
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let trace = Trace::default();
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
        .with_runtime(config, vec![Arc::new(trace.clone())], Default::default())
        .unwrap();
    matrix(store, trace, true).await;
}

#[tokio::test]
async fn sqlite_record_array_cannot_replace_the_authenticated_identity_binding() {
    let config = Arc::new(AuthConfig::default());
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(config, database);
    let a = store
        .create_user(CreateUser::new().with_email("a@record.test").with_name("A"))
        .await
        .unwrap();
    let b = store
        .create_user(CreateUser::new().with_email("b@record.test").with_name("B"))
        .await
        .unwrap();
    let error = store
        .update_user_optional(
            a.id.typed().unwrap(),
            serde_json::from_value(json!({"name":["Changed",0,b.id]})).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error,better_auth_core::AuthError::Internal(message) if message=="SQLite non-JSON fields do not accept arrays or objects")
    );
    for user in [a, b] {
        let stored = store
            .get_user_by_id(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.name, user.name);
        assert_eq!(stored.updated_at, user.updated_at);
    }
    for name in [None, Some(Value::Null)] {
        let mut input = CreateUser::new().with_email("missing@record.test");
        input.name = better_auth_core::SchemaValue::from_json(name);
        let error = store.create_user(input).await.unwrap_err();
        assert!(error.to_string().contains("NOT NULL"));
    }
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
async fn mapped_json_columns_preserve_raw_values_and_apply_each_storage_transform_once() {
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
                    Ok(value.map(|value| json!({"stored":value})))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let _ = output_count.fetch_add(1, Ordering::SeqCst);
                    Ok(value.map(|value| json!({"shown":value})))
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let backend = database.get_database_backend();
    let _ = database
        .execute_raw(
            backend.build(&Schema::new(backend).create_table_from_entity(json_user::Entity)),
        )
        .await
        .unwrap();
    let store = SeaOrmStore::<JsonSchema>::new(config, database.clone());
    let created = store
        .create_user(
            CreateUser::new()
                .with_email("mapped@record.test")
                .with_name("Initial"),
        )
        .await
        .unwrap();
    assert_eq!(
        created.name.json().unwrap(),
        Some(json!({"shown":{"stored":"Initial"}}))
    );
    assert_eq!(inputs.load(Ordering::SeqCst), 1);
    assert_eq!(outputs.load(Ordering::SeqCst), 1);
    let updated = store
        .update_user(
            created.id.typed().unwrap(),
            serde_json::from_value(json!({"name":[1,false],"image":{"raw":null}})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        updated.name.json().unwrap(),
        Some(json!({"shown":{"stored":[1,false]}}))
    );
    assert_eq!(updated.image.json().unwrap(), Some(json!({"raw":null})));
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    assert_eq!(outputs.load(Ordering::SeqCst), 2);
    let physical = json_user::Entity::find_by_id(created.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(physical.name, json!({"stored":[1,false]}));
    assert_eq!(physical.image, Some(json!({"raw":null})));
    let reread = store
        .get_user_by_id(created.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fields(reread), fields(&updated));
    assert_eq!(inputs.load(Ordering::SeqCst), 2);
    assert_eq!(outputs.load(Ordering::SeqCst), 3);
    let id = created.id.typed().unwrap().clone();
    let result: AuthResult<()> = better_auth_core::store::transaction(&store, move |tx| {
        Box::pin(async move {
            let updated = tx
                .update_user(
                    &id,
                    serde_json::from_value(json!({"name":{"rolled":"back"},"image":[1,2]}))
                        .unwrap(),
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
    let reread = store
        .get_user_by_id(created.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fields(reread), fields(&updated));
    let physical_after = json_user::Entity::find_by_id(created.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(physical_after.name, physical.name);
    assert_eq!(physical_after.image, physical.image);
}
