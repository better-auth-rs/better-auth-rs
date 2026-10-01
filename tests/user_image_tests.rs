#![cfg(feature = "seaorm2")]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, AuthUser, CreateUser, UpdateUser,
    store::{
        EphemeralStore, RuntimeStore,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
    },
    wire::UserView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};

const FIRST: &str = "https://image.example/first.png";
const SECOND: &str = "https://image.example/second.png";

#[derive(Clone, Default)]
struct ImageHooks {
    events: Arc<Mutex<Vec<Value>>>,
    reject: Arc<AtomicBool>,
}

fn image(row: impl serde::Serialize) -> Value {
    let row = serde_json::to_value(row).unwrap();
    row.get("image")
        .map_or_else(|| json!({}), |image| json!({"image": image}))
}

impl ImageHooks {
    fn record(&self, event: &str, row: impl serde::Serialize) {
        let mut fields = image(row);
        fields["event"] = json!(event);
        self.events.lock().unwrap().push(fields);
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for ImageHooks {
    async fn before_create_user(
        &self,
        row: &mut CreateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("create.before", row);
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_user(
        &self,
        row: &better_auth_core::wire::UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("create.after", UserView::from(row));
        Ok(())
    }

    async fn before_update_user(
        &self,
        row: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.record("update.before", row);
        if self.reject.load(Ordering::SeqCst) {
            return Err(AuthError::internal("image update rejected"));
        }
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_user(
        &self,
        row: Option<&better_auth_core::wire::UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("update.after", UserView::from(row.unwrap()));
        Ok(())
    }
}

async fn check_image<S: AuthSchema>(store: Arc<dyn AuthStore<S>>, hooks: ImageHooks, sqlite: bool) {
    for (label, input) in [
        ("omitted", None),
        ("null", Some(None)),
        ("value", Some(Some(FIRST.to_owned()))),
    ] {
        hooks.events.lock().unwrap().clear();
        hooks.reject.store(false, Ordering::SeqCst);
        let mut create = CreateUser::new()
            .with_email(format!("{label}@example.test"))
            .with_name("Image user");
        create.image = input.clone().map(Into::into).unwrap_or_default();
        let before = image(&create);
        let initial = if sqlite && input.is_none() {
            json!({"image": null})
        } else {
            before.clone()
        };
        let created = store.create_user(create).await.unwrap();
        assert_eq!(image(UserView::from(&created)), initial);
        let id = created.id();
        let kept = store
            .update_user(
                id.typed().unwrap(),
                UpdateUser {
                    name: Some("Renamed".into()).into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(image(UserView::from(&kept)), initial);
        for value in [json!(SECOND), Value::Null] {
            let update = serde_json::from_value(json!({"image": value})).unwrap();
            let updated = store
                .update_user(id.typed().unwrap(), update)
                .await
                .unwrap();
            assert_eq!(image(UserView::from(&updated)), json!({"image": value}));
        }
        hooks.reject.store(true, Ordering::SeqCst);
        let failure = store
            .update_user(
                id.typed().unwrap(),
                UpdateUser {
                    image: Some(FIRST.into()).into(),
                    ..Default::default()
                },
            )
            .await;
        assert!(
            matches!(failure, Err(AuthError::Internal(message)) if message == "image update rejected")
        );
        let stored = store
            .get_user_by_id(id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(image(UserView::from(&stored)), json!({"image": null}));
        let event = |name: &str, mut fields: Value| {
            fields["event"] = json!(name);
            fields
        };
        assert_eq!(
            *hooks.events.lock().unwrap(),
            [
                event("create.before", before),
                event("create.after", initial.clone()),
                event("update.before", json!({})),
                event("update.after", initial),
                event("update.before", json!({"image": SECOND})),
                event("update.after", json!({"image": SECOND})),
                event("update.before", json!({"image": null})),
                event("update.after", json!({"image": null})),
                event("update.before", json!({"image": FIRST})),
            ]
        );
    }
}

#[tokio::test]
async fn implicit_and_sqlite_image_updates_preserve_omission_and_clear_explicit_null() {
    let config = Arc::new(AuthConfig::default());
    let hooks = ImageHooks::default();
    let store = EphemeralStore::new(config.clone())
        .with_runtime(config.clone(), vec![Arc::new(hooks.clone())])
        .unwrap();
    check_image(store, hooks, false).await;

    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let hooks = ImageHooks::default();
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
        .with_runtime(config, vec![Arc::new(hooks.clone())])
        .unwrap();
    check_image(store, hooks, true).await;
}
