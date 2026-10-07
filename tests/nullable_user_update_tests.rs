#![cfg(feature = "seaorm2")]

use async_trait::async_trait;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::store::{
    EphemeralStore, MemoryCacheAdapter, SecondaryStorage, StatelessSchema, UserStore, transaction,
};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateSession,
    CreateUser, UpdateUser,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

type Events = Arc<Mutex<Vec<&'static str>>>;
#[derive(Default)]
struct Cache {
    inner: MemoryCacheAdapter,
    events: Events,
    watched: Mutex<String>,
}
#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        SecondaryStorage::get(&self.inner, key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        if key == *self.watched.lock().unwrap() {
            self.events.lock().unwrap().push("cache");
        }
        SecondaryStorage::set(&self.inner, key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        SecondaryStorage::delete(&self.inner, key).await
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.inner.get_and_delete(key).await
    }
}
#[derive(Clone)]
struct Observer {
    mode: Arc<AtomicU8>,
    events: Events,
}
#[better_auth::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for Observer {
    async fn before_update_user(
        &self,
        _: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.events.lock().unwrap().push("before");
        match self.mode.load(Ordering::SeqCst) {
            1 => Ok(DatabaseHookUpdate::Cancel),
            2 => Err(AuthError::UserNotFound),
            _ => Ok(DatabaseHookUpdate::Continue),
        }
    }
    async fn after_update_user(
        &self,
        user: Option<&better_auth_core::UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push(if user.is_some() {
            "after"
        } else {
            "after-null"
        });
        if self.mode.load(Ordering::SeqCst) == 3 {
            Err(AuthError::UserNotFound)
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Observer {
    fn name(&self) -> &'static str {
        "nullable-update-test"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(self.clone()));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
fn state() -> (Observer, Arc<Cache>) {
    let events = Events::default();
    (
        Observer {
            mode: Default::default(),
            events: events.clone(),
        },
        Arc::new(Cache {
            events,
            ..Default::default()
        }),
    )
}
fn update(name: &str) -> UpdateUser {
    UpdateUser {
        name: Some(name.into()).into(),
        ..Default::default()
    }
}
async fn cached_name(cache: &Cache, token: &str) -> String {
    let cached = cache.get(token).await.unwrap().unwrap();
    let value: Value = serde_json::from_str(cached.as_str().unwrap()).unwrap();
    value
        .pointer("/user/name")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}
async fn native_missing_user<S: AuthSchema>(
    auth: &BetterAuth<S>,
    observer: &Observer,
    cache: &Cache,
    token: &str,
) {
    for mode in 0..=3 {
        observer.events.lock().unwrap().clear();
        observer.mode.store(mode, Ordering::SeqCst);
        let result = auth
            .store()
            .update_user_by_id_value(
                &better_auth_core::FieldValue::Undefined,
                update("Unmatched native ID"),
            )
            .await;
        if mode < 2 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(result, Err(AuthError::UserNotFound)));
        }
        assert_eq!(
            *observer.events.lock().unwrap(),
            if mode == 1 || mode == 2 {
                vec!["before"]
            } else {
                vec!["before", "after-null"]
            },
        );
        assert_eq!(cached_name(cache, token).await, "Original");
    }
    observer.mode.store(0, Ordering::SeqCst);
    for commit in [false, true] {
        observer.events.lock().unwrap().clear();
        let events = observer.events.clone();
        let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                assert!(
                    tx.update_user_by_id_value(
                        &better_auth_core::FieldValue::Undefined,
                        update("Unmatched transactional ID"),
                    )
                    .await?
                    .is_none()
                );
                assert_eq!(*events.lock().unwrap(), ["before"]);
                if commit {
                    Ok(())
                } else {
                    Err(AuthError::internal("rollback native selector"))
                }
            })
        })
        .await;
        assert_eq!(result.is_ok(), commit);
        assert_eq!(
            *observer.events.lock().unwrap(),
            if commit {
                vec!["before", "after-null"]
            } else {
                vec!["before"]
            },
        );
        assert_eq!(cached_name(cache, token).await, "Original");
    }
}
async fn exercise<S: AuthSchema>(auth: BetterAuth<S>, observer: Observer, cache: Arc<Cache>) {
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("optional@example.test")
                .with_name("Original"),
        )
        .await
        .unwrap();
    let id = user.id().typed().unwrap().to_string();
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: id.clone().into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let token = session.token().to_owned();
    *cache.watched.lock().unwrap() = token.clone();
    native_missing_user(&auth, &observer, &cache, &token).await;
    observer.events.lock().unwrap().clear();
    assert!(
        auth.store()
            .update_user_optional(&uuid::Uuid::new_v4().to_string(), update("Missing"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(*observer.events.lock().unwrap(), ["before", "after-null"]);
    observer.events.lock().unwrap().clear();
    observer.mode.store(1, Ordering::SeqCst);
    assert!(
        auth.store()
            .update_user_optional(&id, update("Cancelled"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(*observer.events.lock().unwrap(), ["before"]);
    assert_eq!(
        auth.store()
            .get_user_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .name
            .typed()
            .unwrap()
            .as_deref(),
        Some("Original")
    );
    assert_eq!(cached_name(&cache, &token).await, "Original");
    assert!(matches!(
        auth.store().update_user(&id, update("Strict cancelled")).await,
        Err(AuthError::Forbidden(message)) if message == "user update cancelled by database hook"
    ));
    observer.events.lock().unwrap().clear();
    observer.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        auth.store()
            .update_user_optional(&id, update("Before error"))
            .await,
        Err(AuthError::UserNotFound)
    ));
    assert_eq!(*observer.events.lock().unwrap(), ["before"]);
    observer.events.lock().unwrap().clear();
    observer.mode.store(3, Ordering::SeqCst);
    assert!(matches!(
        auth.store()
            .update_user_optional(&id, update("After error"))
            .await,
        Err(AuthError::UserNotFound)
    ));
    assert_eq!(*observer.events.lock().unwrap(), ["before", "after"]);
    assert_eq!(
        auth.store()
            .get_user_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .name
            .typed()
            .unwrap()
            .as_deref(),
        Some("After error")
    );
    assert_eq!(cached_name(&cache, &token).await, "Original");
    observer.mode.store(0, Ordering::SeqCst);
    for commit in [false, true] {
        observer.events.lock().unwrap().clear();
        let tx_id = id.clone();
        let observed = observer.events.clone();
        let cache_inner = cache.clone();
        let token_inner = token.clone();
        let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let user = tx.update_user_optional(&tx_id, update("Committed")).await?;
                assert!(user.is_some());
                assert_eq!(*observed.lock().unwrap(), ["before"]);
                assert_eq!(cached_name(&cache_inner, &token_inner).await, "Original");
                if commit {
                    Ok(())
                } else {
                    Err(AuthError::internal("rollback"))
                }
            })
        })
        .await;
        assert_eq!(result.is_ok(), commit);
        assert_eq!(
            auth.store()
                .get_user_by_id(&id)
                .await
                .unwrap()
                .unwrap()
                .name
                .typed()
                .unwrap()
                .as_deref(),
            Some(if commit { "Committed" } else { "After error" })
        );
        assert_eq!(
            cached_name(&cache, &token).await,
            if commit { "Committed" } else { "Original" }
        );
        assert_eq!(
            *observer.events.lock().unwrap(),
            if commit {
                vec!["before", "after", "cache"]
            } else {
                vec!["before"]
            }
        );
    }
}
#[tokio::test]
async fn sqlite_nullable_updates_preserve_hooks_transactions_and_cache_order() {
    use better_auth_seaorm::store::__private_test_support::{
        bundled_schema::BundledSchema, migrator,
    };
    let config = AuthConfig::new("nullable-update-test-secret-at-least-32-characters");
    let database = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let (observer, cache) = state();
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(
            config, database,
        ))
        .secondary_storage(cache.clone())
        .plugin(observer.clone())
        .build()
        .await
        .unwrap();
    exercise(auth, observer, cache).await;
}
#[tokio::test]
async fn ephemeral_nullable_updates_preserve_hooks_transactions_and_cache_order() {
    let (observer, cache) = state();
    let auth = BetterAuth::<StatelessSchema>::stateless(AuthConfig::new(
        "nullable-update-test-secret-at-least-32-characters",
    ))
    .secondary_storage(cache.clone())
    .plugin(observer.clone())
    .build()
    .await
    .unwrap();
    exercise(auth, observer, cache).await;
}
#[tokio::test]
async fn ephemeral_nullable_update_propagates_input_and_output_transform_user_not_found() {
    let mode = Arc::new(AtomicU8::new(0));
    let input_mode = mode.clone();
    let output_mode = mode.clone();
    let mut config = AuthConfig::new("nullable-update-test-secret-at-least-32-characters");
    let _ = config.user.fields_mut().insert(
        "marker".into(),
        better_auth_core::config::UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    if input_mode.load(Ordering::SeqCst) == 1 {
                        Err(AuthError::UserNotFound)
                    } else {
                        Ok(value)
                    }
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    if output_mode.load(Ordering::SeqCst) == 2 {
                        Err(AuthError::UserNotFound)
                    } else {
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("transform@example.test")
                .with_name("Original"),
        )
        .await
        .unwrap();
    for phase in [1, 2] {
        mode.store(phase, Ordering::SeqCst);
        let mut change = update("Written");
        let _ = change
            .additional_fields
            .insert("marker".into(), "value".into());
        assert!(matches!(
            store
                .update_user_optional(user.id.typed().unwrap(), change)
                .await,
            Err(AuthError::UserNotFound)
        ));
        mode.store(0, Ordering::SeqCst);
        assert_eq!(
            store
                .get_user_by_id(user.id.typed().unwrap())
                .await
                .unwrap()
                .unwrap()
                .name
                .typed()
                .unwrap()
                .as_deref(),
            Some(if phase == 1 { "Original" } else { "Written" })
        );
    }
}
