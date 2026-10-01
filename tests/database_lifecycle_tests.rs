#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "Regression fixtures stop on unexpected setup or assertion failures"
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthSession, AuthStore, AuthUser, CreateAccount,
    CreateSession, CreateUser,
    store::{
        AccountStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore,
        StatelessSchema, UserStore,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
        secondary::SecondaryStore,
        transaction,
    },
    user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};

#[path = "../compat-tests/rust-server/src/user_fields/session.rs"]
pub mod application_session;

struct ProjectionSchema;
impl AuthSchema for ProjectionSchema {
    type User = <BundledSchema as AuthSchema>::User;
    type Account = <BundledSchema as AuthSchema>::Account;
    type Verification = <BundledSchema as AuthSchema>::Verification;
    type Session = application_session::Model;
}

#[derive(Clone, Default)]
struct ProjectionHooks(Arc<Mutex<Vec<serde_json::Value>>>);
impl ProjectionHooks {
    fn record<T: serde::Serialize>(&self, session: &T) -> AuthResult<()> {
        let fields = serde_json::to_value(session)?;
        self.0.lock().unwrap().push(
            fields
                .get("deviceLabel")
                .or_else(|| fields.get("label"))
                .cloned()
                .unwrap_or_default(),
        );
        Ok(())
    }
}
#[better_auth::database_hooks()]
impl SeaOrmHooks<ProjectionSchema> for ProjectionHooks {
    async fn before_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, ProjectionSchema>,
    ) -> AuthResult<HookControl> {
        self.record(row)?;
        Ok(HookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, ProjectionSchema>,
    ) -> AuthResult<()> {
        self.record(row)
    }
}
#[better_auth::database_hooks()]
impl DatabaseHooks<StatelessSchema> for ProjectionHooks {
    async fn before_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record(row)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record(row)
    }
}

async fn check_projected_snapshots<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    hooks: ProjectionHooks,
    reject: Arc<AtomicBool>,
) {
    let user = store
        .create_user(CreateUser::new().with_email("snapshot@example.com"))
        .await
        .unwrap();
    let first = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    let second = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    store.delete_session(first.token()).await.unwrap();
    assert_eq!(
        *hooks.0.lock().unwrap(),
        vec![serde_json::json!("raw:out"), serde_json::json!("raw:out")]
    );
    hooks.0.lock().unwrap().clear();
    reject.store(true, Ordering::SeqCst);
    store.delete_session(second.token()).await.unwrap();
    assert!(hooks.0.lock().unwrap().is_empty());
    reject.store(false, Ordering::SeqCst);
    assert!(store.get_session(second.token()).await.unwrap().is_some());
    reject.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .delete_user_sessions_optional(user.id().typed().unwrap(), false)
            .await
            .unwrap(),
        Some(1)
    );
    assert!(hooks.0.lock().unwrap().is_empty());
    reject.store(false, Ordering::SeqCst);
    assert!(store.get_session(second.token()).await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_and_ephemeral_delete_hooks_receive_one_transformed_hidden_snapshot() {
    use better_auth_seaorm::sea_orm::ConnectionTrait;
    for database in [false, true] {
        let hooks = ProjectionHooks::default();
        let reject = Arc::new(AtomicBool::new(false));
        let rejected = reject.clone();
        let mut config = AuthConfig::default();
        let _ = config.session.additional_fields.insert(
            "label".into(),
            UserFieldConfig {
                required: Some(false),
                returned: false,
                field_name: Some("deviceLabel".into()),
                default_value: Some(serde_json::json!("raw")),
                output_transform: Some(Arc::new(move |value| {
                    if rejected.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("snapshot rejected"));
                    }
                    Ok(value
                        .map(|value| serde_json::json!(format!("{}:out", value.as_str().unwrap()))))
                })),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        if database {
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&db).await.unwrap();
            for field in [
                "device_label",
                "internal_note",
                "validated_label",
                "settings",
            ] {
                let _ = db
                    .execute_unprepared(&format!("ALTER TABLE sessions ADD COLUMN {field} TEXT"))
                    .await
                    .unwrap();
            }
            let store = SeaOrmStore::<ProjectionSchema>::new(config, db)
                .with_hooks(vec![Arc::new(hooks.clone())]);
            check_projected_snapshots(Arc::new(store), hooks, reject).await;
        } else {
            let store = EphemeralStore::new(config).with_hooks(vec![Arc::new(hooks.clone())]);
            check_projected_snapshots(Arc::new(store), hooks, reject).await;
        }
    }
}

#[derive(Clone, Default)]
struct Hooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    before_count: Arc<AtomicUsize>,
    cancel_second: bool,
    fail_after: Option<&'static str>,
}
impl Hooks {
    fn before_session(&self) -> bool {
        self.events.lock().unwrap().push("session.before");
        self.cancel_second && self.before_count.fetch_add(1, Ordering::SeqCst) == 1
    }
    fn before(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
    fn after(&self, event: &'static str) -> AuthResult<()> {
        self.events.lock().unwrap().push(event);
        if self.fail_after == Some(event) {
            return Err(AuthError::internal(event));
        }
        Ok(())
    }
}
#[better_auth::database_hooks()]
impl<S: AuthSchema> SeaOrmHooks<S> for Hooks {
    async fn before_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        Ok(if self.before_session() {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("session.after")
    }
    async fn before_delete_account(
        &self,
        _: &better_auth_core::wire::AccountView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.before("account.before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_account(
        &self,
        _: &better_auth_core::wire::AccountView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("account.after")
    }
    async fn before_delete_user(
        &self,
        _: &better_auth_core::wire::UserView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.before("user.before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_user(
        &self,
        _: &better_auth_core::wire::UserView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("user.after")
    }
}
#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(if self.before_session() {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }
    async fn after_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("session.after")
    }
    async fn before_delete_account(
        &self,
        _: &better_auth_core::wire::AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.before("account.before");
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_account(
        &self,
        _: &better_auth_core::wire::AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("account.after")
    }
    async fn before_delete_user(
        &self,
        _: &better_auth_core::wire::UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.before("user.before");
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_user(
        &self,
        _: &better_auth_core::wire::UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after("user.after")
    }
}

async fn sqlite(config: Arc<AuthConfig>, hooks: Hooks) -> Arc<dyn AuthStore<BundledSchema>> {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    Arc::new(SeaOrmStore::<BundledSchema>::new(config, database).hook(hooks))
}
fn ephemeral(config: Arc<AuthConfig>, hooks: Hooks) -> Arc<dyn AuthStore<StatelessSchema>> {
    Arc::new(EphemeralStore::new(config).with_hooks(vec![Arc::new(hooks)]))
}
fn session(user_id: &str) -> CreateSession {
    CreateSession {
        user_id: user_id.into(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}
async fn check_batch<S: AuthSchema>(store: Arc<dyn AuthStore<S>>, hooks: Hooks) {
    let user = store
        .create_user(CreateUser::new().with_email("batch@example.com"))
        .await
        .unwrap();
    for _ in 0..2 {
        let _ = store
            .create_session(session(user.id().typed().unwrap()))
            .await
            .unwrap();
    }
    hooks.events.lock().unwrap().clear();
    let result = store
        .delete_user_sessions_optional(user.id().typed().unwrap(), false)
        .await;
    let count = store
        .get_user_sessions(user.id().typed().unwrap())
        .await
        .unwrap()
        .len();
    if hooks.cancel_second {
        assert_eq!(result.unwrap(), None);
        assert_eq!(count, 2);
        assert_eq!(
            *hooks.events.lock().unwrap(),
            ["session.before", "session.before"]
        );
    } else {
        assert!(matches!(result,Err(AuthError::Internal(message)) if message=="session.after"));
        assert_eq!(count, 0);
        assert_eq!(
            *hooks.events.lock().unwrap(),
            ["session.before", "session.before", "session.after"]
        );
    }
}

#[tokio::test]
async fn sqlite_batch_cancellation_precedes_writes_and_after_failure_follows_all_writes() {
    for cancel_second in [true, false] {
        let hooks = Hooks {
            cancel_second,
            fail_after: Some("session.after"),
            ..Default::default()
        };
        check_batch(
            sqlite(Arc::new(AuthConfig::default()), hooks.clone()).await,
            hooks,
        )
        .await;
    }
}
#[tokio::test]
async fn ephemeral_batch_preserves_the_same_cancellation_and_after_failure_boundaries() {
    for cancel_second in [true, false] {
        let hooks = Hooks {
            cancel_second,
            fail_after: Some("session.after"),
            ..Default::default()
        };
        check_batch(
            ephemeral(Arc::new(AuthConfig::default()), hooks.clone()),
            hooks,
        )
        .await;
    }
}

async fn check_transaction<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: Arc<AuthConfig>,
    hooks: Hooks,
    rollback: bool,
) {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let store =
        SecondaryStore::new(inner.clone(), cache.clone(), config, Default::default()).unwrap();
    let user = store
        .create_user(CreateUser::new().with_email("transaction@example.com"))
        .await
        .unwrap();
    let user_id = user.id().into_owned();
    let _ = store
        .create_account(CreateAccount {
            user_id: (user_id.clone()).into(),
            provider_id: "mock".into(),
            account_id: "mock".into(),
            password: Default::default(),
            access_token: Default::default(),
            refresh_token: Default::default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: Default::default(),
            ..Default::default()
        })
        .await
        .unwrap();
    let session = store
        .create_session(session(user_id.typed().unwrap()))
        .await
        .unwrap();
    let token = session.token().to_owned();
    hooks.events.lock().unwrap().clear();
    let tx_id = user_id.clone();
    let tx_token = token.clone();
    let tx_cache = cache.clone();
    let tx_events = hooks.events.clone();
    let result: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            tx.delete_user(tx_id.typed().unwrap()).await?;
            assert_eq!(
                *tx_events.lock().unwrap(),
                ["session.before", "account.before", "user.before"]
            );
            assert!(tx_cache.get(&tx_token).await?.is_some());
            if rollback {
                return Err(AuthError::internal("rollback"));
            }
            Ok(())
        })
    })
    .await;
    let should_fail = rollback || hooks.fail_after.is_some();
    assert_eq!(result.is_err(), should_fail);
    assert_eq!(
        inner
            .get_user_by_id(user_id.typed().unwrap())
            .await
            .unwrap()
            .is_some(),
        rollback
    );
    assert_eq!(inner.get_session(&token).await.unwrap().is_some(), rollback);
    assert_eq!(cache.get(&token).await.unwrap().is_some(), should_fail);
    let mut expected = vec!["session.before", "account.before", "user.before"];
    if !rollback {
        expected.push("session.after");
        if hooks.fail_after != Some("session.after") {
            expected.extend(["account.after", "user.after"]);
        }
    }
    assert_eq!(*hooks.events.lock().unwrap(), expected);
}
#[tokio::test]
async fn sqlite_user_deletion_keeps_child_user_and_cache_effects_in_commit_order() {
    for (fail_after, rollback) in [
        (None, false),
        (Some("session.after"), false),
        (Some("user.after"), false),
        (None, true),
    ] {
        let mut config = AuthConfig::default();
        config.session.store_session_in_database = true;
        let config = Arc::new(config);
        let hooks = Hooks {
            fail_after,
            ..Default::default()
        };
        check_transaction(
            sqlite(config.clone(), hooks.clone()).await,
            config,
            hooks,
            rollback,
        )
        .await;
    }
}
#[tokio::test]
async fn ephemeral_user_deletion_keeps_the_same_commit_effect_order() {
    for (fail_after, rollback) in [
        (None, false),
        (Some("session.after"), false),
        (Some("user.after"), false),
        (None, true),
    ] {
        let mut config = AuthConfig::default();
        config.session.store_session_in_database = true;
        let config = Arc::new(config);
        let hooks = Hooks {
            fail_after,
            ..Default::default()
        };
        check_transaction(
            ephemeral(config.clone(), hooks.clone()),
            config,
            hooks,
            rollback,
        )
        .await;
    }
}

#[tokio::test]
async fn ephemeral_delete_snapshot_projection_error_does_not_cancel_the_batch_write() {
    let reject = Arc::new(AtomicBool::new(false));
    let rejection = reject.clone();
    let mut config = AuthConfig::default();
    let _ = config.session.additional_fields.insert(
        "marker".into(),
        UserFieldConfig {
            required: Some(false),
            output_transform: Some(Arc::new(move |value| {
                if rejection.load(Ordering::SeqCst) {
                    return Err(AuthError::internal("snapshot rejected"));
                }
                Ok(value)
            })),
            ..Default::default()
        },
    );
    let hooks = Hooks::default();
    let store = EphemeralStore::new(Arc::new(config)).with_hooks(vec![Arc::new(hooks.clone())]);
    let user = store
        .create_user(CreateUser::new().with_email("projection@example.com"))
        .await
        .unwrap();
    let session = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    reject.store(true, Ordering::SeqCst);
    store.delete_session(session.token()).await.unwrap();
    reject.store(false, Ordering::SeqCst);
    assert!(store.get_session(session.token()).await.unwrap().is_some());
    assert!(hooks.events.lock().unwrap().is_empty());
    reject.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .delete_user_sessions_optional(user.id().typed().unwrap(), false)
            .await
            .unwrap(),
        Some(1)
    );
    assert!(hooks.events.lock().unwrap().is_empty());
    reject.store(false, Ordering::SeqCst);
    assert!(store.get_session(session.token()).await.unwrap().is_none());
}

async fn check_token_batch<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    hooks: Hooks,
    preserve: bool,
) {
    let user = store
        .create_user(CreateUser::new().with_email("token-batch@example.com"))
        .await
        .unwrap();
    let first = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    let second = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    let untouched = store
        .create_session(session(user.id().typed().unwrap()))
        .await
        .unwrap();
    let tokens = vec![
        first.token().to_owned(),
        first.token().to_owned(),
        second.token().to_owned(),
        "missing-token".into(),
    ];
    hooks.events.lock().unwrap().clear();
    let result = if preserve {
        store.end_sessions(&tokens).await
    } else {
        store.delete_sessions(&tokens).await
    };
    assert!(
        store
            .get_session(untouched.token())
            .await
            .unwrap()
            .is_some()
    );
    if hooks.cancel_second {
        result.unwrap();
        assert_eq!(
            *hooks.events.lock().unwrap(),
            ["session.before", "session.before"]
        );
        assert!(store.get_session(first.token()).await.unwrap().is_some());
        assert!(store.get_session(second.token()).await.unwrap().is_some());
    } else {
        assert!(matches!(result, Err(AuthError::Internal(message)) if message == "session.after"));
        assert_eq!(
            *hooks.events.lock().unwrap(),
            ["session.before", "session.before", "session.after"]
        );
        for token in [first.token(), second.token()] {
            let row = store.get_session(token).await.unwrap();
            if preserve {
                assert!(row.is_none_or(|row| row.expires_at() <= Utc::now()));
            } else {
                assert!(row.is_none());
            }
        }
    }
}

#[tokio::test]
async fn token_batches_deduplicate_database_hooks_and_keep_cancel_and_after_error_write_boundaries()
{
    for preserve in [false, true] {
        for cancel_second in [false, true] {
            let hooks = Hooks {
                cancel_second,
                fail_after: Some("session.after"),
                ..Default::default()
            };
            check_token_batch(
                sqlite(Arc::new(AuthConfig::default()), hooks.clone()).await,
                hooks,
                preserve,
            )
            .await;
            let hooks = Hooks {
                cancel_second,
                fail_after: Some("session.after"),
                ..Default::default()
            };
            check_token_batch(
                ephemeral(Arc::new(AuthConfig::default()), hooks.clone()),
                hooks,
                preserve,
            )
            .await;
        }
    }
}
