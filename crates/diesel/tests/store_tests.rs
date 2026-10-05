//! Store conformance tests for `DieselStore`.
//!
//! Every test runs on an in-memory SQLite database. Set
//! `BETTER_AUTH_DIESEL_POSTGRES_URL` to a PostgreSQL URL whose role may
//! create databases to run the same tests on PostgreSQL; each test then uses
//! a fresh database.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "store tests fail fast on fixture setup and index into known result sets"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use better_auth_core::config::AuthConfig;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::store::{
    AccountStore, ApiKeyStore, AuthStore, ConsumeApiKeyResult, DeviceCodeStore, InvitationStore,
    ListOrganizationMembersParams, MemberStore, OrganizationStore, PasskeyStore, SessionStore,
    TwoFactorStore, UserStore, VerificationStore, transaction,
};
use better_auth_core::types::UpdatePasskeyAuthentication;
use better_auth_core::{
    AuthError, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DatabaseError, InvitationStatus, ListUsersParams, UpdateAccount,
    UpdateApiKey, UpdateDeviceCode, UpdateOrganization, UpdateTwoFactor, UpdateUser,
};
use better_auth_diesel::{
    DieselAuthSchema, DieselHookContext, DieselHooks, DieselPool, DieselStore, HookControl,
};
use chrono::{Duration, Utc};
use diesel_async::AsyncMigrationHarness;
use diesel_migrations::MigrationHarness;

fn config() -> Arc<AuthConfig> {
    Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long"))
}

#[cfg(feature = "sqlite")]
async fn sqlite_pool() -> DieselPool {
    let pool = DieselPool::sqlite(":memory:").expect("sqlite pool should build");
    let sqlite = pool
        .as_sqlite()
        .expect("DieselPool::sqlite builds a SQLite pool");
    let connection = sqlite.get().await.expect("sqlite connection");
    let mut harness = AsyncMigrationHarness::new(connection);
    let _ = harness
        .run_pending_migrations(better_auth_diesel::migrations::SQLITE)
        .expect("sqlite migrations should run");
    pool
}

/// A PostgreSQL database created for one test.
#[cfg(feature = "postgres")]
struct PostgresDatabase {
    admin_url: String,
    name: String,
}

#[cfg(feature = "postgres")]
impl PostgresDatabase {
    /// Connect like the store does, so that `sslmode` in the URL applies.
    async fn admin_execute(admin_url: &str, statement: &str) {
        use diesel_async::SimpleAsyncConnection;

        let pool = DieselPool::postgres(admin_url).expect("postgres admin pool");
        let mut connection = pool.get().await.expect("postgres admin connection");
        better_auth_diesel::with_connection!(&mut connection, |c| {
            c.batch_execute(statement).await
        })
        .expect("postgres admin statement should run");
    }

    async fn drop_database(self) {
        Self::admin_execute(
            &self.admin_url,
            &format!("DROP DATABASE {} WITH (FORCE)", self.name),
        )
        .await;
    }
}

#[cfg(feature = "postgres")]
async fn postgres_pool() -> Option<(DieselPool, PostgresDatabase)> {
    let Ok(admin_url) = std::env::var("BETTER_AUTH_DIESEL_POSTGRES_URL") else {
        eprintln!("BETTER_AUTH_DIESEL_POSTGRES_URL is not set; skipping the PostgreSQL run");
        return None;
    };

    let database = format!("better_auth_{}", uuid::Uuid::new_v4().simple());
    PostgresDatabase::admin_execute(&admin_url, &format!("CREATE DATABASE {database}")).await;

    // Swap the database name and keep connection parameters such as `sslmode`.
    let (base, path) = admin_url
        .rsplit_once('/')
        .expect("postgres URL should name a database");
    let parameters = path.find('?').map_or("", |start| &path[start..]);
    let pool =
        DieselPool::postgres(format!("{base}/{database}{parameters}")).expect("postgres pool");
    let postgres = pool
        .as_postgres()
        .expect("DieselPool::postgres builds a PostgreSQL pool");
    let connection = postgres.get().await.expect("postgres connection");
    let mut harness = AsyncMigrationHarness::new(connection);
    let _ = harness
        .run_pending_migrations(better_auth_diesel::migrations::POSTGRES)
        .expect("postgres migrations should run");
    Some((
        pool,
        PostgresDatabase {
            admin_url,
            name: database,
        },
    ))
}

/// Generate one test per backend for each scenario function.
macro_rules! store_tests {
    ($($name:ident),* $(,)?) => {
        #[cfg(feature = "sqlite")]
        mod sqlite {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    super::$name(super::sqlite_pool().await).await;
                }
            )*
        }

        #[cfg(feature = "postgres")]
        mod postgres {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    if let Some((pool, database)) = super::postgres_pool().await {
                        super::$name(pool).await;
                        database.drop_database().await;
                    }
                }
            )*
        }
    };
}

store_tests!(
    users_round_trip,
    user_update_and_ban_lifecycle,
    delete_user_cascades,
    duplicate_email_is_a_constraint_error,
    sessions_round_trip,
    expired_and_inactive_sessions_are_purged,
    accounts_round_trip,
    verifications_round_trip,
    verifications_are_consumed_newest_first,
    transaction_commits_and_rolls_back,
    hooks_can_cancel_and_observe_writes,
    hook_writes_share_the_auth_transaction,
    cancelled_consume_rolls_back_hook_writes,
    failed_deletes_keep_api_keys,
    organizations_members_and_invitations,
    query_organization_members_applies_filter_sort_and_pagination,
    member_sort_without_a_known_field_is_created_at_ascending,
    hooks_can_use_the_pool_outside_a_transaction,
    two_factor_round_trip,
    api_keys_round_trip,
    api_key_usage_is_metered,
    passkeys_round_trip,
    device_codes_round_trip,
    connection_check_succeeds,
);

fn store(pool: DieselPool) -> DieselStore {
    DieselStore::new(config(), pool)
}

async fn create_user(store: &DieselStore, id: &str, email: &str) {
    let _ = store
        .create_user(CreateUser {
            id: Some(id.to_owned()),
            email: Some(email.to_owned()),
            name: Some(format!("User {id}")),
            ..CreateUser::default()
        })
        .await
        .expect("user should be created");
}

fn session_input(user_id: &str, expires_in: Duration) -> CreateSession {
    CreateSession {
        user_id: user_id.to_owned(),
        expires_at: Utc::now() + expires_in,
        ip_address: None,
        user_agent: Some("agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
    }
}

fn account_input(user_id: &str, provider_id: &str, account_id: &str) -> CreateAccount {
    CreateAccount {
        user_id: user_id.to_owned(),
        account_id: account_id.to_owned(),
        provider_id: provider_id.to_owned(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some("hash".to_owned()),
    }
}

fn api_key_input(reference_id: &str, key_hash: &str) -> CreateApiKey {
    CreateApiKey {
        reference_id: reference_id.to_owned(),
        config_id: "default".to_owned(),
        name: Some("key".to_owned()),
        prefix: None,
        key_hash: key_hash.to_owned(),
        start: None,
        expires_at: None,
        remaining: None,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
        refill_interval: None,
        refill_amount: None,
        permissions: None,
        metadata: None,
        enabled: true,
    }
}

async fn users_round_trip(pool: DieselPool) {
    let store = store(pool);
    let user = store
        .create_user(CreateUser {
            id: Some("user-1".to_owned()),
            email: Some("Alice@Example.COM".to_owned()),
            name: Some("Alice".to_owned()),
            username: Some("Alice_W".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("user should be created");

    assert_eq!(user.email(), Some("alice@example.com"));
    assert_eq!(user.username(), Some("alice_w"));
    assert_eq!(user.metadata(), &serde_json::json!({}));
    assert!(!user.email_verified());
    assert!(!user.banned());

    let by_id = store.get_user_by_id("user-1").await.expect("lookup");
    assert_eq!(by_id.as_ref(), Some(&user));
    let by_email = store
        .get_user_by_email("ALICE@example.com")
        .await
        .expect("lookup");
    assert_eq!(by_email.map(|user| user.id), Some("user-1".to_owned()));
    let by_username = store.get_user_by_username("ALICE_w").await.expect("lookup");
    assert_eq!(by_username.map(|user| user.id), Some("user-1".to_owned()));
    assert!(
        store
            .get_user_by_id("missing")
            .await
            .expect("lookup")
            .is_none()
    );

    create_user(&store, "user-2", "bob@example.com").await;
    let mut listed = store
        .list_users_by_ids(&[
            "user-1".to_owned(),
            "user-2".to_owned(),
            "missing".to_owned(),
        ])
        .await
        .expect("list by ids");
    listed.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));
    assert_eq!(
        listed
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        ["user-1", "user-2"]
    );
    assert!(
        store
            .list_users_by_ids(&[])
            .await
            .expect("empty")
            .is_empty()
    );

    let (users, total) = store
        .list_users(ListUsersParams {
            sort_by: Some("email".to_owned()),
            sort_direction: Some("asc".to_owned()),
            ..ListUsersParams::default()
        })
        .await
        .expect("list users");
    assert_eq!(total, 2);
    assert_eq!(users[0].email(), Some("alice@example.com"));
}

async fn user_update_and_ban_lifecycle(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let updated = store
        .update_user(
            "user-1",
            UpdateUser {
                email: Some("NEW@example.com".to_owned()),
                name: Some("Renamed".to_owned()),
                email_verified: Some(true),
                metadata: Some(serde_json::json!({"plan": "pro"})),
                ..UpdateUser::default()
            },
        )
        .await
        .expect("update");
    assert_eq!(updated.email(), Some("new@example.com"));
    assert_eq!(updated.name(), Some("Renamed"));
    assert!(updated.email_verified());
    assert_eq!(updated.metadata()["plan"], "pro");
    assert!(updated.updated_at() >= updated.created_at());

    let expires = Utc::now() + Duration::days(1);
    let banned = store
        .update_user(
            "user-1",
            UpdateUser {
                banned: Some(true),
                ban_reason: Some("spam".to_owned()),
                ban_expires: Some(expires),
                ..UpdateUser::default()
            },
        )
        .await
        .expect("ban");
    assert!(banned.banned());
    assert_eq!(banned.ban_reason(), Some("spam"));
    let stored_expiry = banned.ban_expires().expect("ban expiry");
    assert!((stored_expiry - expires).num_milliseconds().abs() < 1);

    let unbanned = store
        .update_user(
            "user-1",
            UpdateUser {
                banned: Some(false),
                ban_reason: Some("ignored".to_owned()),
                ..UpdateUser::default()
            },
        )
        .await
        .expect("unban");
    assert!(!unbanned.banned());
    assert_eq!(unbanned.ban_reason(), None);
    assert_eq!(unbanned.ban_expires(), None);

    let missing = store
        .update_user("missing", UpdateUser::default())
        .await
        .expect_err("missing user");
    assert!(matches!(missing, AuthError::UserNotFound));
}

async fn delete_user_cascades(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;
    let session = store
        .create_session(session_input("user-1", Duration::hours(1)))
        .await
        .expect("session");
    let _ = store
        .create_account(account_input("user-1", "credential", "user-1"))
        .await
        .expect("account");
    let key = store
        .create_api_key(api_key_input("user-1", "hash-1"))
        .await
        .expect("api key");

    store.delete_user("user-1").await.expect("delete");

    assert!(
        store
            .get_user_by_id("user-1")
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        store
            .get_session(session.token())
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        store
            .get_user_accounts("user-1")
            .await
            .expect("lookup")
            .is_empty()
    );
    assert!(
        store
            .get_api_key_by_id(&key.id)
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(matches!(
        store.delete_user("user-1").await,
        Err(AuthError::UserNotFound)
    ));
}

async fn duplicate_email_is_a_constraint_error(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;
    let err = store
        .create_user(CreateUser {
            email: Some("ALICE@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect_err("duplicate email");
    assert!(matches!(
        err,
        AuthError::Database(DatabaseError::UniqueConstraint(_))
    ));
}

async fn sessions_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let first = store
        .create_session(session_input("user-1", Duration::hours(1)))
        .await
        .expect("session");
    assert!(first.token().starts_with("session_"));
    assert_eq!(first.ip_address(), Some(""));
    assert_eq!(first.user_agent(), Some("agent"));
    assert!(first.active());
    let second = store
        .create_session(session_input("user-1", Duration::hours(2)))
        .await
        .expect("session");

    let fetched = store
        .get_session(first.token())
        .await
        .expect("lookup")
        .expect("session exists");
    assert_eq!(fetched, first);

    let mut sessions = store
        .get_user_sessions("user-1")
        .await
        .expect("list")
        .into_iter()
        .map(|session| session.id)
        .collect::<Vec<_>>();
    sessions.sort();
    let mut expected = vec![first.id.clone(), second.id.clone()];
    expected.sort();
    assert_eq!(sessions, expected);

    let touched = store
        .update_session_fields(first.token(), serde_json::Map::new())
        .await
        .expect("touch")
        .expect("session exists");
    assert!(touched.updated_at() >= first.updated_at());
    let mut fields = serde_json::Map::new();
    let _ = fields.insert("theme".to_owned(), serde_json::json!("dark"));
    assert!(matches!(
        store.update_session_fields(first.token(), fields).await,
        Err(AuthError::Config(_))
    ));
    assert!(
        store
            .update_session_fields("missing", serde_json::Map::new())
            .await
            .expect("lookup")
            .is_none()
    );

    let new_expiry = Utc::now() + Duration::days(7);
    store
        .update_session_expiry(first.token(), new_expiry)
        .await
        .expect("extend");
    let extended = store
        .get_session(first.token())
        .await
        .expect("lookup")
        .expect("session exists");
    assert!(
        (extended.expires_at() - new_expiry)
            .num_milliseconds()
            .abs()
            < 1
    );
    assert!(matches!(
        store.update_session_expiry("missing", new_expiry).await,
        Err(AuthError::SessionNotFound)
    ));

    let with_org = store
        .update_session_active_organization(first.token(), Some("org-1"))
        .await
        .expect("set active org");
    assert_eq!(with_org.active_organization_id(), Some("org-1"));
    let cleared = store
        .update_session_active_organization(first.token(), None)
        .await
        .expect("clear active org");
    assert_eq!(cleared.active_organization_id(), None);

    store.delete_session(first.token()).await.expect("delete");
    assert!(
        store
            .get_session(first.token())
            .await
            .expect("lookup")
            .is_none()
    );

    store
        .delete_user_sessions("user-1")
        .await
        .expect("delete all");
    assert!(
        store
            .get_user_sessions("user-1")
            .await
            .expect("list")
            .is_empty()
    );
}

async fn expired_and_inactive_sessions_are_purged(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;
    let live = store
        .create_session(session_input("user-1", Duration::hours(1)))
        .await
        .expect("live session");
    // Sub-second offsets check that timestamps compare in time order, which
    // on SQLite depends on the fixed-width text encoding.
    let _ = store
        .create_session(session_input("user-1", Duration::milliseconds(-1)))
        .await
        .expect("expired session");
    let _ = store
        .create_session(session_input("user-1", Duration::seconds(-30)))
        .await
        .expect("expired session");

    let removed = store.delete_expired_sessions().await.expect("purge");
    assert_eq!(removed, 2);
    let remaining = store.get_user_sessions("user-1").await.expect("list");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id(), live.id());
}

async fn accounts_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let credential = store
        .create_account(account_input("user-1", "credential", "user-1"))
        .await
        .expect("account");
    let github = store
        .create_account(account_input("user-1", "github", "gh-1"))
        .await
        .expect("account");

    let fetched = store
        .get_account("github", "gh-1")
        .await
        .expect("lookup")
        .expect("account exists");
    assert_eq!(fetched, github);

    let accounts = store.get_user_accounts("user-1").await.expect("list");
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id(), github.id());

    let token_expiry = Utc::now() + Duration::hours(1);
    let updated = store
        .update_account(
            &credential.id,
            UpdateAccount {
                access_token: Some("access".to_owned()),
                access_token_expires_at: Some(token_expiry),
                ..UpdateAccount::default()
            },
        )
        .await
        .expect("update");
    assert_eq!(updated.access_token(), Some("access"));
    assert_eq!(updated.password(), Some("hash"));
    assert!(updated.access_token_expires_at().is_some());

    assert!(matches!(
        store
            .update_account("missing", UpdateAccount::default())
            .await,
        Err(AuthError::NotFound(_))
    ));

    store.delete_account(&github.id).await.expect("delete");
    assert!(
        store
            .get_account("github", "gh-1")
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(matches!(
        store.delete_account(&github.id).await,
        Err(AuthError::NotFound(_))
    ));
}

async fn verifications_round_trip(pool: DieselPool) {
    let store = store(pool);
    let created = store
        .create_verification(CreateVerification {
            identifier: "reset:alice".to_owned(),
            value: "token-1".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("verification");
    let _ = store
        .create_verification(CreateVerification {
            identifier: "reset:bob".to_owned(),
            value: "token-2".to_owned(),
            expires_at: Utc::now() - Duration::seconds(1),
        })
        .await
        .expect("expired verification");

    let fetched = store
        .get_verification("reset:alice", "token-1")
        .await
        .expect("lookup")
        .expect("verification exists");
    assert_eq!(fetched, created);
    assert!(
        store
            .get_verification("reset:bob", "token-2")
            .await
            .expect("lookup")
            .is_none()
    );
    assert_eq!(
        store
            .get_verification_by_value("token-1")
            .await
            .expect("lookup")
            .map(|verification| verification.identifier().to_owned()),
        Some("reset:alice".to_owned())
    );
    assert!(
        store
            .get_verification_by_identifier("reset:alice")
            .await
            .expect("lookup")
            .is_some()
    );

    let consumed = store
        .consume_verification("reset:alice", "token-1")
        .await
        .expect("consume");
    assert_eq!(
        consumed.map(|verification| verification.id),
        Some(created.id)
    );
    assert!(
        store
            .consume_verification("reset:alice", "token-1")
            .await
            .expect("consume")
            .is_none()
    );

    let removed = store.delete_expired_verifications().await.expect("purge");
    assert_eq!(removed, 1);

    let other = store
        .create_verification(CreateVerification {
            identifier: "verify:carol".to_owned(),
            value: "token-3".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("verification");
    store.delete_verification(&other.id).await.expect("delete");
    assert!(
        store
            .get_verification_by_identifier("verify:carol")
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn verifications_are_consumed_newest_first(pool: DieselPool) {
    let store = store(pool);
    for value in ["older", "newer"] {
        let _ = store
            .create_verification(CreateVerification {
                identifier: "otp:alice".to_owned(),
                value: value.to_owned(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .expect("verification");
        // Keep `created_at` distinct at microsecond precision.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // An older value no longer matches: nothing is consumed.
    assert!(
        store
            .consume_verification("otp:alice", "older")
            .await
            .expect("consume")
            .is_none()
    );
    let consumed = store
        .consume_verification_by_identifier("otp:alice")
        .await
        .expect("consume")
        .expect("newest record");
    assert_eq!(consumed.value, "newer");
    assert!(
        store
            .get_verification_by_identifier("otp:alice")
            .await
            .expect("lookup")
            .is_none(),
        "consuming removes every record for the identifier"
    );

    // An expired record is consumed but not returned.
    let _ = store
        .create_verification(CreateVerification {
            identifier: "otp:bob".to_owned(),
            value: "stale".to_owned(),
            expires_at: Utc::now() - Duration::seconds(1),
        })
        .await
        .expect("expired verification");
    assert!(
        store
            .consume_verification_by_identifier("otp:bob")
            .await
            .expect("consume")
            .is_none()
    );
    assert_eq!(
        store.delete_expired_verifications().await.expect("purge"),
        0,
        "the expired record was consumed"
    );
}

async fn transaction_commits_and_rolls_back(pool: DieselPool) {
    let store = store(pool);
    let auth_store: &dyn AuthStore<DieselAuthSchema> = &store;

    let session = transaction(auth_store, |tx| {
        Box::pin(async move {
            let user = tx
                .create_user(CreateUser {
                    id: Some("user-1".to_owned()),
                    email: Some("alice@example.com".to_owned()),
                    ..CreateUser::default()
                })
                .await?;
            let _ = tx
                .create_account(account_input(&user.id, "credential", &user.id))
                .await?;
            tx.create_session(session_input(&user.id, Duration::hours(1)))
                .await
        })
    })
    .await
    .expect("transaction should commit");

    assert!(
        store
            .get_user_by_id("user-1")
            .await
            .expect("lookup")
            .is_some()
    );
    assert!(
        store
            .get_session(session.token())
            .await
            .expect("lookup")
            .is_some()
    );

    let result = transaction(auth_store, |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser {
                    id: Some("user-2".to_owned()),
                    email: Some("bob@example.com".to_owned()),
                    ..CreateUser::default()
                })
                .await?;
            Err::<(), _>(AuthError::internal("abort"))
        })
    })
    .await;

    assert!(result.is_err());
    assert!(
        store
            .get_user_by_id("user-2")
            .await
            .expect("lookup")
            .is_none()
    );
}

#[derive(Default)]
struct HookObservations {
    saw_transaction: AtomicBool,
    saw_delete: AtomicBool,
}

struct RecordingHooks(Arc<HookObservations>);

#[async_trait]
impl DieselHooks for RecordingHooks {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &DieselHookContext<'_>,
    ) -> better_auth_core::AuthResult<HookControl> {
        if ctx.in_transaction {
            self.0.saw_transaction.store(true, Ordering::SeqCst);
        }
        if user.email.as_deref() == Some("blocked@example.com") {
            return Ok(HookControl::Cancel);
        }
        user.name = Some("Hooked".to_owned());
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _session: &better_auth_diesel::models::Session,
        _ctx: &DieselHookContext<'_>,
    ) -> better_auth_core::AuthResult<()> {
        self.0.saw_delete.store(true, Ordering::SeqCst);
        Ok(())
    }
}

async fn hooks_can_cancel_and_observe_writes(pool: DieselPool) {
    let hooks = Arc::new(HookObservations::default());
    let store = store(pool).hook(RecordingHooks(Arc::clone(&hooks)));

    let blocked = store
        .create_user(CreateUser {
            email: Some("blocked@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect_err("hook should cancel");
    assert!(matches!(blocked, AuthError::Forbidden(_)));

    let user = store
        .create_user(CreateUser {
            id: Some("user-1".to_owned()),
            email: Some("alice@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("user");
    assert_eq!(user.name(), Some("Hooked"));
    assert!(!hooks.saw_transaction.load(Ordering::SeqCst));

    let auth_store: &dyn AuthStore<DieselAuthSchema> = &store;
    let _ = transaction(auth_store, |tx| {
        Box::pin(async move {
            tx.create_user(CreateUser {
                email: Some("bob@example.com".to_owned()),
                ..CreateUser::default()
            })
            .await
        })
    })
    .await
    .expect("transaction");
    assert!(hooks.saw_transaction.load(Ordering::SeqCst));

    let session = store
        .create_session(session_input("user-1", Duration::hours(1)))
        .await
        .expect("session");
    store.delete_session(session.token()).await.expect("delete");
    assert!(hooks.saw_delete.load(Ordering::SeqCst));
}

diesel::table! {
    app_workspaces (user_id) {
        user_id -> Text,
    }
}

/// Provisions an application row for every new user on the connection of
/// the auth write.
struct ProvisioningHook;

#[async_trait]
impl DieselHooks for ProvisioningHook {
    async fn after_create_user(
        &self,
        user: &better_auth_diesel::models::User,
        ctx: &DieselHookContext<'_>,
    ) -> better_auth_core::AuthResult<()> {
        use diesel::ExpressionMethods;
        use diesel_async::RunQueryDsl;

        let mut connection = ctx.connection().await?;
        let _ = better_auth_diesel::with_connection!(&mut *connection, |c| {
            diesel::insert_into(app_workspaces::table)
                .values(app_workspaces::user_id.eq(&user.id))
                .execute(c)
                .await
        })
        .map_err(|err| AuthError::Database(DatabaseError::Query(err.to_string())))?;
        Ok(())
    }
}

async fn workspace_count(pool: &DieselPool) -> i64 {
    use diesel::QueryDsl;
    use diesel_async::RunQueryDsl;

    let mut connection = pool.get().await.expect("connection");
    better_auth_diesel::with_connection!(&mut connection, |c| {
        app_workspaces::table.count().get_result(c).await
    })
    .expect("count workspaces")
}

/// Run application DDL or DML that the tests need besides the auth schema.
async fn execute_sql(pool: &DieselPool, sql: &str) {
    use diesel_async::SimpleAsyncConnection;

    let mut connection = pool.get().await.expect("connection");
    better_auth_diesel::with_connection!(&mut connection, |c| c.batch_execute(sql).await)
        .expect("application SQL should run");
}

async fn hook_writes_share_the_auth_transaction(pool: DieselPool) {
    execute_sql(
        &pool,
        "CREATE TABLE app_workspaces (user_id TEXT PRIMARY KEY)",
    )
    .await;
    let store = store(pool.clone()).hook(ProvisioningHook);
    let auth_store: &dyn AuthStore<DieselAuthSchema> = &store;

    let rolled_back = transaction(auth_store, |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser {
                    email: Some("rollback@example.com".to_owned()),
                    ..CreateUser::default()
                })
                .await?;
            Err::<(), _>(AuthError::internal("abort"))
        })
    })
    .await;
    assert!(rolled_back.is_err());
    assert_eq!(workspace_count(&pool).await, 0);

    let _ = transaction(auth_store, |tx| {
        Box::pin(async move {
            tx.create_user(CreateUser {
                email: Some("commit@example.com".to_owned()),
                ..CreateUser::default()
            })
            .await
        })
    })
    .await
    .expect("transaction");
    assert_eq!(workspace_count(&pool).await, 1);

    let _ = store
        .create_user(CreateUser {
            email: Some("direct@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("user");
    assert_eq!(workspace_count(&pool).await, 2);
}

/// Records a workspace row and then cancels the verification deletion.
struct CancellingVerificationHook;

#[async_trait]
impl DieselHooks for CancellingVerificationHook {
    async fn before_delete_verification(
        &self,
        verification: &better_auth_diesel::models::Verification,
        ctx: &DieselHookContext<'_>,
    ) -> better_auth_core::AuthResult<HookControl> {
        use diesel::ExpressionMethods;
        use diesel_async::RunQueryDsl;

        let mut connection = ctx.connection().await?;
        let _ = better_auth_diesel::with_connection!(&mut *connection, |c| {
            diesel::insert_into(app_workspaces::table)
                .values(app_workspaces::user_id.eq(&verification.identifier))
                .execute(c)
                .await
        })
        .map_err(|err| AuthError::Database(DatabaseError::Query(err.to_string())))?;
        Ok(HookControl::Cancel)
    }
}

async fn cancelled_consume_rolls_back_hook_writes(pool: DieselPool) {
    execute_sql(
        &pool,
        "CREATE TABLE app_workspaces (user_id TEXT PRIMARY KEY)",
    )
    .await;
    let store = store(pool.clone()).hook(CancellingVerificationHook);
    let _ = store
        .create_verification(CreateVerification {
            identifier: "otp:alice".to_owned(),
            value: "token".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("verification");

    assert!(
        store
            .consume_verification("otp:alice", "token")
            .await
            .expect("consume")
            .is_none()
    );
    assert!(
        store
            .get_verification("otp:alice", "token")
            .await
            .expect("lookup")
            .is_some(),
        "a cancelled consume keeps the record"
    );
    assert_eq!(
        workspace_count(&pool).await,
        0,
        "a cancelled consume discards the hook's writes"
    );
}

async fn failed_deletes_keep_api_keys(pool: DieselPool) {
    // Application rows that block deletion through restrictive foreign keys.
    execute_sql(
        &pool,
        "CREATE TABLE app_profiles (user_id TEXT NOT NULL REFERENCES users (id));
         CREATE TABLE app_projects (organization_id TEXT NOT NULL REFERENCES organization (id));",
    )
    .await;
    let store = store(pool.clone());
    create_user(&store, "user-1", "alice@example.com").await;
    let _ = store
        .create_organization(CreateOrganization {
            id: Some("org-1".to_owned()),
            name: "Org".to_owned(),
            slug: "org".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization");
    execute_sql(
        &pool,
        "INSERT INTO app_profiles (user_id) VALUES ('user-1');
         INSERT INTO app_projects (organization_id) VALUES ('org-1');",
    )
    .await;
    let user_key = store
        .create_api_key(api_key_input("user-1", "user-hash"))
        .await
        .expect("user key");
    let org_key = store
        .create_api_key(api_key_input("org-1", "org-hash"))
        .await
        .expect("organization key");

    assert!(store.delete_user("user-1").await.is_err());
    assert!(store.delete_organization("org-1").await.is_err());
    for key in [&user_key, &org_key] {
        assert!(
            store
                .get_api_key_by_id(&key.id)
                .await
                .expect("lookup")
                .is_some(),
            "a failed deletion keeps the owner's API keys"
        );
    }
}

async fn organizations_members_and_invitations(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "owner", "owner@example.com").await;
    create_user(&store, "member", "member@example.com").await;

    let organization = store
        .create_organization(CreateOrganization {
            id: Some("org-1".to_owned()),
            name: "Org".to_owned(),
            slug: "org".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization");
    assert_eq!(organization.metadata, Some(serde_json::json!({})));
    let _ = store
        .create_organization(CreateOrganization::new("Other", "other"))
        .await
        .expect("organization");

    assert_eq!(
        store
            .get_organization_by_slug("org")
            .await
            .expect("lookup")
            .map(|org| org.id),
        Some("org-1".to_owned())
    );
    assert_eq!(
        store
            .list_organizations_by_ids(&["org-1".to_owned()])
            .await
            .expect("list")
            .len(),
        1
    );

    let renamed = store
        .update_organization(
            "org-1",
            UpdateOrganization {
                name: Some("Renamed".to_owned()),
                metadata: Some(serde_json::json!({"tier": 2})),
                ..UpdateOrganization::default()
            },
        )
        .await
        .expect("update");
    assert_eq!(renamed.name, "Renamed");
    assert_eq!(renamed.metadata, Some(serde_json::json!({"tier": 2})));

    let owner = store
        .create_member(CreateMember::new("org-1", "owner", "owner"))
        .await
        .expect("owner");
    let member = store
        .create_member(CreateMember::new("org-1", "member", "member"))
        .await
        .expect("member");
    assert!(
        store
            .create_member(CreateMember::new("org-1", "member", "admin"))
            .await
            .is_err(),
        "a user is a member of an organization at most once"
    );

    assert_eq!(
        store
            .get_member("org-1", "member")
            .await
            .expect("lookup")
            .map(|found| found.id),
        Some(member.id.clone())
    );
    let promoted = store
        .update_member_role(&member.id, "admin")
        .await
        .expect("promote");
    assert_eq!(promoted.role, "admin");
    assert_eq!(
        store
            .list_organization_members("org-1")
            .await
            .expect("list")
            .iter()
            .map(|found| found.id.as_str())
            .collect::<Vec<_>>(),
        [owner.id.as_str(), member.id.as_str()]
    );
    assert_eq!(
        store
            .count_organization_members("org-1")
            .await
            .expect("count"),
        2
    );
    assert_eq!(
        store
            .count_organization_owners("org-1")
            .await
            .expect("count"),
        1
    );
    assert_eq!(
        store
            .list_user_organizations("member")
            .await
            .expect("list")
            .iter()
            .map(|org| org.id.as_str())
            .collect::<Vec<_>>(),
        ["org-1"]
    );

    let pending = store
        .create_invitation(CreateInvitation::new(
            "org-1",
            "invitee@example.com",
            "member",
            "owner",
            Utc::now() + Duration::hours(1),
        ))
        .await
        .expect("invitation");
    let canceled = store
        .create_invitation(CreateInvitation::new(
            "org-1",
            "second@example.com",
            "member",
            "owner",
            Utc::now() + Duration::hours(1),
        ))
        .await
        .expect("invitation");
    let _ = store
        .update_invitation_status(&canceled.id, InvitationStatus::Canceled)
        .await
        .expect("cancel");
    let _ = store
        .create_invitation(CreateInvitation::new(
            "org-1",
            "invitee@example.com",
            "member",
            "owner",
            Utc::now() - Duration::hours(1),
        ))
        .await
        .expect("expired invitation");

    assert_eq!(
        store
            .count_pending_organization_invitations("org-1")
            .await
            .expect("count"),
        1
    );
    assert_eq!(
        store
            .get_pending_invitation("org-1", "INVITEE@example.com")
            .await
            .expect("lookup")
            .map(|invitation| invitation.id),
        Some(pending.id.clone())
    );
    assert_eq!(
        store
            .list_user_invitations("invitee@example.com")
            .await
            .expect("list")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_organization_invitations("org-1")
            .await
            .expect("list")
            .len(),
        3
    );
    let renewed_until = Utc::now() + Duration::days(7);
    let renewed = store
        .update_invitation_expiry(&pending.id, renewed_until)
        .await
        .expect("renew");
    assert!(
        (renewed.expires_at - renewed_until)
            .num_milliseconds()
            .abs()
            < 1
    );
    assert_eq!(renewed.role, pending.role);
    assert!(matches!(
        store
            .update_invitation_expiry("missing", renewed_until)
            .await,
        Err(AuthError::NotFound(_))
    ));

    let accepted = store
        .update_invitation_status(&pending.id, InvitationStatus::Accepted)
        .await
        .expect("accept");
    assert_eq!(accepted.status, InvitationStatus::Accepted);

    store
        .delete_member(&member.id)
        .await
        .expect("delete member");
    assert!(
        store
            .get_member_by_id(&member.id)
            .await
            .expect("lookup")
            .is_none()
    );

    let org_key = store
        .create_api_key(api_key_input("org-1", "org-hash"))
        .await
        .expect("org api key");
    store.delete_organization("org-1").await.expect("delete");
    assert!(
        store
            .get_organization_by_id("org-1")
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        store
            .get_member_by_id(&owner.id)
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        store
            .get_api_key_by_id(&org_key.id)
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn query_organization_members_applies_filter_sort_and_pagination(pool: DieselPool) {
    let store = store(pool);
    let _ = store
        .create_organization(CreateOrganization {
            id: Some("org-1".to_owned()),
            name: "Org".to_owned(),
            slug: "org".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization");
    for (user, role) in [
        ("user-owner", "owner"),
        ("user-member", "member"),
        ("user-admin", "admin"),
    ] {
        create_user(&store, user, &format!("{user}@example.com")).await;
        let _ = store
            .create_member(CreateMember::new("org-1", user, role))
            .await
            .expect("member");
    }

    let params = ListOrganizationMembersParams {
        organization_id: "org-1".to_owned(),
        limit: Some(1),
        offset: Some(1),
        sort_by: Some("role".to_owned()),
        sort_direction: Some("asc".to_owned()),
        filter_field: Some("role".to_owned()),
        filter_value: Some("owner".to_owned()),
        filter_operator: Some("ne".to_owned()),
    };
    let (members, total) = store
        .query_organization_members(&params)
        .await
        .expect("query");
    assert_eq!(total, 2);
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, "member");

    let contains = ListOrganizationMembersParams {
        organization_id: "org-1".to_owned(),
        filter_field: Some("userId".to_owned()),
        filter_value: Some("adm".to_owned()),
        filter_operator: Some("contains".to_owned()),
        ..ListOrganizationMembersParams::default()
    };
    let (members, total) = store
        .query_organization_members(&contains)
        .await
        .expect("query");
    assert_eq!(total, 1);
    assert_eq!(members[0].user_id, "user-admin");

    // `_` and `%` match literally: no user id contains "r_".
    let literal = ListOrganizationMembersParams {
        filter_value: Some("r_".to_owned()),
        ..contains.clone()
    };
    let (_, total) = store
        .query_organization_members(&literal)
        .await
        .expect("query");
    assert_eq!(total, 0);

    let bad_date = ListOrganizationMembersParams {
        organization_id: "org-1".to_owned(),
        filter_field: Some("createdAt".to_owned()),
        filter_value: Some("not-a-date".to_owned()),
        ..ListOrganizationMembersParams::default()
    };
    let (members, total) = store
        .query_organization_members(&bad_date)
        .await
        .expect("query");
    assert_eq!((members.len(), total), (0, 0));

    let since = ListOrganizationMembersParams {
        organization_id: "org-1".to_owned(),
        filter_field: Some("createdAt".to_owned()),
        filter_value: Some((Utc::now() - Duration::hours(1)).to_rfc3339()),
        filter_operator: Some("gte".to_owned()),
        sort_by: Some("createdAt".to_owned()),
        sort_direction: Some("desc".to_owned()),
        ..ListOrganizationMembersParams::default()
    };
    let (members, total) = store
        .query_organization_members(&since)
        .await
        .expect("query");
    assert_eq!(total, 3);
    assert_eq!(members[0].user_id, "user-admin");
}

async fn member_sort_without_a_known_field_is_created_at_ascending(pool: DieselPool) {
    let store = store(pool);
    let _ = store
        .create_organization(CreateOrganization::new("Org", "org"))
        .await
        .expect("organization");
    let organization_id = store
        .get_organization_by_slug("org")
        .await
        .expect("lookup")
        .expect("organization exists")
        .id;
    let mut created = Vec::new();
    for user in ["user-c", "user-a", "user-b"] {
        create_user(&store, user, &format!("{user}@example.com")).await;
        let member = store
            .create_member(CreateMember::new(&organization_id, user, "member"))
            .await
            .expect("member");
        created.push(member.id);
        // Keep `created_at` distinct at microsecond precision.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    for sort_by in [None, Some("unknownField".to_owned())] {
        let params = ListOrganizationMembersParams {
            organization_id: organization_id.clone(),
            sort_by,
            sort_direction: Some("desc".to_owned()),
            ..ListOrganizationMembersParams::default()
        };
        let (members, _) = store
            .query_organization_members(&params)
            .await
            .expect("query");
        assert_eq!(
            members
                .into_iter()
                .map(|member| member.id)
                .collect::<Vec<_>>(),
            created
        );
    }
}

/// Reads the user count through the pool from `before_create_user`.
struct PoolReadingHook;

#[async_trait]
impl DieselHooks for PoolReadingHook {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        ctx: &DieselHookContext<'_>,
    ) -> better_auth_core::AuthResult<HookControl> {
        use diesel::QueryDsl;
        use diesel_async::RunQueryDsl;

        let mut connection = ctx.pool.get().await?;
        let _: i64 = better_auth_diesel::with_connection!(&mut connection, |c| {
            better_auth_diesel::schema::users::table
                .count()
                .get_result(c)
                .await
        })
        .map_err(|err| AuthError::Database(DatabaseError::Query(err.to_string())))?;
        Ok(HookControl::Continue)
    }
}

async fn hooks_can_use_the_pool_outside_a_transaction(pool: DieselPool) {
    // A write checks out its own connection only after its `before_*`
    // hooks, so a hook can use the pool even when it holds one connection.
    let store = store(pool).hook(PoolReadingHook);
    let created = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        store.create_user(CreateUser {
            email: Some("alice@example.com".to_owned()),
            ..CreateUser::default()
        }),
    )
    .await
    .expect("a hook using the pool must not deadlock the write");
    let _ = created.expect("user");
}

async fn two_factor_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let created = store
        .create_two_factor(CreateTwoFactor {
            user_id: "user-1".to_owned(),
            secret: "secret".to_owned(),
            backup_codes: "a,b".to_owned(),
            verified: false,
        })
        .await
        .expect("two factor");
    assert!(!created.verified);
    assert_eq!(created.failed_verification_count, 0);
    assert!(created.locked_until.is_none());
    assert_eq!(
        store
            .get_two_factor_by_user_id("user-1")
            .await
            .expect("lookup")
            .map(|found| found.id),
        Some(created.id.clone())
    );
    let updated = store
        .update_two_factor_backup_codes("user-1", "c,d")
        .await
        .expect("update");
    assert_eq!(updated.backup_codes, "c,d");

    let enrolled = store
        .update_two_factor(
            &created.id,
            UpdateTwoFactor {
                verified: Some(true),
                ..UpdateTwoFactor::default()
            },
        )
        .await
        .expect("enroll");
    assert!(enrolled.verified);
    assert_eq!(enrolled.secret, "secret");
    assert!(matches!(
        store
            .update_two_factor("missing", UpdateTwoFactor::default())
            .await,
        Err(AuthError::NotFound(_))
    ));

    assert!(
        store
            .compare_exchange_two_factor_backup_codes(&created.id, "c,d", "e,f")
            .await
            .expect("swap")
    );
    assert!(
        !store
            .compare_exchange_two_factor_backup_codes(&created.id, "c,d", "g,h")
            .await
            .expect("stale swap")
    );

    let lock = Utc::now() + Duration::minutes(15);
    store
        .record_two_factor_failure(&created.id, 2, lock)
        .await
        .expect("first failure");
    let factor = store
        .get_two_factor_by_user_id("user-1")
        .await
        .expect("lookup")
        .expect("factor exists");
    assert_eq!(factor.failed_verification_count, 1);
    assert!(factor.locked_until.is_none());
    store
        .record_two_factor_failure(&created.id, 2, lock)
        .await
        .expect("second failure");
    let factor = store
        .get_two_factor_by_user_id("user-1")
        .await
        .expect("lookup")
        .expect("factor exists");
    assert_eq!(factor.failed_verification_count, 2);
    assert!(factor.locked_until.is_some());

    store
        .reset_two_factor_failures(&created.id, Some(Utc::now()))
        .await
        .expect("reset of an active lock");
    let factor = store
        .get_two_factor_by_user_id("user-1")
        .await
        .expect("lookup")
        .expect("factor exists");
    assert_eq!(
        factor.failed_verification_count, 2,
        "the lock has not expired"
    );
    store
        .reset_two_factor_failures(&created.id, None)
        .await
        .expect("reset");
    let factor = store
        .get_two_factor_by_user_id("user-1")
        .await
        .expect("lookup")
        .expect("factor exists");
    assert_eq!(factor.failed_verification_count, 0);
    assert!(factor.locked_until.is_none());
    assert!(matches!(
        store.update_two_factor_backup_codes("missing", "x").await,
        Err(AuthError::NotFound(_))
    ));
    store.delete_two_factor("user-1").await.expect("delete");
    assert!(
        store
            .get_two_factor_by_user_id("user-1")
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn api_keys_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let first = store
        .create_api_key(CreateApiKey {
            expires_at: Some((Utc::now() + Duration::days(1)).to_rfc3339()),
            remaining: Some(5.0),
            ..api_key_input("user-1", "hash-1")
        })
        .await
        .expect("api key");
    assert_eq!(first.request_count, Some(0.0));
    assert_eq!(first.remaining, Some(5.0));
    assert!(first.expires_at.is_some());
    let second = store
        .create_api_key(api_key_input("user-1", "hash-2"))
        .await
        .expect("api key");

    assert_eq!(
        store
            .get_api_key_by_hash("hash-2")
            .await
            .expect("lookup")
            .map(|key| key.id),
        Some(second.id.clone())
    );
    assert_eq!(
        store
            .list_api_keys_by_reference("user-1")
            .await
            .expect("list")
            .iter()
            .map(|key| key.id.as_str())
            .collect::<Vec<_>>(),
        [first.id.as_str(), second.id.as_str()]
    );

    let updated = store
        .update_api_key(
            &first.id,
            UpdateApiKey {
                name: Some("renamed".to_owned()),
                enabled: Some(false),
                expires_at: Some(None),
                ..UpdateApiKey::default()
            },
        )
        .await
        .expect("update");
    assert_eq!(updated.name.as_deref(), Some("renamed"));
    assert!(!updated.enabled);
    assert_eq!(updated.expires_at, None);
    assert!(matches!(
        store
            .update_api_key(
                &first.id,
                UpdateApiKey {
                    expires_at: Some(Some("yesterday".to_owned())),
                    ..UpdateApiKey::default()
                },
            )
            .await,
        Err(AuthError::BadRequest(_))
    ));
    assert!(matches!(
        store
            .update_api_key("missing", UpdateApiKey::default())
            .await,
        Err(AuthError::NotFound(_))
    ));

    let _ = store
        .create_api_key(CreateApiKey {
            expires_at: Some((Utc::now() - Duration::seconds(1)).to_rfc3339()),
            ..api_key_input("user-1", "hash-3")
        })
        .await
        .expect("expired api key");
    assert_eq!(store.delete_expired_api_keys().await.expect("purge"), 1);

    store.delete_api_key(&second.id).await.expect("delete");
    assert!(
        store
            .get_api_key_by_id(&second.id)
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn api_key_usage_is_metered(pool: DieselPool) {
    let store = store(pool);

    let limited = store
        .create_api_key(CreateApiKey {
            remaining: Some(1.0),
            ..api_key_input("user-1", "limited")
        })
        .await
        .expect("api key");
    let ConsumeApiKeyResult::Allowed(key) = store
        .consume_api_key_usage(&limited.id, false)
        .await
        .expect("consume")
    else {
        panic!("first use should be allowed");
    };
    assert_eq!(key.remaining, Some(0.0));
    assert!(key.last_request.is_some());
    assert!(matches!(
        store.consume_api_key_usage(&limited.id, false).await,
        Ok(ConsumeApiKeyResult::UsageExhausted)
    ));
    assert!(
        store
            .get_api_key_by_id(&limited.id)
            .await
            .expect("lookup")
            .is_none(),
        "an exhausted key without refill is deleted"
    );

    let rate_limited = store
        .create_api_key(CreateApiKey {
            rate_limit_enabled: true,
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(2.0),
            ..api_key_input("user-1", "rate-limited")
        })
        .await
        .expect("api key");
    for expected in [1.0, 2.0] {
        let ConsumeApiKeyResult::Allowed(key) = store
            .consume_api_key_usage(&rate_limited.id, true)
            .await
            .expect("consume")
        else {
            panic!("use within the limit should be allowed");
        };
        assert_eq!(key.request_count, Some(expected));
    }
    let Ok(ConsumeApiKeyResult::RateLimited { try_again_in }) =
        store.consume_api_key_usage(&rate_limited.id, true).await
    else {
        panic!("a use over the limit should be rate limited");
    };
    assert!(try_again_in > 0.0 && try_again_in <= 60_000.0);
    assert!(matches!(
        store.consume_api_key_usage(&rate_limited.id, false).await,
        Ok(ConsumeApiKeyResult::Allowed(_))
    ));

    // A rate-limited request still spends quota but keeps the window.
    let quota = store
        .create_api_key(CreateApiKey {
            remaining: Some(10.0),
            rate_limit_enabled: true,
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(1.0),
            ..api_key_input("user-1", "quota")
        })
        .await
        .expect("api key");
    assert!(matches!(
        store.consume_api_key_usage(&quota.id, true).await,
        Ok(ConsumeApiKeyResult::Allowed(_))
    ));
    let before = store
        .get_api_key_by_id(&quota.id)
        .await
        .expect("lookup")
        .expect("key exists");
    assert!(matches!(
        store.consume_api_key_usage(&quota.id, true).await,
        Ok(ConsumeApiKeyResult::RateLimited { .. })
    ));
    let after = store
        .get_api_key_by_id(&quota.id)
        .await
        .expect("lookup")
        .expect("key exists");
    assert_eq!(after.remaining, Some(8.0));
    assert_eq!(after.request_count, before.request_count);
    assert_eq!(after.last_request, before.last_request);
    assert_eq!(after.updated_at, before.updated_at);

    assert!(matches!(
        store.consume_api_key_usage("missing", true).await,
        Err(AuthError::NotFound(_))
    ));
}

async fn passkeys_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;

    let passkey = store
        .create_passkey(CreatePasskey {
            user_id: "user-1".to_owned(),
            name: Some("laptop".to_owned()),
            credential_id: "cred-1".to_owned(),
            public_key: "pk".to_owned(),
            counter: 1,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: Some("internal".to_owned()),
            credential: "{}".to_owned(),
            aaguid: None,
        })
        .await
        .expect("passkey");
    assert_eq!(
        store
            .get_passkey_by_credential_id("cred-1")
            .await
            .expect("lookup")
            .map(|found| found.id),
        Some(passkey.id.clone())
    );
    assert_eq!(
        store
            .list_passkeys_by_user("user-1")
            .await
            .expect("list")
            .len(),
        1
    );

    let authenticated = store
        .update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication {
                credential: "{\"v\":2}".to_owned(),
                counter: 7,
                backed_up: true,
                device_type: "multiDevice".to_owned(),
            },
        )
        .await
        .expect("authenticate");
    assert_eq!(authenticated.counter, 7);
    assert!(authenticated.backed_up);
    let renamed = store
        .update_passkey_name(&passkey.id, "phone")
        .await
        .expect("rename");
    assert_eq!(renamed.name.as_deref(), Some("phone"));
    assert!(matches!(
        store.update_passkey_name("missing", "x").await,
        Err(AuthError::NotFound(_))
    ));

    store.delete_passkey(&passkey.id).await.expect("delete");
    assert!(
        store
            .get_passkey_by_id(&passkey.id)
            .await
            .expect("lookup")
            .is_none()
    );
}

async fn device_codes_round_trip(pool: DieselPool) {
    let store = store(pool);
    create_user(&store, "user-1", "alice@example.com").await;
    create_user(&store, "user-2", "bob@example.com").await;

    let code = store
        .create_device_code(CreateDeviceCode {
            device_code: "device-1".to_owned(),
            user_code: "USER-1".to_owned(),
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            status: "pending".to_owned(),
            last_polled_at: None,
            polling_interval: Some(5),
            client_id: Some("cli".to_owned()),
            scope: None,
        })
        .await
        .expect("device code");
    assert_eq!(
        store
            .get_device_code_by_user_code("USER-1")
            .await
            .expect("lookup")
            .map(|found| found.id),
        Some(code.id.clone())
    );

    assert!(
        store
            .claim_device_code(&code.id, "user-1")
            .await
            .expect("claim")
    );
    assert!(
        !store
            .claim_device_code(&code.id, "user-2")
            .await
            .expect("claim"),
        "a claimed code cannot be claimed again"
    );

    let polled_at = Utc::now();
    let polled = store
        .update_device_code(
            &code.id,
            UpdateDeviceCode {
                last_polled_at: Some(Some(polled_at)),
                ..UpdateDeviceCode::default()
            },
        )
        .await
        .expect("poll");
    assert!(polled.last_polled_at.is_some());
    assert_eq!(polled.user_id.as_deref(), Some("user-1"));
    let unchanged = store
        .update_device_code(&code.id, UpdateDeviceCode::default())
        .await
        .expect("no-op update");
    assert_eq!(unchanged.status, "pending");

    let approve = UpdateDeviceCode {
        status: Some("approved".to_owned()),
        ..UpdateDeviceCode::default()
    };
    assert!(
        store
            .update_device_code_if_status(&code.id, "pending", approve.clone())
            .await
            .expect("approve")
    );
    assert!(
        !store
            .update_device_code_if_status(&code.id, "pending", approve)
            .await
            .expect("approve again")
    );
    assert!(
        !store
            .delete_device_code_if_status(&code.id, "pending")
            .await
            .expect("delete with stale status")
    );
    assert!(
        store
            .delete_device_code_if_status(&code.id, "approved")
            .await
            .expect("delete")
    );
    assert!(
        store
            .get_device_code_by_device_code("device-1")
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(matches!(
        store
            .update_device_code(&code.id, UpdateDeviceCode::default())
            .await,
        Err(AuthError::NotFound(_))
    ));
}

async fn connection_check_succeeds(pool: DieselPool) {
    store(pool)
        .test_connection()
        .await
        .expect("connection check");
}
