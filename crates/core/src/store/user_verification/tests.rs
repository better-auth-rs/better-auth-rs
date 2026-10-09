#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Cleanup regressions must fail immediately when setup or hook observations differ"
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use chrono::{Duration, Utc};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};

use super::revoke_unproven_account_access;
use crate::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateSession, CreateUser, FieldMap,
    FieldValue, StatelessSchema, UpdateUser,
    store::{
        AccountStore, EphemeralStore, SessionStore, UserStore, VerificationStore,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
    },
    wire::{AccountView, SessionView, UserView, VerificationView},
};

type Events = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Continue,
    CancelFirstAccount,
    FailFirstAccountAfter,
    CancelUserUpdate,
}

struct CleanupHooks {
    behavior: Behavior,
    fail_lock_release: bool,
    events: Events,
}

impl CleanupHooks {
    fn record(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for CleanupHooks {
    async fn before_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        let subject = account.account_id.typed()?;
        self.record(format!("account:before:{subject}"));
        Ok(
            if self.behavior == Behavior::CancelFirstAccount && subject == "first" {
                DatabaseHookControl::Cancel
            } else {
                DatabaseHookControl::Continue
            },
        )
    }

    async fn after_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let subject = account.account_id.typed()?;
        self.record(format!("account:after:{subject}"));
        if self.behavior == Behavior::FailFirstAccountAfter && subject == "first" {
            return Err(AuthError::internal("account after failed"));
        }
        Ok(())
    }

    async fn before_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record(format!("session:before:{}", session.user_id.typed()?));
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record(format!("session:after:{}", session.user_id.typed()?));
        Ok(())
    }

    async fn before_update_user(
        &self,
        update: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        assert_eq!(
            update,
            &FieldMap::from([("emailVerified".into(), true.into())])
        );
        self.record("user:before");
        Ok(if self.behavior == Behavior::CancelUserUpdate {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(*user.unwrap().email_verified.typed()?);
        self.record("user:after");
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        _: &VerificationView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("lock:before");
        if self.fail_lock_release {
            return Err(AuthError::internal("lock release failed"));
        }
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("lock:after");
        Ok(())
    }
}

struct Fixture {
    store: EphemeralStore,
    events: Events,
    owner_session: SessionView,
    other_session: SessionView,
}

async fn seed_user(store: &EphemeralStore, id: &str) -> AuthResult<SessionView> {
    let _ = store
        .create_user(CreateUser {
            id: Some(id.into()),
            email: Some(format!("{id}@cleanup.test")),
            ..Default::default()
        })
        .await?;
    store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: id.into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
}

impl Fixture {
    async fn new(behavior: Behavior, fail_lock_release: bool) -> AuthResult<Self> {
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        let owner_session = seed_user(&store, "owner").await?;
        let other_session = seed_user(&store, "other").await?;
        for (subject, owner) in [("first", "owner"), ("second", "owner"), ("other", "other")] {
            let _ = store
                .create_account(CreateAccount {
                    id: subject.into(),
                    account_id: subject.into(),
                    provider_id: "cleanup".into(),
                    user_id: owner.into(),
                    ..Default::default()
                })
                .await?;
        }
        let events = Events::default();
        Ok(Self {
            store: store.with_hooks(vec![Arc::new(CleanupHooks {
                behavior,
                fail_lock_release,
                events: events.clone(),
            })]),
            events,
            owner_session,
            other_session,
        })
    }

    async fn assert_state(
        &self,
        accounts: &[&str],
        owner_session_exists: bool,
        verified: bool,
        lock_exists: bool,
    ) -> AuthResult<()> {
        let actual = self
            .store
            .get_user_accounts("owner")
            .await?
            .into_iter()
            .map(|account| account.account_id.display_string())
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(actual, accounts);
        assert_eq!(
            self.store
                .get_session(self.owner_session.token.typed()?)
                .await?
                .is_some(),
            owner_session_exists
        );
        assert_eq!(
            *self
                .store
                .get_user_by_id("owner")
                .await?
                .unwrap()
                .email_verified
                .typed()?,
            verified
        );
        assert_eq!(
            self.store
                .get_verification_including_expired("revoke-unproven-account-access:owner")
                .await?
                .is_some(),
            lock_exists
        );
        assert_eq!(
            self.store
                .get_account("cleanup", "other")
                .await?
                .unwrap()
                .user_id,
            "other"
        );
        assert_eq!(
            self.store
                .get_session(self.other_session.token.typed()?)
                .await?,
            Some(self.other_session.clone())
        );
        assert!(
            !*self
                .store
                .get_user_by_id("other")
                .await?
                .unwrap()
                .email_verified
                .typed()?
        );
        Ok(())
    }
}

#[tokio::test]
async fn cancelled_account_delete_continues_other_cleanup_operations() -> AuthResult<()> {
    let fixture = Fixture::new(Behavior::CancelFirstAccount, false).await?;
    let verified = revoke_unproven_account_access(&fixture.store, &"owner".into())
        .await?
        .unwrap();
    assert!(*verified.email_verified.typed()?);
    assert_eq!(
        *fixture.events.lock().unwrap(),
        [
            "account:before:first",
            "account:before:second",
            "account:after:second",
            "session:before:owner",
            "session:after:owner",
            "user:before",
            "user:after",
            "lock:before",
            "lock:after",
        ]
    );
    fixture.assert_state(&["first"], false, true, false).await
}

#[tokio::test]
async fn account_after_error_preserves_the_deletion_and_stops_later_cleanup() -> AuthResult<()> {
    let fixture = Fixture::new(Behavior::FailFirstAccountAfter, false).await?;
    let error = revoke_unproven_account_access(&fixture.store, &"owner".into())
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::Internal(message) if message == "account after failed"));
    assert_eq!(
        *fixture.events.lock().unwrap(),
        [
            "account:before:first",
            "account:after:first",
            "lock:before",
            "lock:after"
        ]
    );
    fixture.assert_state(&["second"], true, false, false).await
}

#[tokio::test]
async fn cancelled_user_update_returns_none_and_keeps_prior_deletions() -> AuthResult<()> {
    let fixture = Fixture::new(Behavior::CancelUserUpdate, false).await?;
    assert!(
        revoke_unproven_account_access(&fixture.store, &"owner".into())
            .await?
            .is_none()
    );
    assert_eq!(
        *fixture.events.lock().unwrap(),
        [
            "account:before:first",
            "account:after:first",
            "account:before:second",
            "account:after:second",
            "session:before:owner",
            "session:after:owner",
            "user:before",
            "lock:before",
            "lock:after",
        ]
    );
    fixture.assert_state(&[], false, false, false).await
}

#[tokio::test]
async fn lock_release_error_preserves_the_original_success_or_failure() -> AuthResult<()> {
    for behavior in [Behavior::Continue, Behavior::FailFirstAccountAfter] {
        let fixture = Fixture::new(behavior, true).await?;
        let result = revoke_unproven_account_access(&fixture.store, &"owner".into()).await;
        if behavior == Behavior::Continue {
            assert!(*result?.unwrap().email_verified.typed()?);
            fixture.assert_state(&[], false, true, true).await?;
        } else {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "account after failed")
            );
            fixture.assert_state(&["second"], true, false, true).await?;
        }
        let events = fixture.events.lock().unwrap();
        assert_eq!(events.last().map(String::as_str), Some("lock:before"));
        assert!(!events.iter().any(|event| event == "lock:after"));
    }
    Ok(())
}

#[derive(Clone, Default)]
struct DatabaseOperations {
    names: Events,
    next_id: Arc<AtomicU64>,
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "otel.name" && value.starts_with("db ") {
            self.0 = Some(value.into());
        }
    }

    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for DatabaseOperations {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut name = SpanName::default();
        attributes.record(&mut name);
        if let Some(name) = name.0 {
            self.names.lock().unwrap().push(name);
        }
        Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn native_falsy_selectors_skip_user_reads_and_release_the_reservation() -> AuthResult<()> {
    for (native, text) in [
        (FieldValue::Bool(false), "false"),
        (FieldValue::Number(0.0), "0"),
        (FieldValue::Null, "null"),
        (FieldValue::Undefined, "undefined"),
    ] {
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        let session = seed_user(&store, text).await?;
        let operations = DatabaseOperations::default();
        assert!(
            revoke_unproven_account_access(&store, &native)
                .with_subscriber(operations.clone())
                .await?
                .is_none()
        );
        assert_eq!(
            *operations.names.lock().unwrap(),
            [
                "db create verification",
                "db findMany verification",
                "db delete verification"
            ],
            "native selector: {text}"
        );
        assert!(
            store
                .get_verification_including_expired(&format!(
                    "revoke-unproven-account-access:{text}"
                ))
                .await?
                .is_none()
        );
        assert!(
            !*store
                .get_user_by_id(text)
                .await?
                .unwrap()
                .email_verified
                .typed()?
        );
        assert_eq!(
            store.get_session(session.token.typed()?).await?,
            Some(session.clone())
        );

        let verified = revoke_unproven_account_access(&store, &text.into())
            .await?
            .unwrap();
        assert!(*verified.email_verified.typed()?);
        assert!(store.get_session(session.token.typed()?).await?.is_none());
        assert!(
            store
                .get_verification_including_expired(&format!(
                    "revoke-unproven-account-access:{text}"
                ))
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn already_verified_user_keeps_access_and_releases_the_reservation() -> AuthResult<()> {
    let fixture = Fixture::new(Behavior::Continue, false).await?;
    let _ = fixture
        .store
        .update_user(
            "owner",
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    fixture.events.lock().unwrap().clear();
    assert!(
        *revoke_unproven_account_access(&fixture.store, &"owner".into())
            .await?
            .unwrap()
            .email_verified
            .typed()?
    );
    assert_eq!(
        *fixture.events.lock().unwrap(),
        ["lock:before", "lock:after"]
    );
    fixture
        .assert_state(&["first", "second"], true, true, false)
        .await
}
