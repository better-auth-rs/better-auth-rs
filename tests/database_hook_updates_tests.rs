#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "database hook fixtures fail immediately on setup and assertion errors"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthSession, AuthUser, CreateAccount,
    CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
    store::{AccountStore, SessionStore, UserStore, VerificationStore, transaction},
};
use better_auth_seaorm::{
    DatabaseHookUpdate, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore, SessionUpdate,
    VerificationUpdate,
    sea_orm::{Database, EntityTrait},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::Utc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type Verification = <BundledSchema as AuthSchema>::Verification;

async fn store() -> SeaOrmStore<BundledSchema> {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    SeaOrmStore::new(
        AuthConfig::new("database-hook-updates-secret-at-least-32-characters"),
        db,
    )
}

#[derive(Clone)]
struct PatchHook {
    first: bool,
    missing: Arc<Mutex<Vec<&'static str>>>,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for PatchHook {
    async fn before_update_user(
        &self,
        _: &str,
        _: &better_auth_core::FieldValue,
        update: &mut better_auth_core::FieldMap,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<better_auth_core::FieldMap>> {
        assert_eq!(
            update
                .get("name")
                .and_then(better_auth_core::FieldValue::as_str),
            Some("requested")
        );
        assert!(!update.contains_key("image"));
        Ok(DatabaseHookUpdate::Patch(if self.first {
            better_auth_core::FieldMap::from([("image".into(), "first-image".into())])
        } else {
            better_auth_core::FieldMap::from([("name".into(), "last-name".into())])
        }))
    }
    async fn before_update_account(
        &self,
        update: &UpdateAccount,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        assert_eq!(
            update.password.typed().unwrap().as_deref(),
            Some("requested")
        );
        assert!(update.scope.is_undefined());
        Ok(DatabaseHookUpdate::Patch(if self.first {
            UpdateAccount {
                scope: (Some("first-scope".into())).into(),
                ..Default::default()
            }
        } else {
            UpdateAccount {
                password: (Some("last-password".into())).into(),
                ..Default::default()
            }
        }))
    }
    async fn before_update_session(
        &self,
        _: &better_auth_core::FieldValue,
        update: &SessionUpdate,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        let fields = update.clone().into_public_fields()?;
        assert_eq!(
            fields
                .get("activeOrganizationId")
                .and_then(better_auth_core::FieldValue::as_str),
            Some("requested")
        );
        assert!(!fields.contains_key("token"));
        Ok(DatabaseHookUpdate::Patch(if self.first {
            SessionUpdate {
                token: Some("rotated-by-hook".into()),
                user_agent: Some(Some("first-agent".into())),
                ..Default::default()
            }
        } else {
            SessionUpdate {
                active_organization_id: Some(None),
                ..Default::default()
            }
        }))
    }
    async fn before_update_verification(
        &self,
        _: &str,
        update: &VerificationUpdate,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        assert_eq!(
            Some(update.value.typed().unwrap().as_str()),
            Some("requested")
        );
        assert!(update.identifier.is_undefined());
        Ok(DatabaseHookUpdate::Patch(if self.first {
            VerificationUpdate {
                identifier: (Some("moved".into()))
                    .map(better_auth_core::SchemaValue::Typed)
                    .unwrap_or_default(),
                ..Default::default()
            }
        } else {
            VerificationUpdate {
                value: (Some("last-value".into()))
                    .map(better_auth_core::SchemaValue::Typed)
                    .unwrap_or_default(),
                ..Default::default()
            }
        }))
    }
    async fn after_update_user(
        &self,
        value: Option<&better_auth_core::wire::UserView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        if value.is_none() {
            self.missing.lock().unwrap().push("user");
        }
        Ok(())
    }
    async fn after_update_account(
        &self,
        value: better_auth_core::store::database_hooks::DatabaseUpdateResult<
            &better_auth_core::wire::AccountView,
        >,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        let better_auth_core::store::database_hooks::DatabaseUpdateResult::One(value) = value
        else {
            return Err(AuthError::internal(
                "This single Account update must return a projected record or null",
            ));
        };
        if value.is_none() {
            self.missing.lock().unwrap().push("account");
        }
        Ok(())
    }
    async fn after_update_session(
        &self,
        value: Option<&better_auth_core::wire::SessionView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        if value.is_none() {
            self.missing.lock().unwrap().push("session");
        }
        Ok(())
    }
    async fn after_update_verification(
        &self,
        value: Option<&better_auth_core::wire::VerificationView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        if value.is_none() {
            self.missing.lock().unwrap().push("verification");
        }
        Ok(())
    }
}

#[tokio::test]
async fn updates_merge_independent_patches_and_dispatch_missing_rows_to_after_hooks() {
    let store = store().await;
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("patch@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let account = store
        .create_account(CreateAccount {
            user_id: (user.id().into_owned()).into(),
            account_id: "patch-account".into(),
            provider_id: "credential".into(),
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
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id().into_owned(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    for value in ["first", "second"] {
        let _ = store
            .create_verification(CreateVerification {
                identifier: "original".into(),
                value: value.into(),
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let missing = Arc::new(Mutex::new(Vec::new()));
    let store = store
        .hook(PatchHook {
            first: true,
            missing: missing.clone(),
        })
        .hook(PatchHook {
            first: false,
            missing: missing.clone(),
        });
    let updated = store
        .update_user(
            user.id().typed().unwrap(),
            UpdateUser {
                name: Some("requested".into()).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.name.typed().unwrap().as_deref(), Some("last-name"));
    assert_eq!(
        updated.image.typed().unwrap().as_deref(),
        Some("first-image")
    );
    let updated = store
        .update_account(
            account.id.typed().unwrap(),
            UpdateAccount {
                password: (Some("requested".into())).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        updated.password.typed().unwrap().as_deref(),
        Some("last-password")
    );
    assert_eq!(
        updated.scope.typed().unwrap().as_deref(),
        Some("first-scope")
    );
    let updated = store
        .update_session_active_organization(session.token().typed().unwrap(), Some("requested"))
        .await
        .unwrap();
    assert_eq!(updated.token().typed().unwrap(), "rotated-by-hook");
    assert_eq!(
        updated.user_agent().typed().unwrap().as_deref(),
        Some("first-agent")
    );
    assert_eq!(
        updated.active_organization_id().field_value(),
        better_auth::FieldValue::Null
    );
    assert!(
        store
            .get_session(session.token().typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    store
        .update_verification_by_identifier("original", Some("requested".into()), None)
        .await
        .unwrap();
    type VerificationEntity = <Verification as better_auth_seaorm::SeaOrmVerificationModel>::Entity;
    let rows = VerificationEntity::find()
        .all(store.connection())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.identifier == "moved" && row.value == "last-value")
    );

    assert!(
        store
            .update_user(
                "missing",
                UpdateUser {
                    name: Some("requested".into()).into(),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_account_optional(
                "missing",
                UpdateAccount {
                    password: (Some("requested".into())).into(),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .update_session_active_organization("missing", Some("requested"))
            .await
            .is_err()
    );
    store
        .update_verification_by_identifier("missing", Some("requested".into()), None)
        .await
        .unwrap();
    assert_eq!(
        *missing.lock().unwrap(),
        [
            "user",
            "user",
            "account",
            "account",
            "session",
            "session",
            "verification",
            "verification"
        ]
    );
}

#[derive(Clone, Default)]
struct CommitHook {
    events: Arc<Mutex<Vec<String>>>,
    fail: Arc<AtomicBool>,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for CommitHook {
    async fn before_create_user(
        &self,
        _: &mut better_auth_core::FieldMap,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        assert!(ctx.tx.is_some());
        self.events.lock().unwrap().push("before".into());
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_create_user(
        &self,
        user: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        let user = user
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        assert!(ctx.tx.is_none());
        let fresh = SeaOrmStore::<BundledSchema>::new(ctx.config.clone(), ctx.db.clone());
        assert_eq!(
            fresh
                .get_user_by_id(user.id().typed().unwrap())
                .await?
                .unwrap()
                .name
                .typed()
                .unwrap()
                .as_deref(),
            Some("Updated")
        );
        self.events.lock().unwrap().push("created".into());
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuthError::internal("after-commit"));
        }
        Ok(())
    }
    async fn after_update_user(
        &self,
        user: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        assert_eq!(
            user.unwrap().name.typed().unwrap().as_deref(),
            Some("Updated")
        );
        self.events.lock().unwrap().push("updated".into());
        Ok(())
    }
}

#[tokio::test]
async fn transaction_hooks_wait_for_commit_skip_rollback_and_preserve_rows_after_failure() {
    let hooks = CommitHook::default();
    let store = store().await.hook(hooks.clone());
    for mode in ["commit", "rollback", "after-error"] {
        hooks.events.lock().unwrap().clear();
        hooks.fail.store(mode == "after-error", Ordering::SeqCst);
        let events = hooks.events.clone();
        let result = transaction(&store, move |tx| {
            Box::pin(async move {
                let user = tx
                    .create_user(
                        CreateUser::new()
                            .with_email(format!("{mode}@example.com"))
                            .with_name("Created"),
                    )
                    .await?;
                let _ = tx
                    .update_user(
                        user.id().typed().unwrap(),
                        UpdateUser {
                            name: Some("Updated".into()).into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                assert_eq!(*events.lock().unwrap(), ["before"]);
                if mode == "rollback" {
                    return Err(AuthError::internal("rollback"));
                }
                Ok(())
            })
        })
        .await;
        let stored = store
            .get_user_by_email(&format!("{mode}@example.com"))
            .await
            .unwrap();
        match mode {
            "commit" => {
                result.unwrap();
                assert!(stored.is_some());
                assert_eq!(
                    *hooks.events.lock().unwrap(),
                    ["before", "created", "updated"]
                );
            }
            "rollback" => {
                assert!(result.is_err());
                assert!(stored.is_none());
                assert_eq!(*hooks.events.lock().unwrap(), ["before"]);
            }
            _ => {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "after-commit")
                );
                assert_eq!(
                    stored.unwrap().name.typed().unwrap().as_deref(),
                    Some("Updated")
                );
                assert_eq!(*hooks.events.lock().unwrap(), ["before", "created"]);
            }
        }
    }
}
