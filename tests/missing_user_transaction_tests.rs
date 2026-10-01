#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "Regression setup and assertions fail immediately"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateUser, HttpMethod,
    UpdateUser,
    hooks::with_request_hook_context,
    store::{
        AuthTransaction, EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        transaction,
    },
};
use better_auth_seaorm::{
    SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

#[derive(Clone, Copy)]
enum Scenario {
    Commit,
    Rollback,
    AfterError,
    Cancel,
    NestedBeforeError,
    OutsideAfterError,
}

#[derive(Clone)]
struct MissingUpdateHooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    scenario: Scenario,
}

fn update_name(name: &str) -> UpdateUser {
    UpdateUser {
        name: Some(name.into()),
        ..Default::default()
    }
}

impl MissingUpdateHooks {
    async fn before<S: AuthSchema>(
        &self,
        update: &UpdateUser,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        if matches!(self.scenario, Scenario::Cancel) {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        if matches!(self.scenario, Scenario::NestedBeforeError)
            && update.name.as_deref() == Some("outer")
        {
            let result = transaction
                .unwrap()
                .update_user("missing-nested", update_name("nested"))
                .await;
            assert!(matches!(result, Err(AuthError::UserNotFound)));
            return Err(AuthError::internal("outer before rejected"));
        }
        Ok(DatabaseHookUpdate::Continue)
    }

    fn after_missing(&self, is_missing: bool, path: Option<&str>) -> AuthResult<()> {
        assert!(is_missing);
        assert_eq!(path, Some("/missing-update"));
        self.events.lock().unwrap().push("after:null");
        if matches!(
            self.scenario,
            Scenario::AfterError | Scenario::OutsideAfterError
        ) {
            return Err(AuthError::internal("nullable after rejected"));
        }
        Ok(())
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> SeaOrmHooks<S> for MissingUpdateHooks {
    async fn before_update_user(
        &self,
        _: &str,
        update: &UpdateUser,
        context: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.before(update, context.transaction).await
    }

    async fn after_update_user(
        &self,
        user: Option<&better_auth_core::wire::UserView>,
        context: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after_missing(
            user.is_none(),
            context
                .request
                .as_ref()
                .map(|request| request.path.as_str()),
        )
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for MissingUpdateHooks {
    async fn before_update_user(
        &self,
        update: &UpdateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.before(update, context.transaction).await
    }

    async fn after_update_user(
        &self,
        user: Option<&better_auth_core::wire::UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after_missing(
            user.is_none(),
            context
                .request
                .as_ref()
                .map(|request| request.path.as_str()),
        )
    }
}

async fn check_missing_update<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    hooks: MissingUpdateHooks,
) {
    let events = hooks.events.clone();
    let scenario = hooks.scenario;
    let request = AuthRequest::new(HttpMethod::Post, "/missing-update");
    if matches!(scenario, Scenario::OutsideAfterError) {
        let result = with_request_hook_context(
            &request,
            store.update_user("missing-user", update_name("outer")),
        )
        .await;
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "nullable after rejected")
        );
        assert_eq!(*events.lock().unwrap(), ["after:null"]);
        return;
    }
    let outcome: AuthResult<()> = transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            let _ = tx.create_user(CreateUser::new().with_email("commit-proof@example.com")).await?;
            let before_events = events.clone();
            tx.queue_after_commit(Box::pin(async move {
                before_events.lock().unwrap().push("earlier");
                Ok(())
            }))?;
            let missing = with_request_hook_context(&request, tx.update_user("missing-user", update_name("outer"))).await;
            match scenario {
                Scenario::Cancel => assert!(matches!(missing, Err(AuthError::Forbidden(_)))),
                Scenario::NestedBeforeError => assert!(matches!(missing, Err(AuthError::Internal(message)) if message == "outer before rejected")),
                _ => assert!(matches!(missing, Err(AuthError::UserNotFound))),
            }
            assert!(events.lock().unwrap().is_empty());
            tx.queue_after_commit(Box::pin(async move {
                events.lock().unwrap().push("later");
                Ok(())
            }))?;
            if matches!(scenario, Scenario::Rollback) {
                return Err(AuthError::internal("rollback requested"));
            }
            Ok(())
        })
    }).await;
    let expected: &[&str] = match scenario {
        Scenario::Rollback => {
            assert!(
                matches!(outcome, Err(AuthError::Internal(message)) if message == "rollback requested")
            );
            &[]
        }
        Scenario::AfterError => {
            assert!(
                matches!(outcome, Err(AuthError::Internal(message)) if message == "nullable after rejected")
            );
            &["earlier", "after:null"]
        }
        Scenario::Cancel => {
            outcome.unwrap();
            &["earlier", "later"]
        }
        _ => {
            outcome.unwrap();
            &["earlier", "after:null", "later"]
        }
    };
    assert_eq!(*hooks.events.lock().unwrap(), expected);
    assert_eq!(
        store
            .get_user_by_email("commit-proof@example.com")
            .await
            .unwrap()
            .is_some(),
        !matches!(scenario, Scenario::Rollback)
    );
}

const SCENARIOS: [Scenario; 6] = [
    Scenario::Commit,
    Scenario::Rollback,
    Scenario::AfterError,
    Scenario::Cancel,
    Scenario::NestedBeforeError,
    Scenario::OutsideAfterError,
];

#[tokio::test]
async fn missing_sqlite_user_update_keeps_its_nullable_after_hook_in_the_commit_queue() {
    for scenario in SCENARIOS {
        let hooks = MissingUpdateHooks {
            events: Default::default(),
            scenario,
        };
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let store =
            SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db).hook(hooks.clone());
        check_missing_update(Arc::new(store), hooks).await;
    }
}

#[tokio::test]
async fn missing_ephemeral_user_update_obeys_the_same_nullable_commit_boundary() {
    for scenario in SCENARIOS {
        let hooks = MissingUpdateHooks {
            events: Default::default(),
            scenario,
        };
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()))
            .with_hooks(vec![Arc::new(hooks.clone())]);
        check_missing_update::<StatelessSchema>(Arc::new(store), hooks).await;
    }
}
