#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]
use better_auth::{AuthConfig, AuthError};
use better_auth_core::{
    background::{BackgroundTask, BackgroundTasks},
    middleware::EndpointRateLimit,
    observability::{LogArgument, LogLevel, LogSink},
    store::{EphemeralStore, RateLimitStore},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::bundled_schema::BundledSchema,
    store::entities::rate_limit,
};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    events: Mutex<Vec<String>>,
    tasks: Mutex<Vec<BackgroundTask>>,
}
impl LogSink for State {
    fn log(&self, _: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        let message = message.to_string();
        if message == "Error pruning rate limit rows" || message == "Failed to run background task:"
        {
            self.events.lock().unwrap().push(message);
            assert!(!arguments.is_empty());
        }
    }
}
fn config(state: Arc<State>, fail_handler: bool) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.level = LogLevel::Error;
    config.logger.log = Some(state.clone());
    config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
        state.events.lock().unwrap().push("handler".into());
        state.tasks.lock().unwrap().push(task);
        if fail_handler {
            return Err(AuthError::internal("handler-sync"));
        }
        Ok(())
    }));
    config
}
async fn finish(state: &State) {
    let tasks = std::mem::take(&mut *state.tasks.lock().unwrap());
    for task in tasks {
        task.await.unwrap();
    }
}
async fn read_count(db: &DatabaseConnection) -> i64 {
    db.query_one_raw(Statement::from_string(
        DbBackend::Sqlite,
        "SELECT COUNT(*) AS count FROM rate_limit".to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "count")
    .unwrap()
}
async fn fixture(
    state: Arc<State>,
    fail_handler: bool,
) -> (DatabaseConnection, SeaOrmStore<BundledSchema>) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    let _ = db
        .execute(
            &better_auth_seaorm::sea_orm::Schema::new(DbBackend::Sqlite)
                .create_table_from_entity(rate_limit::Entity),
        )
        .await
        .unwrap();
    let store = SeaOrmStore::new(config(state, fail_handler), db.clone());
    (db, store)
}
#[tokio::test]
async fn sqlite_reset_schedules_cleanup_once_and_keeps_sql_failure_separate_from_handler_failure() {
    for reject in [false, true] {
        for fail_handler in [false, true] {
            let state = Arc::new(State::default());
            let (db, store) = fixture(state.clone(), fail_handler).await;
            let _ = db
                .execute_unprepared(
                    "INSERT INTO rate_limit(id,key,count,last_request) VALUES('old','old',1,0)",
                )
                .await
                .unwrap();
            if reject {
                let _=db.execute_unprepared("CREATE TRIGGER reject_cleanup BEFORE DELETE ON rate_limit BEGIN SELECT RAISE(FAIL,'cleanup-async'); END").await.unwrap();
            }
            let rule = EndpointRateLimit {
                window: 60.0,
                max_requests: 2.0,
            };
            assert!(
                store
                    .consume_rate_limit("key", rule, 60.0)
                    .await
                    .unwrap()
                    .allowed
            );
            assert!(
                store
                    .consume_rate_limit("key", rule, 60.0)
                    .await
                    .unwrap()
                    .allowed
            );
            assert!(
                !store
                    .consume_rate_limit("key", rule, 60.0)
                    .await
                    .unwrap()
                    .allowed
            );
            assert!(state.events.lock().unwrap().is_empty());
            assert!(
                store
                    .consume_rate_limit(
                        "key",
                        EndpointRateLimit {
                            window: 0.0,
                            max_requests: 1.0
                        },
                        60.0
                    )
                    .await
                    .unwrap()
                    .allowed
            );
            finish(&state).await;
            let mut expected = vec!["handler".to_owned()];
            if fail_handler {
                expected.push("Failed to run background task:".into());
            }
            if reject {
                expected.push("Error pruning rate limit rows".into());
            }
            assert_eq!(*state.events.lock().unwrap(), expected);
            assert_eq!(read_count(&db).await, if reject { 2 } else { 1 });
        }
    }
}
#[tokio::test]
async fn ephemeral_database_rate_limit_uses_the_same_reset_scheduler() {
    let state = Arc::new(State::default());
    let store = EphemeralStore::new(Arc::new(config(state.clone(), false)));
    let rule = EndpointRateLimit {
        window: 60.0,
        max_requests: 1.0,
    };
    assert!(
        store
            .consume_rate_limit("key", rule, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !store
            .consume_rate_limit("key", rule, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert!(state.events.lock().unwrap().is_empty());
    assert!(
        store
            .consume_rate_limit(
                "key",
                EndpointRateLimit {
                    window: 0.0,
                    max_requests: 1.0
                },
                -1.0
            )
            .await
            .unwrap()
            .allowed
    );
    finish(&state).await;
    assert_eq!(*state.events.lock().unwrap(), vec!["handler"]);
    assert!(
        store
            .consume_rate_limit("key", rule, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(state.events.lock().unwrap().len(), 1);
}
