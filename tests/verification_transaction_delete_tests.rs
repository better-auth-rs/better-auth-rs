#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "contract fixtures fail immediately on invalid setup or assertions"
)]

use better_auth::store::transaction;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::store::{VerificationStore, database_hooks::VerificationUpdate};
use better_auth_core::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use better_auth_core::wire::VerificationView;
use better_auth_core::{CreateVerification, FieldDate, FieldMap};
use better_auth_seaorm::sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Hooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: &'static str,
}
#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn before_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        assert!(context.tx.is_some());
        self.events.lock().unwrap().push("before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.events.lock().unwrap().push("after");
        if self.outcome == "after-error" {
            return Err(AuthError::internal("after-error"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn verification_delete_uses_the_active_transaction_and_ordered_after_hooks() {
    let upstream: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/background-otp-deletion-upstream.json"
    ))
    .unwrap();
    for outcome in ["commit", "rollback", "after-error"] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let config =
            AuthConfig::new("background-transaction-delete-secret-at-least-thirty-two-characters")
                .base_url("http://localhost:3000");
        let auth = AuthBuilder::new(config.clone())
            .store(
                SeaOrmStore::<BundledSchema>::new(config, db.clone()).hook(Hooks {
                    events: events.clone(),
                    outcome,
                }),
            )
            .build()
            .await
            .unwrap();
        let _ = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "transaction-delete".into(),
                value: "123456:0".into(),
                expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .to_utc()
                    .into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let found = Arc::new(Mutex::new(None));
        let captured = found.clone();
        let emitted = events.clone();
        let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                tx.delete_verification_by_identifier("transaction-delete")
                    .await?;
                *captured.lock().unwrap() = Some(
                    tx.get_verification_including_expired("transaction-delete")
                        .await?
                        .is_some(),
                );
                emitted.lock().unwrap().push("after-delete");
                if outcome == "rollback" {
                    return Err(AuthError::internal("rollback"));
                }
                Ok(())
            })
        })
        .await;
        let error = result.err().map(|error| match error {
            AuthError::Internal(message) => message,
            error => panic!("unexpected error: {error:?}"),
        });
        let count = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM verifications".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "count")
            .unwrap();
        let actual = json!({"outcome":outcome, "foundInside":*found.lock().unwrap(), "error":error, "events":*events.lock().unwrap(), "count":count});
        assert_eq!(
            &actual,
            upstream
                .iter()
                .find(|record| record["outcome"] == outcome)
                .unwrap()
        );
    }
}

fn consume_date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

type ConsumeEvents = Arc<Mutex<Vec<(&'static str, FieldMap)>>>;

struct MutateConsumeHook {
    mode: &'static str,
    events: ConsumeEvents,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for MutateConsumeHook {
    async fn before_delete_verification(
        &self,
        record: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        self.events
            .lock()
            .unwrap()
            .push(("before", record.fields()?));
        let tx = context.transaction.ok_or_else(|| {
            AuthError::internal("The consume hook requires its active transaction")
        })?;
        let updated = tx
            .update_verification(
                "subject",
                VerificationUpdate {
                    id: if self.mode == "move-id" {
                        "moved".into()
                    } else {
                        Default::default()
                    },
                    value: "updated-proof".into(),
                    expires_at: consume_date(if self.mode == "expire" {
                        -1_000_000_000
                    } else {
                        200
                    })
                    .into(),
                    updated_at: consume_date(3).into(),
                    ..Default::default()
                },
            )
            .await?
            .ok_or_else(|| AuthError::internal("The hook update must find the verification"))?;
        self.events
            .lock()
            .unwrap()
            .push(("write", updated.fields()?));
        if self.mode == "before-error" {
            return Err(AuthError::internal("before-error"));
        }
        Ok(if self.mode == "cancel" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_delete_verification(
        &self,
        record: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        self.events
            .lock()
            .unwrap()
            .push(("after", record.fields()?));
        if self.mode == "after-error" {
            return Err(AuthError::internal("after-error"));
        }
        Ok(())
    }
}

const CONSUME_MODES: [&str; 7] = [
    "payload",
    "expire",
    "before-error",
    "after-error",
    "output-error",
    "cancel",
    "move-id",
];

async fn check_consume(db: DatabaseConnection, mode: &'static str) {
    let mut config =
        AuthConfig::new("verification-consume-hook-secret-at-least-thirty-two-characters");
    let output_calls = Arc::new(AtomicUsize::new(0));
    let captured = output_calls.clone();
    let _ = config.verification.additional_fields.insert(
        "value".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    let call = captured.fetch_add(1, Ordering::SeqCst) + 1;
                    if mode == "output-error" && call == 3 {
                        return Err(AuthError::internal("output-error"));
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let observer = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
    let original = observer
        .create_verification(CreateVerification {
            id: "target".into(),
            identifier: "subject".into(),
            value: "original-proof".into(),
            created_at: consume_date(0).into(),
            updated_at: consume_date(0).into(),
            expires_at: consume_date(100).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let unrelated = observer
        .create_verification(CreateVerification {
            id: "unrelated".into(),
            identifier: "unrelated".into(),
            value: "retained-proof".into(),
            created_at: consume_date(0).into(),
            updated_at: consume_date(0).into(),
            expires_at: consume_date(100).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    output_calls.store(0, Ordering::SeqCst);
    let events = ConsumeEvents::default();
    let store = SeaOrmStore::<BundledSchema>::new(config, db.clone()).hook(MutateConsumeHook {
        mode,
        events: events.clone(),
    });
    let result = store.consume_verification_by_identifier("subject").await;
    let mut changed = original.clone();
    changed.value = "updated-proof".into();
    changed.expires_at = consume_date(if mode == "expire" {
        -1_000_000_000
    } else {
        200
    })
    .into();
    changed.updated_at = consume_date(3).into();
    if mode == "move-id" {
        changed.id = "moved".into();
    }
    match mode {
        "before-error" | "after-error" | "output-error" => assert!(
            matches!(result, Err(AuthError::Internal(ref message)) if message == mode),
            "{mode}: {result:?}"
        ),
        "expire" | "cancel" | "move-id" => assert_eq!(result.unwrap(), None, "{mode}"),
        _ => assert_eq!(result.unwrap(), Some(changed.clone()), "{mode}"),
    }
    let after = matches!(mode, "payload" | "expire" | "after-error");
    let mut expected_events = vec![
        ("before", original.fields().unwrap()),
        ("write", changed.fields().unwrap()),
    ];
    if after {
        expected_events.push(("after", changed.fields().unwrap()));
    }
    assert_eq!(*events.lock().unwrap(), expected_events, "{mode}");
    assert_eq!(
        output_calls.load(Ordering::SeqCst),
        if matches!(mode, "before-error" | "cancel" | "move-id") {
            2
        } else {
            3
        },
        "{mode}"
    );
    // Disable the one-shot output failure before observing the durable result.
    output_calls.store(100, Ordering::SeqCst);
    let remaining = observer
        .get_verification_including_expired("subject")
        .await
        .unwrap();
    assert_eq!(
        remaining,
        match mode {
            "before-error" | "output-error" => Some(original),
            "cancel" | "move-id" => Some(changed),
            _ => None,
        },
        "{mode}"
    );
    assert_eq!(
        observer
            .get_verification_including_expired("unrelated")
            .await
            .unwrap(),
        Some(unrelated),
        "{mode}"
    );
}

#[tokio::test]
async fn verification_consume_returns_the_deleted_row_after_hook_updates_and_preserves_failure_storage()
 {
    for mode in CONSUME_MODES {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        check_consume(db, mode).await;
    }
}

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

async fn isolated_consume(backend: &'static str, mode: &'static str) -> TestResult {
    let variable = if backend == "postgres" {
        "BETTER_AUTH_TEST_POSTGRES_URL"
    } else {
        "BETTER_AUTH_TEST_MYSQL_URL"
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_verification_consume_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == "postgres" {
        (
            format!("CREATE SCHEMA {name}"),
            format!("SET search_path TO {name}"),
            format!("DROP SCHEMA {name} CASCADE"),
        )
    } else {
        (
            format!("CREATE DATABASE `{name}`"),
            format!("USE `{name}`"),
            format!("DROP DATABASE `{name}`"),
        )
    };
    let _ = database.execute_unprepared(&create).await?;
    let worker = database.clone();
    // A separate task preserves database cleanup when a contract assertion panics.
    let result = tokio::spawn(async move {
        let _ = worker.execute_unprepared(&select).await?;
        migrator::run_migrations(&worker).await?;
        check_consume(worker, mode).await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

async fn server_consume(backend: &'static str) -> TestResult {
    for mode in CONSUME_MODES {
        isolated_consume(backend, mode).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_verification_consume_preserves_deleted_results_and_hook_failures()
-> TestResult {
    server_consume("postgres").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_verification_consume_preserves_deleted_results_and_hook_failures() -> TestResult
{
    server_consume("mysql").await
}

#[tokio::test]
async fn verification_single_delete_catches_selector_errors_without_hiding_consume_or_batch_errors()
{
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let mut config =
        AuthConfig::new("verification-delete-selector-secret-at-least-thirty-two-characters");
    let observer = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
    let original = observer
        .create_verification(CreateVerification {
            id: "target".into(),
            identifier: "subject".into(),
            value: "original-proof".into(),
            created_at: consume_date(0).into(),
            updated_at: consume_date(0).into(),
            expires_at: consume_date(-1_000_000_000).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for name in ["identifier", "expiresAt"] {
        let _ = config.verification.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                field_name: Some(format!("missing_{name}")),
                ..Default::default()
            },
        );
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = SeaOrmStore::<BundledSchema>::new(config, db.clone()).hook(Hooks {
        events: events.clone(),
        outcome: "commit",
    });
    store
        .delete_verification_by_identifier("subject")
        .await
        .unwrap();
    transaction(&store, |tx| {
        Box::pin(async move { tx.delete_verification_by_identifier("subject").await })
    })
    .await
    .unwrap();
    assert!(
        store
            .consume_verification_including_expired("subject")
            .await
            .is_err()
    );
    assert!(store.delete_expired_verifications().await.is_err());
    assert_eq!(
        observer
            .get_verification_including_expired("subject")
            .await
            .unwrap(),
        Some(original)
    );
    assert!(events.lock().unwrap().is_empty());
}
