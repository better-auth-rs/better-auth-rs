#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete records, callback order, and persistence after failures"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateVerification, FieldDate,
    store::{VerificationStore, database_hooks::VerificationUpdate},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::VerificationView,
};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore, TransactionConnection,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    },
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Events = Arc<Mutex<Vec<Value>>>;
type Transaction = Arc<Mutex<Option<TransactionConnection>>>;

fn event(events: &Events, value: Value) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Verification output trace lock poisoned"))?
        .push(value);
    Ok(())
}

fn observed(events: &Events) -> AuthResult<Vec<Value>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Verification output trace lock poisoned"))?
        .clone())
}

fn date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn input() -> CreateVerification {
    CreateVerification {
        id: "target".into(),
        identifier: "subject".into(),
        value: "before".into(),
        expires_at: date(100).into(),
        created_at: date(0).into(),
        updated_at: date(0).into(),
        ..Default::default()
    }
}

fn expected(identifier: &str, value: &str, updated: i64) -> Value {
    json!({
        "id": "target", "identifier": identifier, "value": value,
        "expiresAt": "2030-01-01T00:01:40.000Z", "createdAt": "2030-01-01T00:00:00.000Z",
        "updatedAt": if updated == 0 { "2030-01-01T00:00:00.000Z" } else { "2030-01-01T00:00:01.000Z" },
    })
}

struct Hooks {
    events: Events,
    transaction: Transaction,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn after_create_verification(
        &self,
        row: Option<&VerificationView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        event(&self.events, json!(["after-create", row]))
    }

    async fn after_update_verification(
        &self,
        row: Option<&VerificationView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        event(&self.events, json!(["after-update", row]))
    }

    async fn before_delete_verification(
        &self,
        _: &VerificationView,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        *self
            .transaction
            .lock()
            .map_err(|_| AuthError::internal("Verification transaction lock poisoned"))? = Some(
            context
                .tx
                .ok_or_else(|| AuthError::internal("Consume must retain its transaction"))?
                .clone(),
        );
        Ok(HookControl::Continue)
    }
}

async fn database() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options).await?;
    migrator::run_migrations(&database).await?;
    Ok(database)
}

async fn storage(database: &DatabaseConnection) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
        "SELECT id, identifier, value, expires_at, created_at, updated_at FROM verifications ORDER BY id".to_owned(),
    )).await?.into_iter().map(|row| Ok(json!({
        "id": row.try_get::<String>("", "id")?, "identifier": row.try_get::<String>("", "identifier")?,
        "value": row.try_get::<String>("", "value")?, "expiresAt": row.try_get::<String>("", "expires_at")?,
        "createdAt": row.try_get::<String>("", "created_at")?, "updatedAt": row.try_get::<String>("", "updated_at")?,
    }))).collect()
}

fn reader(
    database: &DatabaseConnection,
    events: &Events,
    reject: bool,
    consume: bool,
) -> SeaOrmStore<BundledSchema> {
    let writer = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    let mut config = AuthConfig::default();
    let trace = events.clone();
    let transaction = Transaction::default();
    let output_transaction = transaction.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let _ = config.verification.additional_fields.insert("identifier".into(), UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new_async(move |value| {
                let writer = writer.clone();
                let events = trace.clone();
                let transaction = output_transaction.clone();
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    event(&events, json!(["identifier", value.json()?]))?;
                    if consume {
                        if call == 2 {
                            let tx = transaction.lock().map_err(|_| AuthError::internal("Verification transaction lock poisoned"))?
                                .clone().ok_or_else(|| AuthError::internal("Consume must retain its transaction"))?;
                            let existing = tx.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                                "SELECT id FROM verifications WHERE id = 'target'".to_owned(),
                            )).await.map_err(|error| AuthError::internal(error.to_string()))?;
                            assert!(existing.is_empty());
                            let _ = tx.execute_unprepared(
                                "INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at) \
                                 VALUES ('target', 'replacement', 'other', '2030-01-01T00:01:40.000Z', \
                                 '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')",
                            ).await.map_err(|error| AuthError::internal(error.to_string()))?;
                            event(&events, json!(["replacement", expected("replacement", "other", 0)]))?;
                        }
                    } else {
                        let changed = writer.update_verification("subject", VerificationUpdate {
                            value: "after".into(), updated_at: date(1).into(), ..Default::default()
                        }).await?;
                        event(&events, json!(["write", changed]))?;
                        if reject {
                            return Err(AuthError::type_error("verification-output-rejected"));
                        }
                    }
                    Ok(value)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    });
    let trace = events.clone();
    let _ = config.verification.additional_fields.insert(
        "value".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    event(&trace, json!(["value", value.json()?]))?;
                    let value = value.as_str().ok_or_else(|| {
                        AuthError::internal("Expected a string verification value")
                    })?;
                    Ok(format!("{value}:out").into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    SeaOrmStore::<BundledSchema>::new(config, database.clone()).hook(Hooks {
        events: events.clone(),
        transaction,
    })
}

#[tokio::test]
async fn sqlite_verification_output_keeps_snapshots_and_persists_writes_before_output_errors()
-> Result<(), Box<dyn std::error::Error>> {
    for path in ["create", "find", "update"] {
        for reject in [false, true] {
            let database = database().await?;
            let writer = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
            if path != "create" {
                let _ = writer.create_verification(input()).await?;
            }
            let events = Events::default();
            let reader = reader(&database, &events, reject, false);
            let result = match path {
                "create" => reader.create_verification_optional(input()).await,
                "find" => reader.get_verification_by_identifier("subject").await,
                _ => {
                    reader
                        .update_verification(
                            "subject",
                            VerificationUpdate {
                                value: "before".into(),
                                updated_at: date(0).into(),
                                ..Default::default()
                            },
                        )
                        .await
                }
            };
            let mut trace = vec![
                json!(["identifier", "subject"]),
                json!(["write", expected("subject", "after", 1)]),
            ];
            if reject {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "verification-output-rejected")
                );
            } else {
                let projected = expected("subject", "before:out", 0);
                assert_eq!(serde_json::to_value(result?)?, projected);
                trace.push(json!(["value", "before"]));
                if path != "find" {
                    trace.push(json!([format!("after-{path}"), projected]));
                }
            }
            assert_eq!(observed(&events)?, trace, "{path}/{reject}");
            assert_eq!(
                storage(&database).await?,
                vec![expected("subject", "after", 1)]
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_verification_consumed_output_retains_the_deleted_snapshot_when_its_id_is_reused()
-> Result<(), Box<dyn std::error::Error>> {
    let database = database().await?;
    let writer = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    let _ = writer.create_verification(input()).await?;
    let events = Events::default();
    let reader = reader(&database, &events, false, true);
    let result = reader
        .consume_verification_including_expired("subject")
        .await?;
    assert_eq!(
        serde_json::to_value(result)?,
        expected("subject", "before:out", 0)
    );
    assert_eq!(
        observed(&events)?,
        vec![
            json!(["identifier", "subject"]),
            json!(["value", "before"]),
            json!(["identifier", "subject"]),
            json!(["replacement", expected("replacement", "other", 0)]),
            json!(["value", "before"]),
        ]
    );
    assert_eq!(
        storage(&database).await?,
        vec![expected("replacement", "other", 0)]
    );
    Ok(())
}
