#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]
#[path = "api_key_metadata/fixture.rs"]
mod fixture;
use better_auth_seaorm::sea_orm::Database;
use fixture::{Fixture, database_metadata};
use serde_json::json;
use std::sync::Arc;
#[derive(Default)]
struct Updates {
    count: std::sync::atomic::AtomicUsize,
    started: tokio::sync::Notify,
}
struct UpdateLayer(Arc<Updates>);
#[derive(Default)]
struct SpanName(String);
impl tracing::field::Visit for SpanName {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" {
            self.0 = value.into();
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for UpdateLayer {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut name = SpanName::default();
        attributes.record(&mut name);
        if name.0 == "db update api_keys" {
            let _ = self
                .0
                .count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.started.notify_one();
        }
    }
}

#[tokio::test]
async fn a_real_sqlite_write_lock_distinguishes_single_await_from_list_background_work() {
    use better_auth_seaorm::sea_orm::{
        ConnectOptions, SqliteTransactionMode, TransactionOptions, TransactionTrait,
    };
    use std::sync::atomic::Ordering;
    use tracing_subscriber::prelude::*;
    let updates = Arc::new(Updates::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(UpdateLayer(updates.clone())),
    )
    .unwrap();
    for endpoint in ["get", "list"] {
        for scheduling in ["default", "handler", "handler-throw"] {
            eprintln!("write-lock case {endpoint}/{scheduling}");
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                let path = std::env::temp_dir()
                    .join(format!("api-key-metadata-{}.sqlite", uuid::Uuid::new_v4()));
                let url = format!("sqlite:{}?mode=rwc", path.display());
                let mut options = ConnectOptions::new(url.clone());
                let _ = options.max_connections(4);
                let db = Database::connect(options).await.unwrap();
                let fixture = Arc::new(Fixture::new("database", scheduling, db).await);
                let locker = Database::connect(url).await.unwrap();
                let transaction = locker
                    .begin_with_options(TransactionOptions {
                        sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                updates.count.store(0, Ordering::SeqCst);
                let worker = fixture.clone();
                let mut operation = tokio::spawn(async move { worker.operation(endpoint).await });
                let expected = if endpoint == "list" { 2 } else { 1 };
                while updates.count.load(Ordering::SeqCst) < expected {
                    updates.started.notified().await;
                }
                let scheduled = endpoint == "list" && scheduling != "default";
                if scheduled {
                    let metadata = (&mut operation).await.unwrap();
                    assert_eq!(
                        metadata,
                        vec![json!({"legacy":"one"}), json!({"legacy":"two"})]
                    );
                } else {
                    assert!(
                        !operation.is_finished(),
                        "single repair must still await SQL"
                    );
                }
                assert_eq!(
                    // Read through the lock owner; a new pooled connection may wait on
                    // SQLite connection initialization while migration holds the pool.
                    database_metadata(&transaction).await,
                    vec![
                        json!(json!({"legacy":"one"}).to_string()),
                        json!(json!({"legacy":"two"}).to_string())
                    ]
                );
                transaction.commit().await.unwrap();
                if !scheduled {
                    let _ = operation.await.unwrap();
                }
                let states = fixture.finish().await;
                assert_eq!(states, if scheduled { vec!["fulfilled"] } else { vec![] });
                let expected = if endpoint == "list" {
                    json!([{"legacy":"one"},{"legacy":"two"}])
                } else {
                    json!([{"legacy":"one"},json!({"legacy":"two"}).to_string()])
                };
                assert_eq!(
                    fixture.snapshot().await.get("database").unwrap().clone(),
                    expected
                );
                drop(fixture);
                locker.close().await.unwrap();
                std::fs::remove_file(path).unwrap();
            })
            .await
            .unwrap();
        }
    }
}
