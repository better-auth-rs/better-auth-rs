#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete results, logs, storage, and retained table identities."
)]

use super::{EphemeralStore, table::TableRef};
use crate::observability::{LogArgument, LogLevel, LogSink};
use crate::store::SessionStore;
use crate::{AuthConfig, AuthContext, AuthError, AuthResult, FieldDate, FieldMap, FieldValue};
use std::sync::Arc;

#[derive(Default)]
struct Logs(parking_lot::Mutex<Vec<LogEntry>>);

type LogEntry = (LogLevel, String, Vec<serde_json::Value>);

impl LogSink for Logs {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        self.0.lock().push((
            level,
            message.to_string(),
            arguments
                .iter()
                .map(|value| match value {
                    LogArgument::Value(value) => (*value).clone(),
                    LogArgument::Native(value) => value
                        .json()
                        .expect("contract logger argument must serialize")
                        .expect("contract logger argument must be JSON-defined"),
                    LogArgument::Text(value) => (*value).into(),
                    LogArgument::Error(error) => error.to_string().into(),
                })
                .collect(),
        ));
        Ok(())
    }
}

fn session() -> FieldMap {
    let date = || FieldValue::from(FieldDate::from_milliseconds(1_893_456_000_000.0));
    [
        ("id".into(), "session".into()),
        ("token".into(), "token".into()),
        ("userId".into(), "owner".into()),
        ("expiresAt".into(), date()),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
    ]
    .into()
}

#[tokio::test]
async fn native_join_reads_missing_child_only_after_a_matching_base_row() -> AuthResult<()> {
    for hit in [false, true] {
        for disabled in [false, true] {
            let mut config = AuthConfig::default();
            config.advanced.database.joins = Some(true);
            config.logger = crate::LoggerConfig {
                disabled: Some(true),
                ..Default::default()
            }
            .into();
            let store = Arc::new(EphemeralStore::empty(Arc::new(config.clone())));
            let table = TableRef::new(store.operations.clone());
            let row = table.push(session())?;
            store
                .operation(|op| op.replace_physical_table("session".into(), Some(table.clone())))?;
            let logs = Arc::new(Logs::default());
            config.logger = crate::LoggerConfig {
                disabled: Some(disabled),
                log: Some(logs.clone()),
                ..Default::default()
            }
            .into();
            let context = AuthContext::new(Arc::new(config), store.clone())
                .expect("fixture context initializes");
            let result = context
                .with_native_context(Default::default(), |_| async {
                    store
                        .get_session_snapshot(if hit { "token" } else { "missing" })
                        .await
                })
                .await;
            if hit {
                let error = result.err().ok_or_else(|| {
                    AuthError::internal("A matched native join must read its missing child table")
                })?;
                assert_eq!(
                    error
                        .instrumentation_message()
                        .expect("fixture error message"),
                    "JoinOption model user not found"
                );
            } else {
                assert!(result?.is_none());
            }
            let expected = if hit && !disabled {
                vec![(
                    LogLevel::Error,
                    "[MemoryAdapter] JoinOption model user not found in the DB".into(),
                    vec![serde_json::json!(["session"])],
                )]
            } else {
                Vec::new()
            };
            assert_eq!(*logs.0.lock(), expected);
            let root = store.operation(|op| op.capture_state())?;
            assert_eq!(root.keys(), ["session"]);
            let current = root.table("session")?;
            assert!(current.array().same_array(&table.array()));
            assert_eq!(current.snapshot()?, [session()]);
            let selected = current
                .row_at(0)?
                .ok_or_else(|| AuthError::internal("The stored session must remain present"))?;
            assert!(selected.same_row(&row));
        }
    }
    Ok(())
}
