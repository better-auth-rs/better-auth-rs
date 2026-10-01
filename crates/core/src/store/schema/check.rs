use super::{SchemaFinding, SchemaMismatch};
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use std::sync::Arc;
use tokio::sync::Mutex;

tokio::task_local! {
    static TRANSACTIONS: Vec<Arc<SchemaCheck>>;
}

/// Adapter-owned introspection. A revision changes only after an explicit schema invalidation.
#[async_trait]
pub trait SchemaInspector: Send + Sync + 'static {
    fn revision(&self) -> u64 {
        0
    }
    async fn findings(&self) -> AuthResult<Vec<SchemaFinding>>;
}

#[derive(Debug, thiserror::Error)]
pub enum SchemaCheckError {
    #[error(transparent)]
    Mismatch(#[from] SchemaMismatch),
    /// Keep the original driver error while sharing one failed attempt with concurrent callers.
    #[error(transparent)]
    Store(#[from] AuthError),
}

type Verdict = Shared<BoxFuture<'static, Result<(), Arc<SchemaCheckError>>>>;

#[derive(Default)]
struct State {
    revision: u64,
    verdict: Option<Verdict>,
}

/// One cached verdict per configured adapter. Construct a new check for each auth build.
pub struct SchemaCheck {
    inspector: Arc<dyn SchemaInspector>,
    state: Mutex<State>,
}

impl SchemaCheck {
    pub fn new(inspector: Arc<dyn SchemaInspector>) -> Self {
        Self {
            inspector,
            state: Mutex::new(State::default()),
        }
    }

    pub async fn check(&self) -> AuthResult<()> {
        loop {
            let revision = self.inspector.revision();
            let verdict = {
                let mut state = self.state.lock().await;
                if state.revision != revision {
                    state.revision = revision;
                    state.verdict = None;
                }
                state
                    .verdict
                    .get_or_insert_with(|| {
                        let inspector = self.inspector.clone();
                        async move {
                            let findings = inspector
                                .findings()
                                .await
                                .map_err(|error| Arc::new(SchemaCheckError::Store(error)))?;
                            if findings.is_empty() {
                                Ok(())
                            } else {
                                Err(Arc::new(SchemaCheckError::Mismatch(SchemaMismatch::new(
                                    findings,
                                ))))
                            }
                        }
                        .boxed()
                        .shared()
                    })
                    .clone()
            };
            let result = verdict.clone().await;
            if self.inspector.revision() != revision {
                continue;
            }
            if matches!(&result, Err(error) if matches!(error.as_ref(), SchemaCheckError::Store(_)))
            {
                let mut state = self.state.lock().await;
                if state.revision == revision
                    && state
                        .verdict
                        .as_ref()
                        .is_some_and(|current| current.ptr_eq(&verdict))
                {
                    state.verdict = None;
                }
            }
            return result.map_err(AuthError::SchemaCheck);
        }
    }
}

/// Explicit checks remain available when automatic runtime validation is disabled.
#[derive(Clone)]
pub struct SchemaValidation {
    pub check: Arc<SchemaCheck>,
    pub runtime_enabled: bool,
}

impl SchemaValidation {
    pub async fn check_runtime(&self) -> AuthResult<()> {
        let active = TRANSACTIONS
            .try_with(|checks| checks.iter().any(|check| Arc::ptr_eq(check, &self.check)))
            .unwrap_or(false);
        if self.runtime_enabled && !active {
            self.check.check().await?;
        }
        Ok(())
    }

    /// Scope the active transaction without treating another auth instance's check as completed.
    pub async fn in_transaction<T>(&self, operation: impl std::future::Future<Output = T>) -> T {
        let mut checks = TRANSACTIONS.try_with(Clone::clone).unwrap_or_default();
        checks.push(self.check.clone());
        TRANSACTIONS.scope(checks, Box::pin(operation)).await
    }

    /// Initialization reports failure but must not prevent the auth context from resolving.
    pub fn start(&self) {
        if !self.runtime_enabled {
            return;
        }
        let check = self.check.clone();
        let _task = tokio::spawn(async move {
            if let Err(error) = check.check().await {
                match &error {
                    AuthError::SchemaCheck(error)
                        if matches!(error.as_ref(), SchemaCheckError::Mismatch(_)) =>
                    {
                        tracing::error!("{error}")
                    }
                    _ => tracing::error!(
                        "Could not validate the database schema. Check your database connection."
                    ),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct Pending {
        revision: AtomicU64,
        calls: AtomicUsize,
        started: Notify,
        release: Notify,
    }

    #[async_trait]
    impl SchemaInspector for Pending {
        fn revision(&self) -> u64 {
            self.revision.load(Ordering::Acquire)
        }
        async fn findings(&self) -> AuthResult<Vec<SchemaFinding>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.started.notify_one();
                self.release.notified().await;
                Ok(vec![SchemaFinding::MissingTable {
                    table: "old_schema".into(),
                }])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[tokio::test]
    async fn invalidating_a_pending_check_discards_the_stale_mismatch_for_its_waiters() {
        let inspector = Arc::new(Pending {
            revision: AtomicU64::new(0),
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
        });
        let check = Arc::new(SchemaCheck::new(inspector.clone()));
        let waiting = check.clone();
        let task = tokio::spawn(async move { waiting.check().await });
        inspector.started.notified().await;
        inspector.revision.fetch_add(1, Ordering::AcqRel);
        inspector.release.notify_one();
        task.await.unwrap().unwrap();
        check.check().await.unwrap();
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 2);
    }

    struct Retry(AtomicUsize);
    #[async_trait]
    impl SchemaInspector for Retry {
        async fn findings(&self) -> AuthResult<Vec<SchemaFinding>> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(AuthError::Database(
                    crate::error::DatabaseError::Connection("closed fixture handle".into()),
                ))
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[tokio::test]
    async fn a_driver_failure_can_retry_and_then_caches_the_clean_result() {
        let inspector = Arc::new(Retry(AtomicUsize::new(0)));
        let check = SchemaCheck::new(inspector.clone());
        let failure = check.check().await.unwrap_err();
        assert!(
            matches!(failure, AuthError::SchemaCheck(ref error) if matches!(error.as_ref(), SchemaCheckError::Store(AuthError::Database(_))))
        );
        check.check().await.unwrap();
        check.check().await.unwrap();
        assert_eq!(inspector.0.load(Ordering::SeqCst), 2);
    }
}
