#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;
use std::{
    future::Future,
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{
    Event, Metadata, Subscriber, field::Visit, level_filters::LevelFilter, span,
    subscriber::Interest,
};

static RECORDER: Once = Once::new();
static NEXT_SPAN: AtomicU64 = AtomicU64::new(0);

tokio::task_local! {
    static ACTIVE_TRACE: Arc<AdmissionTrace>;
}

#[derive(Default)]
pub(super) struct AdmissionTrace {
    pub events: Mutex<Vec<String>>,
    pub owners: Mutex<Vec<FieldValue>>,
    pub sessions: Mutex<Vec<SessionView>>,
    pub banned_users: Mutex<Vec<FieldMap>>,
}

impl AdmissionTrace {
    pub(super) fn capture<F: Future>(
        self: &Arc<Self>,
        operation: F,
    ) -> impl Future<Output = F::Output> + use<F> {
        // Keep the subscriber available when another thread registers a callsite between future polls.
        RECORDER.call_once(|| {
            tracing::subscriber::set_global_default(DatabaseSpans).expect(
                "Passkey admission recorder must own the API test binary's global subscriber",
            );
        });
        ACTIVE_TRACE.scope(self.clone(), operation)
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for AdmissionTrace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("session:before".into());
        self.owners
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let session = session
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.events.lock().unwrap().push("session:after".into());
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }
}

struct DatabaseSpans;
struct SpanFields<'a>(&'a AdmissionTrace);

impl Visit for SpanFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name"
            && matches!(
                value,
                "db findOne passkey"
                    | "db update passkey"
                    | "db findOne user"
                    | "db update user"
                    | "db create session"
            )
        {
            self.0.events.lock().unwrap().push(value.into());
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for DatabaseSpans {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        // Route each emission through the current task scope, including nested and parallel captures.
        Interest::sometimes()
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        ACTIVE_TRACE.try_with(|_| ()).is_ok()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn new_span(&self, attributes: &span::Attributes<'_>) -> span::Id {
        ACTIVE_TRACE.with(|trace| attributes.record(&mut SpanFields(trace)));
        span::Id::from_u64(NEXT_SPAN.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[tokio::test]
async fn unscoped_first_span_preserves_parallel_capture_isolation() {
    async fn database_operation(model: &str, operation: &str) {
        better_auth_core::observability::database::with_database_operation(
            &test_helpers::create_test_config(),
            model,
            operation,
            async { Ok(()) },
        )
        .await
        .expect("database trace regression operation should succeed");
    }

    let first = Arc::<AdmissionTrace>::default();
    let pending = first.capture(database_operation("session", "create"));
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("unscoped span runtime should build")
            .block_on(database_operation("user", "findOne"));
    })
    .join()
    .expect("unscoped span thread must complete");
    pending.await;
    assert_eq!(*first.events.lock().unwrap(), ["db create session"]);

    let second = Arc::<AdmissionTrace>::default();
    tokio::join!(
        first.capture(async {
            database_operation("passkey", "findOne").await;
            tokio::task::yield_now().await;
            database_operation("passkey", "update").await;
        }),
        second.capture(async {
            database_operation("user", "findOne").await;
            tokio::task::yield_now().await;
            database_operation("user", "update").await;
        }),
    );
    assert_eq!(
        *first.events.lock().unwrap(),
        [
            "db create session",
            "db findOne passkey",
            "db update passkey"
        ]
    );
    assert_eq!(
        *second.events.lock().unwrap(),
        ["db findOne user", "db update user"]
    );

    let parent = Arc::<AdmissionTrace>::default();
    let child = Arc::<AdmissionTrace>::default();
    parent
        .capture(async {
            database_operation("passkey", "findOne").await;
            child
                .capture(async {
                    database_operation("user", "findOne").await;
                    tokio::task::yield_now().await;
                    database_operation("user", "update").await;
                })
                .await;
            database_operation("passkey", "update").await;
        })
        .await;
    assert_eq!(
        *parent.events.lock().unwrap(),
        ["db findOne passkey", "db update passkey"]
    );
    assert_eq!(
        *child.events.lock().unwrap(),
        ["db findOne user", "db update user"]
    );
}
