use super::*;
use std::{
    future::Future,
    sync::{
        Once,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tracing::{Event, Metadata, Subscriber, field::Visit, level_filters::LevelFilter, span};

tokio::task_local! {
    static ACTIVE_TRACE: Arc<AdmissionTrace>;
}

static SUBSCRIBER: Once = Once::new();
static SUBSCRIBER_READY: AtomicBool = AtomicBool::new(false);
static NEXT_SPAN: AtomicU64 = AtomicU64::new(0);

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
        // Keep callsite interest valid when another test first emits a span without a capture scope.
        SUBSCRIBER.call_once(|| {
            tracing::subscriber::set_global_default(DatabaseSpans)
                .expect("API unit tests must share the admission trace subscriber");
            SUBSCRIBER_READY.store(true, Ordering::Release);
            tracing::callsite::rebuild_interest_cache();
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
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        // Dispatch registration precedes global publication; keep callsites disabled until publication completes.
        Some(if SUBSCRIBER_READY.load(Ordering::Acquire) {
            LevelFilter::TRACE
        } else {
            LevelFilter::OFF
        })
    }

    fn new_span(&self, attributes: &span::Attributes<'_>) -> span::Id {
        if let Ok(trace) = ACTIVE_TRACE.try_with(Arc::clone) {
            attributes.record(&mut SpanFields(&trace));
        }
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
    fn database_span(name: &str) {
        let _span = tracing::info_span!("admission trace regression", "otel.name" = name);
    }

    let first = Arc::<AdmissionTrace>::default();
    let pending = first.capture(async { database_span("db create session") });
    std::thread::spawn(|| database_span("db findOne user"))
        .join()
        .expect("unscoped span thread must complete");
    pending.await;
    assert_eq!(*first.events.lock().unwrap(), ["db create session"]);

    let second = Arc::<AdmissionTrace>::default();
    tokio::join!(
        first.capture(async {
            database_span("db findOne passkey");
            tokio::task::yield_now().await;
            database_span("db update passkey");
        }),
        second.capture(async {
            database_span("db findOne user");
            tokio::task::yield_now().await;
            database_span("db update user");
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
}
