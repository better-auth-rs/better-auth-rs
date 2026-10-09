use super::*;
use std::sync::{
    Once,
    atomic::{AtomicBool, Ordering},
};
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

tokio::task_local! {
    static ACTIVE_EVENTS: Events;
}

static TRACER: Once = Once::new();
static TRACER_READY: AtomicBool = AtomicBool::new(false);

struct ScopedEvents;

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    #[expect(
        clippy::expect_used,
        reason = "Each integration test binary owns one subscriber; conflicting ownership must fail the contract."
    )]
    pub(super) async fn capture<T>(&self, operation: impl std::future::Future<Output = T>) -> T {
        // Keep callsite interest valid when parallel tests emit spans outside a capture scope.
        TRACER.call_once(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(ScopedEvents),
            )
            .expect("Contract tests must share the database operation subscriber");
            TRACER_READY.store(true, Ordering::Release);
            tracing::callsite::rebuild_interest_cache();
        });
        ACTIVE_EVENTS.scope(self.clone(), operation).await
    }

    pub(super) fn push(&self, event: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Account/User HTTP recorder poisoned"))?
            .push(event);
        Ok(())
    }

    pub(super) fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|_| {
            AuthError::internal("Account/User HTTP recorder poisoned")
        })?))
    }
}

impl<S: Subscriber> Layer<S> for ScopedEvents {
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        // Publish the global dispatcher before enabling callsites.
        Some(if TRACER_READY.load(Ordering::Acquire) {
            tracing::metadata::LevelFilter::TRACE
        } else {
            tracing::metadata::LevelFilter::OFF
        })
    }

    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        context: Context<'_, S>,
    ) {
        if let Ok(events) = ACTIVE_EVENTS.try_with(Clone::clone) {
            events.on_new_span(attributes, id, context);
        }
    }
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" {
            self.0 = Some(value.into());
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl<S: Subscriber> Layer<S> for Events {
    #[expect(
        clippy::expect_used,
        reason = "Tracing callbacks cannot return errors; recorder poisoning must fail the contract."
    )]
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        if attributes.metadata().target() != "better-auth" {
            return;
        }
        let mut name = SpanName::default();
        attributes.record(&mut name);
        let Some(name) = name.0 else {
            return;
        };
        let Some((operation, model)) = name
            .strip_prefix("db ")
            .and_then(|name| name.split_once(' '))
        else {
            return;
        };
        // Hook spans share the prefix but do not represent adapter queries.
        if !operation.ends_with(".before") && !operation.ends_with(".after") {
            self.push(json!({"kind": "query", "operation": operation, "model": model}))
                .expect("Record database query");
        }
    }
}
