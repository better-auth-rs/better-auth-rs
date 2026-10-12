use super::*;
use tracing::{Subscriber, field::Visit, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    pub(super) async fn capture<T>(&self, operation: impl std::future::Future<Output = T>) -> T {
        static TRACING: std::sync::Once = std::sync::Once::new();
        // Keep a process subscriber alive so parallel unscoped spans cannot disable cached callsites.
        TRACING.call_once(|| {
            assert!(
                tracing::subscriber::set_global_default(
                    tracing::subscriber::NoSubscriber::default()
                )
                .is_ok(),
                "The query recorder must initialize the test process subscriber once"
            );
        });
        // Retained projection tasks inherit the subscriber and its recorder.
        operation
            .with_subscriber(tracing_subscriber::registry().with(self.clone()))
            .await
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

pub(super) fn object_keys(value: &Value) -> Option<Vec<String>> {
    value
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
}

pub(super) fn assert_provider_token_keys(
    actual: &[Value],
    expected: &[Value],
    case: &impl std::fmt::Debug,
) {
    let token_keys = |events: &[Value]| {
        events
            .iter()
            .filter(|event| event["kind"] == "provider.userInfo")
            .map(|event| object_keys(&event["tokens"]))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        token_keys(actual),
        token_keys(expected),
        "{case:?}: provider token own-property order"
    );
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
