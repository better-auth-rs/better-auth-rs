use super::*;
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
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
