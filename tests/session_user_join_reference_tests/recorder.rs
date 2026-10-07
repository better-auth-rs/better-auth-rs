use super::*;
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    pub(super) fn push(&self, value: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Session/User recorder poisoned"))?
            .push(value);
        Ok(())
    }

    pub(super) fn take(&self) -> AuthResult<Value> {
        Ok(std::mem::take(
            &mut *self
                .0
                .lock()
                .map_err(|_| AuthError::internal("Session/User recorder poisoned"))?,
        )
        .into())
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
        reason = "Tracing callbacks cannot return recorder errors."
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
        if let Some((operation, model)) = name
            .0
            .as_deref()
            .and_then(|name| name.strip_prefix("db "))
            .and_then(|name| name.split_once(' '))
        {
            self.push(json!(["query", operation, model]))
                .expect("Record query");
        }
    }
}
