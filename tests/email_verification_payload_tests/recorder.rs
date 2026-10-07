use super::*;
use better_auth_core::api_error::{ApiErrorHandler, ApiErrorTask};
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    pub(super) fn push(&self, event: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Email payload recorder poisoned"))?
            .push(event);
        Ok(())
    }

    pub(super) fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|_| {
            AuthError::internal("Email payload recorder poisoned")
        })?))
    }
}

impl<S: AuthSchema> ApiErrorHandler<S> for Events {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        let native = match error {
            AuthError::Serialization(error) => {
                json!({"variant": "serialization", "category": format!("{:?}", error.classify()), "message": error.to_string()})
            }
            other => json!({"variant": "other", "message": other.to_string()}),
        };
        self.push(
            json!({"kind": "api-error", "native": native, "isApiError": error.is_api_error()}),
        )?;
        Ok(None)
    }
}

#[derive(Default)]
struct Fields(serde_json::Map<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let _ = self.0.insert(field.name().into(), json!(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = self
            .0
            .insert(field.name().into(), json!(format!("{value:?}")));
    }
}

impl<S: Subscriber> Layer<S> for Events {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        if attributes.metadata().target() != "better-auth" {
            return;
        }
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        if let Some((operation, model)) = fields
            .0
            .get("otel.name")
            .and_then(Value::as_str)
            .and_then(|name| name.strip_prefix("db "))
            .and_then(|name| name.split_once(' '))
        {
            // Real callbacks record hook entries; these spans only observe adapter queries.
            if !operation.ends_with(".before") && !operation.ends_with(".after") {
                self.push(json!({"kind": "query", "operation": operation, "model": model}))
                    .expect("Record database operation");
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "better-auth"
            || *event.metadata().level() != tracing::Level::ERROR
            || event.metadata().name() == "exception"
        {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.push(json!({"kind": "console.error", "native": fields.0}))
            .expect("Record outer logger error");
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions panic while missing diagnostic fields propagate errors"
)]
pub(super) fn assert_events(actual: &[Value], case: &Value) -> TestResult {
    let expected = required(case, "/events")
        .as_array()
        .expect("Captured request events");
    let paired = |events: &[Value]| {
        events
            .iter()
            .map(|event| {
                let kind = required(event, "/kind");
                if matches!(kind.as_str(), Some("api-error" | "console.error")) {
                    json!({"kind": kind})
                } else {
                    event.clone()
                }
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        paired(actual),
        paired(expected),
        "{}: complete callback/log/query sequence",
        required(case, "/scenario")
    );
    for event in actual {
        if required(event, "/kind") == "api-error" {
            assert_eq!(required(event, "/isApiError"), false);
            assert_eq!(required(event, "/native/variant"), "serialization");
            assert_eq!(required(event, "/native/category"), "Data");
            assert!(
                !required(event, "/native/message")
                    .as_str()
                    .ok_or("Missing native error message")?
                    .is_empty()
            );
        } else if required(event, "/kind") == "console.error" {
            assert!(
                required(event, "/native/message")
                    .as_str()
                    .ok_or("Missing native logger message")?
                    .contains("Authentication request failed")
            );
            assert!(
                required(event, "/native/arguments")
                    .as_str()
                    .ok_or("Missing native logger error arguments")?
                    .contains("Serialization")
            );
        }
    }
    if !actual.is_empty() {
        eprintln!(
            "Email payload native diagnostics {}/{}: Rust={actual:?}; upstream={expected:?}",
            required(case, "/backend"),
            required(case, "/scenario")
        );
    }
    Ok(())
}
