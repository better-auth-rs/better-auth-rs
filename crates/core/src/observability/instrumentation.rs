use std::future::Future;

use tracing::{Instrument, Span, field};

use crate::AuthResult;

#[derive(Clone, Debug, Default)]
pub struct ExperimentalConfig {
    pub instrumentation: InstrumentationConfig,
}

/// Control Better Auth spans independently of logging and usage reporting.
#[derive(Clone, Debug)]
pub struct InstrumentationConfig {
    pub enabled: bool,
}

impl Default for InstrumentationConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Semantic fields emitted at endpoint, hook and adapter boundaries.
#[derive(Clone, Copy, Default)]
pub struct SpanAttributes<'a> {
    pub route: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub hook_type: Option<&'a str>,
    pub context: Option<&'a str>,
    pub collection: Option<&'a str>,
    pub database_operation: Option<&'a str>,
}

fn span(config: &InstrumentationConfig, name: &str, attributes: SpanAttributes<'_>) -> Span {
    if !config.enabled {
        return Span::none();
    }
    let span = tracing::info_span!(target: "better-auth", "better_auth",
        "otel.name" = name,
        "otel.scope.name" = "better-auth", "otel.scope.version" = "1.7.6",
        "http.route" = field::Empty, "better_auth.operation_id" = field::Empty,
        "better_auth.hook.type" = field::Empty, "better_auth.context" = field::Empty,
        "db.collection.name" = field::Empty, "db.operation.name" = field::Empty,
        "http.response.status_code" = field::Empty,
        "otel.status_code" = field::Empty, "otel.status_description" = field::Empty,
    );
    for (name, value) in [
        ("http.route", attributes.route),
        ("better_auth.operation_id", attributes.operation_id),
        ("better_auth.hook.type", attributes.hook_type),
        ("better_auth.context", attributes.context),
        ("db.collection.name", attributes.collection),
        ("db.operation.name", attributes.database_operation),
    ] {
        if let Some(value) = value {
            let _ = span.record(name, value);
        }
    }
    span
}

/// Trace one actual operation. Dropping the future also releases its span.
pub fn with_span<T, F>(
    config: &InstrumentationConfig,
    name: &str,
    attributes: SpanAttributes<'_>,
    operation: F,
) -> impl Future<Output = AuthResult<T>> + use<T, F>
where
    F: Future<Output = AuthResult<T>>,
{
    // Box the operation before constructing the instrumented future; nested dispatchers can be large.
    let operation = Box::pin(operation);
    let enabled = config.enabled;
    let span = span(config, name, attributes);
    let records = span.clone();
    async move {
        let result = operation.await;
        if enabled && let Err(error) = &result {
            if error.is_api_error() && (300..400).contains(&error.status_code()) {
                let _ = records.record("http.response.status_code", error.status_code());
                let _ = records.record("otel.status_code", "OK");
            } else {
                let message = error.instrumentation_message();
                tracing::event!(name: "exception", target: "better-auth", tracing::Level::ERROR, "exception.message" = %message);
                let _ = records.record("otel.status_code", "ERROR");
                let _ = records.record("otel.status_description", message.as_str());
            }
        }
        result
    }.instrument(span)
}

/// Trace an actual matched endpoint hook; matcher evaluation stays outside this boundary.
pub async fn with_endpoint_hook<T>(
    config: &crate::AuthConfig,
    request: &crate::AuthRequest,
    phase: &str,
    source: &str,
    operation: impl Future<Output = AuthResult<T>>,
) -> AuthResult<T> {
    let context = crate::hooks::current_request_hook_context();
    let route = context
        .as_ref()
        .map_or(request.path(), |context| context.path.as_str());
    let operation_id = context
        .as_ref()
        .and_then(|context| context.operation_id.as_deref())
        .unwrap_or(route);
    with_span(
        &config.experimental.instrumentation,
        &format!("hook {phase} {route} {source}"),
        SpanAttributes {
            route: Some(route),
            operation_id: Some(operation_id),
            hook_type: Some(phase),
            context: Some(source),
            ..Default::default()
        },
        operation,
    )
    .await
}
