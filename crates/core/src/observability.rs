//! Per-instance diagnostics and tracing. Usage reporting is configured independently.

pub mod instrumentation;
pub mod logger;
pub mod telemetry;

pub use instrumentation::{ExperimentalConfig, InstrumentationConfig, SpanAttributes, with_span};
pub use logger::{LogArgument, LogLevel, LogSink, LoggerConfig};
pub use telemetry::{TelemetryConfig, TelemetryEvent, TelemetryTransport};

pub mod database;

pub mod hooks;
pub use hooks::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
