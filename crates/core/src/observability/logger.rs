use std::{error::Error, fmt, io::IsTerminal, sync::Arc};

use serde_json::Value;

/// Ordering preserves the separate success threshold; success callbacks receive `Info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    #[default]
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Success => "success",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Success => "SUCCESS",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Debug => "\x1b[35m",
            Self::Info => "\x1b[34m",
            Self::Success => "\x1b[32m",
            Self::Warn => "\x1b[33m",
            Self::Error => "\x1b[31m",
        }
    }
}

/// Callback arguments remain separate from the message and retain structured values and errors.
#[derive(Clone, Copy, Debug)]
pub enum LogArgument<'a> {
    Text(&'a str),
    Value(&'a Value),
    Error(&'a (dyn Error + Send + Sync)),
}

impl<'a> From<&'a str> for LogArgument<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(value)
    }
}
impl fmt::Display for LogArgument<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(value) => formatter.write_str(value),
            Self::Value(value) => formatter.write_str(
                &crate::SchemaValue::<String>::Dynamic(
                    crate::FieldValue::from_json((*value).clone()).map_err(|_| fmt::Error)?,
                )
                .display_string()
                .map_err(|_| fmt::Error)?,
            ),
            Self::Error(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

/// Synchronous application logger. The callback owns formatting and output.
pub trait LogSink: Send + Sync {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]);
}

/// Per-auth logger policy. The default sink emits Rust tracing events.
#[derive(Clone, Default)]
pub struct LoggerConfig {
    /// Omission keeps logging enabled without reporting an explicit telemetry option.
    pub disabled: Option<bool>,
    /// Omission uses the warning threshold.
    pub level: Option<LogLevel>,
    /// Control the default message renderer. Custom sinks receive unformatted messages.
    pub disable_colors: Option<bool>,
    pub log: Option<Arc<dyn LogSink>>,
}

impl fmt::Debug for LoggerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoggerConfig")
            .field("disabled", &self.disabled)
            .field("level", &self.level)
            .field("disable_colors", &self.disable_colors)
            .field("custom_sink", &self.log.is_some())
            .finish()
    }
}

impl LoggerConfig {
    pub fn enabled(&self, level: LogLevel) -> bool {
        !self.disabled.unwrap_or(false) && level >= self.level.unwrap_or_default()
    }

    pub fn log<'a>(
        &self,
        level: LogLevel,
        message: impl Into<LogArgument<'a>>,
        arguments: &[LogArgument<'_>],
    ) {
        let message = message.into();
        if !self.enabled(level) {
            return;
        }
        if let Some(sink) = &self.log {
            sink.log(
                if level == LogLevel::Success {
                    LogLevel::Info
                } else {
                    level
                },
                message,
                arguments,
            );
            return;
        }
        let colors = self
            .disable_colors
            .map_or_else(|| std::io::stdout().is_terminal(), |disabled| !disabled);
        let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let message = if colors {
            format!(
                "\x1b[2m{time}\x1b[0m {}{}\x1b[0m \x1b[1m[Better Auth]:\x1b[0m {message}",
                level.color(),
                level.name()
            )
        } else {
            format!("{time} {} [Better Auth]: {message}", level.name())
        };
        match level {
            LogLevel::Debug => tracing::debug!(target: "better-auth", message, ?arguments),
            LogLevel::Info | LogLevel::Success => {
                tracing::info!(target: "better-auth", message, ?arguments)
            }
            LogLevel::Warn => tracing::warn!(target: "better-auth", message, ?arguments),
            LogLevel::Error => tracing::error!(target: "better-auth", message, ?arguments),
        }
    }

    pub fn debug(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.log(LogLevel::Debug, message, arguments);
    }
    pub fn info(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.log(LogLevel::Info, message, arguments);
    }
    pub fn success(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.log(LogLevel::Success, message, arguments);
    }
    pub fn warn(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.log(LogLevel::Warn, message, arguments);
    }
    pub fn error(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.log(LogLevel::Error, message, arguments);
    }
}

/// Use the current auth instance's logger without retaining a process-global instance.
pub fn current() -> LoggerConfig {
    crate::request_runtime::current_logger().unwrap_or_default()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "The synchronous recording callback cannot propagate mutex poisoning through LogSink."
)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Capture(Mutex<Vec<(LogLevel, String, Vec<Value>)>>);
    impl LogSink for Capture {
        fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
            let arguments = arguments
                .iter()
                .map(|value| match value {
                    LogArgument::Text(value) => Value::String((*value).into()),
                    LogArgument::Value(value) => (*value).clone(),
                    LogArgument::Error(error) => Value::String(error.to_string()),
                })
                .collect();
            self.0.lock().expect("capture mutex is not poisoned").push((
                level,
                message.to_string(),
                arguments,
            ));
        }
    }

    #[test]
    fn thresholds_keep_success_order_and_custom_arguments_unformatted() {
        let levels = [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Success,
            LogLevel::Warn,
            LogLevel::Error,
        ];
        let structured = serde_json::json!({"value": 1});
        let tail = Value::String("tail".into());
        for configured_level in [None].into_iter().chain(levels.map(Some)) {
            let level = configured_level.unwrap_or_default();
            for disabled in [None, Some(false), Some(true)] {
                let sink = Arc::new(Capture::default());
                let logger = LoggerConfig {
                    level: configured_level,
                    disabled,
                    log: Some(sink.clone()),
                    disable_colors: Some(false),
                };
                for event in levels {
                    logger.log(
                        event,
                        "literal %s",
                        &[LogArgument::Value(&structured), LogArgument::Value(&tail)],
                    );
                }
                let expected: Vec<_> = levels
                    .into_iter()
                    .filter(|event| !disabled.unwrap_or(false) && *event >= level)
                    .map(|event| {
                        (
                            if event == LogLevel::Success {
                                LogLevel::Info
                            } else {
                                event
                            },
                            "literal %s".to_owned(),
                            vec![structured.clone(), tail.clone()],
                        )
                    })
                    .collect();
                assert_eq!(
                    *sink.0.lock().expect("capture mutex is not poisoned"),
                    expected
                );
            }
        }
    }
}
