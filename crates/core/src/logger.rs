//! Logging abstraction for Better Auth.
//!
//! Provides a [`Logger`] trait that can be implemented to customize logging
//! behavior, along with a default [`TracingLogger`] that delegates to the
//! [`tracing`] crate.

use std::fmt;
use std::sync::Arc;

/// Logging trait for Better Auth.
///
/// Implement this trait to provide custom logging behavior. The default
/// implementation ([`TracingLogger`]) delegates to the `tracing` crate.
///
/// # Example
///
/// ```rust
/// use better_auth_core::logger::{Logger, TracingLogger};
///
/// // Use the default tracing-based logger
/// let logger = TracingLogger;
/// logger.info("Server started");
///
/// // Or implement your own
/// struct MyLogger;
/// impl Logger for MyLogger {
///     fn info(&self, message: &str) {
///         println!("[INFO] {}", message);
///     }
///     fn warn(&self, message: &str) {
///         println!("[WARN] {}", message);
///     }
///     fn error(&self, message: &str) {
///         eprintln!("[ERROR] {}", message);
///     }
///     fn debug(&self, message: &str) {
///         println!("[DEBUG] {}", message);
///     }
/// }
/// ```
pub trait Logger: Send + Sync {
    /// Log an informational message.
    fn info(&self, message: &str);

    /// Log a warning message.
    fn warn(&self, message: &str);

    /// Log an error message.
    fn error(&self, message: &str);

    /// Log a debug message.
    fn debug(&self, message: &str);
}

impl fmt::Debug for dyn Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn Logger")
    }
}

/// Default logger implementation using the `tracing` crate.
///
/// This is the logger used when no custom logger is provided in the
/// [`AuthConfig`](crate::config::AuthConfig).
#[derive(Debug, Clone)]
pub struct TracingLogger;

impl Logger for TracingLogger {
    fn info(&self, message: &str) {
        tracing::info!("{}", message);
    }

    fn warn(&self, message: &str) {
        tracing::warn!("{}", message);
    }

    fn error(&self, message: &str) {
        tracing::error!("{}", message);
    }

    fn debug(&self, message: &str) {
        tracing::debug!("{}", message);
    }
}

/// Create the default logger instance.
///
/// Returns a `TracingLogger` wrapped in an `Arc` for shared ownership.
pub fn default_logger() -> Arc<dyn Logger> {
    Arc::new(TracingLogger)
}
