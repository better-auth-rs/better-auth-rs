//! Notification work that can outlive an endpoint and its transaction.

use crate::{
    AuthResult,
    observability::{LogArgument, LoggerConfig},
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// An application notification that may run after its endpoint completes.
pub type BackgroundFuture = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'static>>;

/// An already-running notification. Dropping this handle does not cancel the task.
pub struct BackgroundTask(tokio::task::JoinHandle<()>);
impl Future for BackgroundTask {
    type Output = Result<(), tokio::task::JoinError>;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(context)
    }
}

/// Application integration for retaining background tasks until delivery completes.
#[derive(Clone)]
pub struct BackgroundTasks(Arc<dyn Fn(BackgroundTask) -> AuthResult<()> + Send + Sync>);
impl fmt::Debug for BackgroundTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundTasks").finish_non_exhaustive()
    }
}
impl BackgroundTasks {
    /// Receive a running task, for example to register the task with a server lifetime manager.
    pub fn new(handler: impl Fn(BackgroundTask) -> AuthResult<()> + Send + Sync + 'static) -> Self {
        Self(Arc::new(handler))
    }
}

fn log_failure(logger: &LoggerConfig, message: &str, error: &crate::AuthError) {
    logger.error(message, &[LogArgument::Error(error)]);
}

/// Await a notification by default, or hand its running task to the configured handler.
/// Callback factories run before this function; their synchronous errors remain endpoint errors.
pub async fn run_or_await(
    task: Option<BackgroundFuture>,
    handler: Option<&BackgroundTasks>,
    logger: &LoggerConfig,
) {
    run_or_await_with_error_message(task, handler, logger, "Failed to run background task:").await;
}

/// Schedule delivery with its endpoint-specific failure message.
/// Handler failures retain the shared background-task error message.
#[doc(hidden)]
pub async fn run_or_await_with_error_message(
    task: Option<BackgroundFuture>,
    handler: Option<&BackgroundTasks>,
    logger: &LoggerConfig,
    error_message: &'static str,
) {
    let Some(mut task) = task else {
        return;
    };
    let Some(handler) = handler else {
        if let Err(error) = task.await {
            log_failure(logger, error_message, &error);
        }
        return;
    };
    // JavaScript callbacks start before the handler receives their promise. Poll once
    // in the caller's context before transferring the pending Rust future.
    let first = std::future::poll_fn(|context| Poll::Ready(task.as_mut().poll(context))).await;
    let ready = match first {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    };
    let pending = ready.is_none();
    let start = std::sync::Arc::new(tokio::sync::Notify::new());
    let task_start = start.clone();
    let task_logger = logger.clone();
    let handle = crate::request_runtime::spawn_with_request_context(async move {
        task_start.notified().await;
        if pending && let Err(error) = task.await {
            log_failure(&task_logger, error_message, &error);
        }
    });
    if let Err(error) = (handler.0)(BackgroundTask(handle)) {
        log_failure(logger, "Failed to run background task:", &error);
    }
    // An already-rejected promise runs its catch after handler invocation and before
    // the awaiting endpoint continues. A worker must not race ahead of that handler.
    if let Some(Err(error)) = ready {
        log_failure(logger, error_message, &error);
    }
    start.notify_one();
}
