//! HTTP routing error policy. Endpoint responses and native calls retain their own boundaries.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use crate::{AuthContext, AuthError, AuthResponse, AuthResult, AuthSchema};

/// Detached asynchronous work returned by an HTTP error callback.
pub type ApiErrorTask = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'static>>;

/// Observe a router failure using the resolved authentication context.
///
/// Return `Err` to throw synchronously. Return a future for asynchronous work that must not
/// delay the response. The future starts before the response and continues in the request scope.
/// A detached failure is logged; the failure cannot replace an already returned response.
pub trait ApiErrorHandler<S: AuthSchema>: Send + Sync {
    fn on_error(
        &self,
        error: &AuthError,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<ApiErrorTask>>;
}

/// Apply the policy only at the HTTP router's endpoint invocation catch boundary.
pub async fn handle_http_error<S: AuthSchema>(
    error: AuthError,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    if error.is_found_redirect() {
        return Ok(error.to_auth_response());
    }
    if context.config.api_error.throw_errors() {
        return rethrow(error);
    }
    if let Some(callback) = context.extensions.get::<Arc<dyn ApiErrorHandler<S>>>() {
        let task = match callback.on_error(&error, context) {
            Ok(task) => task,
            Err(replacement) => return rethrow(replacement),
        };
        if let Some(mut task) = task {
            // JavaScript executes an async callback until its first suspension before returning its Promise.
            match poll_fn(|cx| Poll::Ready(task.as_mut().poll(cx))).await {
                Poll::Ready(result) => report_detached_error(result),
                Poll::Pending => {
                    drop(crate::request_runtime::spawn_with_request_context(
                        async move {
                            report_detached_error(task.await);
                        },
                    ));
                }
            }
        }
    }
    Ok(error.to_http_response())
}

fn rethrow(error: AuthError) -> AuthResult<AuthResponse> {
    // The outer HTTP router still serializes thrown API errors, including callback replacements.
    if error.is_api_error() {
        Ok(error.to_auth_response())
    } else {
        Err(error)
    }
}

fn report_detached_error(result: AuthResult<()>) {
    if let Err(error) = result {
        crate::observability::logger::current().error(
            "Detached onAPIError callback failed",
            &[crate::observability::LogArgument::Error(&error)],
        );
    }
}
