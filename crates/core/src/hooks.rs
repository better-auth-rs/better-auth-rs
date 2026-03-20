use crate::types::{AuthRequest, HttpMethod, RequestMeta};

/// Request-derived data available to middleware, stores, and other hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    pub method: HttpMethod,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub query: std::collections::HashMap<String, String>,
    pub meta: RequestMeta,
}

impl RequestHookContext {
    /// Build a request hook context from an incoming auth request.
    pub fn from_request(request: &AuthRequest) -> Self {
        Self {
            method: request.method().clone(),
            path: request.path().to_string(),
            headers: request.headers.clone(),
            query: request.query.clone(),
            meta: RequestMeta::from_request(request),
        }
    }
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: RequestHookContext;
}

/// Run a future with request context available to downstream integrations.
pub async fn with_request_hook_context<T>(
    request: &AuthRequest,
    future: impl std::future::Future<Output = T>,
) -> T {
    with_request_hook_context_value(RequestHookContext::from_request(request), future).await
}

/// Run a future with an explicit request hook context.
pub async fn with_request_hook_context_value<T>(
    request_context: RequestHookContext,
    future: impl std::future::Future<Output = T>,
) -> T {
    REQUEST_HOOK_CONTEXT.scope(request_context, future).await
}

pub fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT.try_with(Clone::clone).ok()
}
