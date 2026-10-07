use crate::types::{AuthRequest, HttpMethod, RequestMeta};

/// Request-derived data available to middleware, stores, and other hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    /// Request snapshot for plugin callbacks; native calls still use `is_http` to identify HTTP.
    pub request: AuthRequest,
    /// True only while the HTTP router owns response serialization.
    /// Native calls can carry headers and still preserve their original errors.
    pub is_http: bool,
    pub method: HttpMethod,
    /// Matched endpoint template; native-only outer hooks have no endpoint path.
    pub path: Option<String>,
    /// Effective endpoint identifier for instrumentation.
    pub operation_id: Option<String>,
    /// Values captured from the matched endpoint path.
    pub params: std::collections::HashMap<String, String>,
    pub headers: std::collections::HashMap<String, String>,
    pub query: Option<serde_json::Value>,
    /// Parsed endpoint input. An absent request body remains absent.
    pub body: crate::FieldValue,
    pub meta: RequestMeta,
}

impl RequestHookContext {
    /// Build a request hook context from an incoming auth request.
    pub fn from_request(request: &AuthRequest) -> crate::AuthResult<Self> {
        Ok(Self {
            request: request.clone(),
            is_http: false,
            method: request.method().clone(),
            path: Some(request.path().to_string()),
            operation_id: None,
            params: Default::default(),
            headers: request.headers.clone(),
            query: request.query.clone(),
            body: request.hook_field_value()?,
            meta: RequestMeta::from_request(request),
        })
    }
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: std::cell::RefCell<RequestHookContext>;
}

/// Run a future with request context available to downstream integrations.
pub async fn with_request_hook_context<T>(
    request: &AuthRequest,
    future: impl std::future::Future<Output = crate::AuthResult<T>>,
) -> crate::AuthResult<T> {
    with_request_hook_context_value(RequestHookContext::from_request(request)?, future).await
}

/// Run a future with an explicit request hook context.
pub fn with_request_hook_context_value<T>(
    request_context: RequestHookContext,
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    // Validation nests another endpoint scope around the handler future.
    // Keep that future off each scope's stack frame.
    REQUEST_HOOK_CONTEXT.scope(std::cell::RefCell::new(request_context), Box::pin(future))
}

pub fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT
        .try_with(|context| context.borrow().clone())
        .ok()
}

/// Record the matched endpoint without changing the request's actual path.
pub fn set_request_hook_route(path: &str, route: Option<&crate::AuthRoute>) {
    let mut params = std::collections::HashMap::new();
    let path = route.map_or_else(
        || path.to_owned(),
        |route| {
            route
                .path
                .split('/')
                .zip(path.split('/'))
                .map(|(segment, value)| {
                    if let Some(name) = segment
                        .strip_prefix('{')
                        .and_then(|name| name.strip_suffix('}'))
                    {
                        let _ = params.insert(name.to_owned(), value.to_owned());
                        format!(":{name}")
                    } else {
                        segment.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        },
    );
    let _ = REQUEST_HOOK_CONTEXT.try_with(|context| {
        let mut context = context.borrow_mut();
        context.path = Some(path);
        context.operation_id = route.map(|route| {
            route
                .openapi
                .as_ref()
                .and_then(|metadata| metadata.operation_id.clone())
                .or_else(|| route.endpoint_key.clone())
                .unwrap_or_else(|| route.operation_id.clone())
        });
        context.params = params;
    });
}

/// Refresh the active snapshot after HTTP parsing or body replacement.
/// Preserve the matched route, trusted IP metadata, and HTTP error policy.
pub fn update_request_hook_context(request: &AuthRequest) -> crate::AuthResult<()> {
    let body = request.input_field_value()?;
    let _ = REQUEST_HOOK_CONTEXT.try_with(|context| {
        let mut context = context.borrow_mut();
        context.method = request.method.clone();
        context.headers = request.headers.clone();
        context.query = request.query.clone();
        context.body = body;
        context.request = request.clone();
    });
    Ok(())
}
