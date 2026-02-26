#[cfg(feature = "axum")]
use axum::{
    Router,
    extract::{Request, State},
    response::{Response, IntoResponse},
    http::{StatusCode, HeaderMap},
    routing::{get, post},
};
#[cfg(feature = "axum")]
use tower::ServiceBuilder;
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
use crate::{BetterAuth, AuthRequest, AuthResponse};
use crate::types::HttpMethod;
#[cfg(feature = "axum")]
use crate::error::AuthError;

/// Integration trait for Axum web framework
#[cfg(feature = "axum")]
pub trait AxumIntegration {
    /// Create an Axum router with all authentication routes
    fn axum_router(self) -> Router<Arc<BetterAuth>>;
}

#[cfg(feature = "axum")]
impl AxumIntegration for Arc<BetterAuth> {
    fn axum_router(self) -> Router<Arc<BetterAuth>> {
        let mut router = Router::new();
        
        // Add default health check route
        router = router.route("/health", get(health_check));
        
        for route in self.routes() {
            let handler_fn = create_plugin_handler();
            match route.method {
                crate::types::HttpMethod::Get => {
                    router = router.route(&route.path, get(handler_fn.clone()));
                },
                crate::types::HttpMethod::Post => {
                    router = router.route(&route.path, post(handler_fn.clone()));
                },
                crate::types::HttpMethod::Put => {
                    router = router.route(&route.path, axum::routing::put(handler_fn.clone()));
                },
                crate::types::HttpMethod::Delete => {
                    router = router.route(&route.path, axum::routing::delete(handler_fn.clone()));
                },
                crate::types::HttpMethod::Patch => {
                    router = router.route(&route.path, axum::routing::patch(handler_fn.clone()));
                },
                _ => {} // Skip unsupported methods
            }
        }
        
        router.with_state(self)
    }
}

#[cfg(feature = "axum")]
async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "better-auth"
    }))
}

#[cfg(feature = "axum")]
fn create_plugin_handler() -> impl Fn(State<Arc<BetterAuth>>, Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Clone {
    |State(auth): State<Arc<BetterAuth>>, req: Request| {
        Box::pin(async move {
            match convert_axum_request(req).await {
                Ok(auth_req) => {
                    match auth.handle_request(auth_req).await {
                        Ok(auth_response) => convert_auth_response(auth_response),
                        Err(err) => err.into_response(),
                    }
                },
                Err(err) => err.into_response(),
            }
        })
    }
}

#[cfg(feature = "axum")]
async fn convert_axum_request(req: Request) -> Result<AuthRequest, AuthError> {
    use axum::body::Body;
    use axum::extract::Request as AxumRequest;
    use std::collections::HashMap;
    
    let (parts, body) = req.into_parts();
    
    // Convert method
    let method = match parts.method {
        axum::http::Method::GET => HttpMethod::Get,
        axum::http::Method::POST => HttpMethod::Post,
        axum::http::Method::PUT => HttpMethod::Put,
        axum::http::Method::DELETE => HttpMethod::Delete,
        axum::http::Method::PATCH => HttpMethod::Patch,
        axum::http::Method::OPTIONS => HttpMethod::Options,
        axum::http::Method::HEAD => HttpMethod::Head,
        _ => return Err(AuthError::InvalidRequest("Unsupported HTTP method".to_string())),
    };
    
    // Convert headers
    let mut headers = HashMap::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }
    
    // Get path
    let path = parts.uri.path().to_string();
    
    // Convert query parameters
    let mut query = HashMap::new();
    if let Some(query_str) = parts.uri.query() {
        for (key, value) in url::form_urlencoded::parse(query_str.as_bytes()) {
            query.insert(key.to_string(), value.to_string());
        }
    }
    
    // Convert body
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => if bytes.is_empty() { None } else { Some(bytes.to_vec()) },
        Err(_) => None,
    };
    
    Ok(AuthRequest {
        method,
        path,
        headers,
        body: body_bytes,
        query,
        virtual_user_id: None,
    })
}

#[cfg(feature = "axum")]
fn convert_auth_response(auth_response: AuthResponse) -> Response {
    let mut response = Response::builder()
        .status(StatusCode::from_u16(auth_response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    
    // Add headers
    for (name, value) in auth_response.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value)
        ) {
            response = response.header(header_name, header_value);
        }
    }
    
    response.body(axum::body::Body::from(auth_response.body))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal server error"))
                .unwrap()
        })
}

#[cfg(feature = "axum")]
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthError::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session not found or expired"),
            AuthError::Unauthenticated => (StatusCode::UNAUTHORIZED, "Authentication required"),
            AuthError::Unauthorized => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "Invalid request"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        
        let body = serde_json::json!({
            "error": message,
            "details": self.to_string()
        });
        
        (status, axum::Json(body)).into_response()
    }
}  
