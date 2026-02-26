#[cfg(feature = "axum")]
use axum::{
    Router,
    extract::{FromRequestParts, Request, State},
    http::StatusCode,
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
use crate::BetterAuth;
#[cfg(feature = "axum")]
use better_auth_core::SessionManager;
#[cfg(feature = "axum")]
use better_auth_core::entity::AuthSession as AuthSessionTrait;
use better_auth_core::{
    AuthError, AuthRequest, AuthResponse, DatabaseAdapter, ErrorMessageResponse,
    HealthCheckResponse, HttpMethod, OkResponse,
};

/// Integration trait for Axum web framework
#[cfg(feature = "axum")]
pub trait AxumIntegration<DB: DatabaseAdapter> {
    /// Create an Axum router with all authentication routes
    fn axum_router(self) -> Router<Arc<BetterAuth<DB>>>;
}

#[cfg(feature = "axum")]
impl<DB: DatabaseAdapter> AxumIntegration<DB> for Arc<BetterAuth<DB>> {
    fn axum_router(self) -> Router<Arc<BetterAuth<DB>>> {
        let disabled_paths = self.config().disabled_paths.clone();

        let mut router = Router::new();

        // Add status endpoints
        if !disabled_paths.contains(&"/ok".to_string()) {
            router = router.route("/ok", get(ok_check));
        }
        if !disabled_paths.contains(&"/error".to_string()) {
            router = router.route("/error", get(error_check));
        }

        // Add default health check route
        if !disabled_paths.contains(&"/health".to_string()) {
            router = router.route("/health", get(health_check));
        }

        // Add OpenAPI spec endpoint
        if !disabled_paths.contains(&"/reference/openapi.json".to_string()) {
            router = router.route(
                "/reference/openapi.json",
                get(create_plugin_handler::<DB>()),
            );
        }

        // Add core user management routes
        if !disabled_paths.contains(&"/update-user".to_string()) {
            router = router.route("/update-user", post(create_plugin_handler::<DB>()));
        }
        if !disabled_paths.contains(&"/delete-user".to_string()) {
            router = router.route("/delete-user", post(create_plugin_handler::<DB>()));
            router = router.route("/delete-user", delete(create_plugin_handler::<DB>()));
        }

        // Register plugin routes
        for plugin in self.plugins() {
            for route in plugin.routes() {
                // Skip disabled paths
                if disabled_paths.contains(&route.path) {
                    continue;
                }

                let handler_fn = create_plugin_handler::<DB>();
                match route.method {
                    HttpMethod::Get => {
                        router = router.route(&route.path, get(handler_fn.clone()));
                    }
                    HttpMethod::Post => {
                        router = router.route(&route.path, post(handler_fn.clone()));
                    }
                    HttpMethod::Put => {
                        router = router.route(&route.path, axum::routing::put(handler_fn.clone()));
                    }
                    HttpMethod::Delete => {
                        router =
                            router.route(&route.path, axum::routing::delete(handler_fn.clone()));
                    }
                    HttpMethod::Patch => {
                        router =
                            router.route(&route.path, axum::routing::patch(handler_fn.clone()));
                    }
                    _ => {} // Skip unsupported methods
                }
            }
        }

        router.with_state(self)
    }
}

#[cfg(feature = "axum")]
async fn ok_check() -> impl IntoResponse {
    axum::Json(OkResponse { ok: true })
}

#[cfg(feature = "axum")]
async fn error_check() -> impl IntoResponse {
    axum::Json(OkResponse { ok: false })
}

#[cfg(feature = "axum")]
async fn health_check() -> impl IntoResponse {
    axum::Json(HealthCheckResponse {
        status: "ok",
        service: "better-auth",
    })
}

#[cfg(feature = "axum")]
#[allow(clippy::type_complexity)]
fn create_plugin_handler<DB: DatabaseAdapter>() -> impl Fn(
    State<Arc<BetterAuth<DB>>>,
    Request,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Response> + Send>,
> + Clone {
    |State(auth): State<Arc<BetterAuth<DB>>>, req: Request| {
        Box::pin(async move {
            match convert_axum_request(req).await {
                Ok(auth_req) => match auth.handle_request(auth_req).await {
                    Ok(auth_response) => convert_auth_response(auth_response),
                    Err(err) => convert_auth_error(err),
                },
                Err(err) => convert_auth_error(err),
            }
        })
    }
}

#[cfg(feature = "axum")]
async fn convert_axum_request(req: Request) -> Result<AuthRequest, AuthError> {
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
        _ => {
            return Err(AuthError::InvalidRequest(
                "Unsupported HTTP method".to_string(),
            ));
        }
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
        Ok(bytes) => {
            if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            }
        }
        Err(_) => None,
    };

    Ok(AuthRequest {
        method,
        path,
        headers,
        body: body_bytes,
        query,
    })
}

#[cfg(feature = "axum")]
fn convert_auth_response(auth_response: AuthResponse) -> Response {
    let mut response = Response::builder().status(
        StatusCode::from_u16(auth_response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );

    // Add headers
    for (name, value) in auth_response.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            response = response.header(header_name, header_value);
        }
    }

    response
        .body(axum::body::Body::from(auth_response.body))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal server error"))
                .unwrap()
        })
}

#[cfg(feature = "axum")]
fn convert_auth_error(err: AuthError) -> Response {
    let status_code =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let message = match err.status_code() {
        500 => "Internal server error".to_string(),
        _ => err.to_string(),
    };

    let body = ErrorMessageResponse { message };

    (status_code, axum::Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Axum extractors
// ---------------------------------------------------------------------------

/// Authenticated session extractor.
///
/// Extracts and validates the current user and session from the request.
/// Returns `401 Unauthorized` if no valid session is found.
///
/// Requires `State<Arc<BetterAuth<DB>>>` to be present in the router.
///
/// # Example
///
/// ```rust,ignore
/// use better_auth::handlers::axum::CurrentSession;
///
/// async fn profile(session: CurrentSession<MyDB>) -> impl IntoResponse {
///     let user = &session.user;
///     let session = &session.session;
///     axum::Json(serde_json::json!({ "id": user.id() }))
/// }
/// ```
#[cfg(feature = "axum")]
pub struct CurrentSession<DB: DatabaseAdapter> {
    pub user: DB::User,
    pub session: DB::Session,
}

/// Optional authenticated session extractor.
///
/// Like [`CurrentSession`] but returns `None` instead of a 401 error when
/// no valid session is found. Useful for routes that behave differently
/// for authenticated vs anonymous users.
///
/// # Example
///
/// ```rust,ignore
/// async fn home(session: OptionalSession<MyDB>) -> impl IntoResponse {
///     if let Some(session) = session.0 {
///         axum::Json(serde_json::json!({ "user": session.user.id() }))
///     } else {
///         axum::Json(serde_json::json!({ "user": null }))
///     }
/// }
/// ```
#[cfg(feature = "axum")]
pub struct OptionalSession<DB: DatabaseAdapter>(pub Option<CurrentSession<DB>>);

/// Extract a session token from the request parts.
///
/// Checks the `Authorization: Bearer <token>` header first, then falls
/// back to the configured session cookie.
#[cfg(feature = "axum")]
fn extract_token_from_parts(parts: &Parts, cookie_name: &str) -> Option<String> {
    // Try Bearer token first
    if let Some(auth_header) = parts.headers.get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }

    // Fall back to cookie
    if let Some(cookie_header) = parts.headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for part in cookie_str.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix(&format!("{}=", cookie_name))
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
    }

    None
}

#[cfg(feature = "axum")]
impl<DB: DatabaseAdapter> FromRequestParts<Arc<BetterAuth<DB>>> for CurrentSession<DB> {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<BetterAuth<DB>>,
    ) -> Result<Self, Self::Rejection> {
        let cookie_name = &state.config().session.cookie_name;
        let token = extract_token_from_parts(parts, cookie_name)
            .ok_or_else(|| convert_auth_error(AuthError::Unauthenticated))?;

        let session_manager =
            SessionManager::new(Arc::new(state.config().clone()), state.database().clone());

        let session = session_manager
            .get_session(&token)
            .await
            .map_err(convert_auth_error)?
            .ok_or_else(|| convert_auth_error(AuthError::SessionNotFound))?;

        let user = state
            .database()
            .get_user_by_id(session.user_id())
            .await
            .map_err(convert_auth_error)?
            .ok_or_else(|| convert_auth_error(AuthError::UserNotFound))?;

        Ok(CurrentSession { user, session })
    }
}

#[cfg(feature = "axum")]
impl<DB: DatabaseAdapter> FromRequestParts<Arc<BetterAuth<DB>>> for OptionalSession<DB> {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<BetterAuth<DB>>,
    ) -> Result<Self, Self::Rejection> {
        match CurrentSession::from_request_parts(parts, state).await {
            Ok(session) => Ok(OptionalSession(Some(session))),
            Err(_) => Ok(OptionalSession(None)),
        }
    }
}
