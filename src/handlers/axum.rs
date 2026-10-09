#[cfg(feature = "axum")]
use axum::{
    Router,
    extract::{FromRef, FromRequestParts, Request, State},
    http::StatusCode,
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
use crate::BetterAuth;
#[cfg(feature = "axum")]
use better_auth_core::AuthSession;
#[cfg(feature = "axum")]
use better_auth_core::middleware::BodyLimitConfig;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthSchema, HttpMethod, core_paths};

#[cfg(feature = "axum")]
type AxumAuthHandlerFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;

/// Integration trait for Axum web framework
#[cfg(feature = "axum")]
pub trait AxumIntegration {
    type Schema: AuthSchema;

    /// Create an Axum router with all authentication routes
    fn axum_router(self) -> Router<Arc<BetterAuth<Self::Schema>>>;

    /// Create an Axum router that can be nested into an application using a
    /// custom state type.
    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Self: Sized,
        Arc<BetterAuth<Self::Schema>>: FromRef<S>,
        S: Clone + Send + Sync + 'static;
}

#[cfg(feature = "axum")]
impl<T: AuthSchema> AxumIntegration for Arc<BetterAuth<T>> {
    type Schema = T;

    fn axum_router(self) -> Router<Arc<BetterAuth<T>>> {
        self.axum_router_with_state::<Arc<BetterAuth<T>>>()
    }

    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Arc<BetterAuth<T>>: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        // Omit disabled registrations. The fallback applies the same disabled-path
        // check before HTTP plugins can inspect an unregistered request.
        let disabled_paths = self.config().disabled_paths.clone();

        let mut router = Router::new();

        // Add status endpoints
        if !disabled_paths.contains(&core_paths::OK.to_string()) {
            router = router.route(core_paths::OK, get(create_plugin_handler::<T>()));
        }
        if !disabled_paths.contains(&core_paths::ERROR.to_string()) {
            router = router.route(core_paths::ERROR, get(create_plugin_handler::<T>()));
        }

        // Add OpenAPI spec endpoint
        if !disabled_paths.contains(&core_paths::OPENAPI_SPEC.to_string()) {
            router = router.route(core_paths::OPENAPI_SPEC, get(create_plugin_handler::<T>()));
        }

        // Add core user management routes
        if !disabled_paths.contains(&core_paths::UPDATE_USER.to_string()) {
            router = router.route(core_paths::UPDATE_USER, post(create_plugin_handler::<T>()));
        }
        // One Axum route dispatches through all matching plugins.
        let mut registered = std::collections::HashSet::new();
        for plugin in self.plugins() {
            for route in plugin.routes() {
                // Skip disabled paths
                if disabled_paths.contains(&route.path)
                    || !registered.insert((route.method.clone(), route.path.clone()))
                {
                    continue;
                }

                let handler_fn = create_plugin_handler::<T>();
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

        router
            .fallback(create_plugin_handler::<T>())
            .method_not_allowed_fallback(create_plugin_handler::<T>())
    }
}

#[cfg(feature = "axum")]
fn create_plugin_handler<T: AuthSchema>()
-> impl Fn(State<Arc<BetterAuth<T>>>, Request) -> AxumAuthHandlerFuture + Clone {
    |State(auth): State<Arc<BetterAuth<T>>>, req: Request| {
        Box::pin(async move {
            match convert_axum_request(req, max_body_bytes(auth.body_limit())).await {
                Ok(auth_req) => match auth.handle_request(auth_req).await {
                    Ok(auth_response) => convert_auth_response(auth_response),
                    Err(err) => err.into_response(),
                },
                Err(err) => err.into_response(),
            }
        })
    }
}

/// Effective pre-parse body cap: `usize::MAX` when the caller disabled the
/// limit, otherwise the configured maximum.
#[cfg(feature = "axum")]
fn max_body_bytes(config: &BodyLimitConfig) -> usize {
    if config.enabled {
        config.max_bytes
    } else {
        usize::MAX
    }
}

/// Whether an axum body error was caused by hitting the read limit, as opposed
/// to a transport failure (malformed chunked framing, client disconnect).
#[cfg(feature = "axum")]
fn is_body_length_limit_error(err: &axum::Error) -> bool {
    use std::error::Error;

    let mut source = err.source();
    while let Some(e) = source {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        source = e.source();
    }
    false
}

#[cfg(feature = "axum")]
async fn convert_axum_request(
    req: Request,
    max_body_bytes: usize,
) -> Result<AuthRequest, AuthError> {
    use std::collections::HashMap;

    let (parts, body) = req.into_parts();
    let url = transport_url(&parts)?;
    let mounted = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .is_some_and(|original| original.0.path() != parts.uri.path());

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
            let _ = headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Get path
    let path = parts.uri.path().to_string();

    let query = Some(better_auth_core::query::parse_url_query(
        parts.uri.query().unwrap_or_default(),
    ));

    // Bound the body read at the caller-configured limit. `BodyLimitMiddleware`
    // runs on the already-buffered `AuthRequest` and only sees `Content-Length`,
    // so it cannot stop a `Transfer-Encoding: chunked` body from exhausting
    // memory — this pre-parse cap is the only defence on that path.
    if let Some(len) = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        && len > max_body_bytes
    {
        return Err(AuthError::payload_too_large(format!(
            "Request body exceeds the {max_body_bytes}-byte limit"
        )));
    }

    // Convert body
    let body_bytes = match axum::body::to_bytes(body, max_body_bytes).await {
        Ok(bytes) => {
            if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            }
        }
        Err(err) => {
            if is_body_length_limit_error(&err) {
                return Err(AuthError::payload_too_large(format!(
                    "Request body exceeds the {max_body_bytes}-byte limit"
                )));
            }
            tracing::warn!(error = %err, "Failed to read request body");
            return Err(AuthError::bad_request("Failed to read request body"));
        }
    };

    let request = AuthRequest::from_parts(method, path, headers, body_bytes, query);
    let request = if mounted {
        request.with_base_relative_path()
    } else {
        request
    };
    Ok(match url {
        Some(url) => request.with_url(url),
        None => request,
    })
}

#[cfg(feature = "axum")]
fn transport_url(parts: &Parts) -> Result<Option<url::Url>, AuthError> {
    use axum::{
        extract::OriginalUri,
        http::{Uri, uri::Scheme},
    };

    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    let authority = match uri.authority() {
        Some(authority) => Some(authority.as_str()),
        None => parts
            .headers
            .get(axum::http::header::HOST)
            .map(|host| {
                host.to_str()
                    .map_err(|_| AuthError::bad_request("Invalid request host"))
            })
            .transpose()?,
    };
    let Some(authority) = authority else {
        return Ok(None);
    };
    let scheme = parts
        .extensions
        .get::<Scheme>()
        .or_else(|| uri.scheme())
        .unwrap_or(&Scheme::HTTP);
    if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
        return Err(AuthError::bad_request("Request URL must use HTTP or HTTPS"));
    }
    let uri = Uri::builder()
        .scheme(scheme.clone())
        .authority(authority)
        .path_and_query(uri.path_and_query().map_or("/", |path| path.as_str()))
        .build()
        .map_err(|_| AuthError::bad_request("Invalid request URL"))?;
    url::Url::parse(&uri.to_string())
        .map(Some)
        .map_err(|_| AuthError::bad_request("Invalid request URL"))
}

#[cfg(feature = "axum")]
pub(super) fn convert_auth_response(auth_response: AuthResponse) -> Response {
    let auth_response = match auth_response.into_http_response() {
        Ok(response) => response,
        Err(error) => return error.into_response(),
    };
    let body = match auth_response.body.into_bytes() {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
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

    match response.body(axum::body::Body::from(body)) {
        Ok(resp) => resp,
        Err(_) => {
            let (mut parts, _) = Response::new(()).into_parts();
            parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            Response::from_parts(parts, axum::body::Body::from("Internal server error"))
        }
    }
}

// ---------------------------------------------------------------------------
// Axum extractors
// ---------------------------------------------------------------------------

/// Authenticated session extractor.
///
/// Extracts and validates the current user and session from the request.
/// Returns `401 Unauthorized` if no valid session is found.
///
/// Requires `State<Arc<BetterAuth>>` to be present in the router.
///
/// # Example
///
/// ```rust,ignore
/// use better_auth::integrations::axum::CurrentSession;
///
/// async fn profile(session: CurrentSession<AppAuthSchema>) -> impl IntoResponse {
///     let user = &session.user;
///     let session = &session.session;
///     axum::Json(serde_json::json!({ "id": user.id() }))
/// }
/// ```
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct CurrentSession<T: AuthSchema> {
    pub user: better_auth_core::UserView,
    pub session: better_auth_core::SessionView,
    schema: std::marker::PhantomData<T>,
}

/// Optional authenticated session extractor.
///
/// Like [`CurrentSession`] but returns `None` instead of a 401 error when
/// no valid session is found. Useful for routes that behave differently
/// for authenticated vs anonymous users. Database and internal errors remain rejections.
///
/// # Example
///
/// ```rust,ignore
/// async fn home(session: OptionalSession<AppAuthSchema>) -> impl IntoResponse {
///     if let Some(session) = session.0 {
///         axum::Json(serde_json::json!({ "user": session.user.id() }))
///     } else {
///         axum::Json(serde_json::json!({ "user": null }))
///     }
/// }
/// ```
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct OptionalSession<T: AuthSchema>(pub Option<CurrentSession<T>>);

#[cfg(feature = "axum")]
impl<S, T> FromRequestParts<S> for CurrentSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Arc::<BetterAuth<T>>::from_ref(state);
        resolve_session(parts, &auth)
            .await
            .map_err(IntoResponse::into_response)
    }
}

#[cfg(feature = "axum")]
impl<S, T> FromRequestParts<S> for OptionalSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Arc::<BetterAuth<T>>::from_ref(state);
        match resolve_session(parts, &auth).await {
            Ok(session) => Ok(OptionalSession(Some(session))),
            Err(
                AuthError::Unauthenticated | AuthError::SessionNotFound | AuthError::UserNotFound,
            ) => Ok(OptionalSession(None)),
            Err(error) => Err(error.into_response()),
        }
    }
}

#[cfg(feature = "axum")]
async fn resolve_session<T: AuthSchema>(
    parts: &Parts,
    auth: &BetterAuth<T>,
) -> better_auth_core::AuthResult<CurrentSession<T>> {
    let request = session_request(parts);
    let token = auth
        .session_manager()
        .extract_session_token(&request)
        .ok_or(AuthError::Unauthenticated)?;
    let session = auth
        .session_manager()
        .get_session(&token)
        .await?
        .ok_or(AuthError::SessionNotFound)?;
    let user = auth
        .store()
        .get_user_by_id(session.user_id().typed()?)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    Ok(CurrentSession {
        user,
        session,
        schema: std::marker::PhantomData,
    })
}

#[cfg(feature = "axum")]
pub(super) fn session_request(parts: &Parts) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Get, parts.uri.path());
    request.headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect();
    request
}
