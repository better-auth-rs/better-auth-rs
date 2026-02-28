//! Axum extractors for better-auth.
//!
//! Provides type-safe request extraction that eliminates boilerplate
//! in plugin handler functions.

#[cfg(feature = "axum")]
mod axum_impl {
    use axum::{
        Json,
        extract::{FromRequest, FromRequestParts, Request},
        http::request::Parts,
    };
    use serde::de::DeserializeOwned;
    use validator::Validate;

    use crate::adapters::DatabaseAdapter;
    use crate::entity::{AuthSession, AuthUser};
    use crate::error::AuthError;
    use crate::plugin::AuthState;

    // -----------------------------------------------------------------------
    // CurrentSession — extract and validate the current user + session
    // -----------------------------------------------------------------------

    /// Authenticated session extractor for `AuthState<DB>`.
    ///
    /// Extracts a session token from the `Authorization: Bearer <token>` header
    /// or the configured session cookie, validates it, and returns the user and
    /// session.  Returns `AuthError::Unauthenticated` if no valid session is
    /// found.
    pub struct CurrentSession<DB: DatabaseAdapter> {
        pub user: DB::User,
        pub session: DB::Session,
    }

    /// Optional authenticated session extractor.
    ///
    /// Like [`CurrentSession`] but returns `None` instead of a rejection when
    /// no valid session is found.
    pub struct OptionalSession<DB: DatabaseAdapter>(pub Option<CurrentSession<DB>>);

    /// Extract a session token from request parts.
    ///
    /// Checks `Authorization: Bearer <token>` first, then the configured
    /// session cookie.
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

    impl<DB: DatabaseAdapter> FromRequestParts<AuthState<DB>> for CurrentSession<DB> {
        type Rejection = AuthError;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AuthState<DB>,
        ) -> Result<Self, Self::Rejection> {
            let cookie_name = &state.config.session.cookie_name;
            let token =
                extract_token_from_parts(parts, cookie_name).ok_or(AuthError::Unauthenticated)?;

            let session = state
                .session_manager
                .get_session(&token)
                .await?
                .ok_or(AuthError::SessionNotFound)?;

            let user = state
                .database
                .get_user_by_id(session.user_id())
                .await?
                .ok_or(AuthError::UserNotFound)?;

            Ok(CurrentSession { user, session })
        }
    }

    impl<DB: DatabaseAdapter> FromRequestParts<AuthState<DB>> for OptionalSession<DB> {
        type Rejection = AuthError;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AuthState<DB>,
        ) -> Result<Self, Self::Rejection> {
            match CurrentSession::from_request_parts(parts, state).await {
                Ok(session) => Ok(OptionalSession(Some(session))),
                Err(_) => Ok(OptionalSession(None)),
            }
        }
    }

    // -----------------------------------------------------------------------
    // ValidatedJson — deserialize + validate request body
    // -----------------------------------------------------------------------

    /// Extractor that deserializes JSON and runs `validator::Validate`.
    ///
    /// Replaces the `validate_request_body()` helper used throughout plugins.
    /// Returns `AuthError::Validation` on failure.
    pub struct ValidatedJson<T>(pub T);

    impl<S, T> FromRequest<S> for ValidatedJson<T>
    where
        T: DeserializeOwned + Validate,
        S: Send + Sync,
    {
        type Rejection = AuthError;

        async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
            let Json(value) = Json::<T>::from_request(req, _state)
                .await
                .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;

            value
                .validate()
                .map_err(|e| AuthError::validation(e.to_string()))?;

            Ok(ValidatedJson(value))
        }
    }

    // -----------------------------------------------------------------------
    // AuthRequestExt — convert axum Request to AuthRequest
    // -----------------------------------------------------------------------

    /// Extractor that converts an axum `Request` into an `AuthRequest`.
    ///
    /// Enables delegation to existing plugin handler methods that accept
    /// `&AuthRequest`. This is the primary bridge between the axum-native
    /// routing and legacy handler signatures.
    pub struct AuthRequestExt(pub crate::types::AuthRequest);

    impl<S: Send + Sync> FromRequest<S> for AuthRequestExt {
        type Rejection = AuthError;

        async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
            use crate::types::HttpMethod;
            use std::collections::HashMap;

            let (parts, body) = req.into_parts();

            let method = match parts.method {
                axum::http::Method::GET => HttpMethod::Get,
                axum::http::Method::POST => HttpMethod::Post,
                axum::http::Method::PUT => HttpMethod::Put,
                axum::http::Method::DELETE => HttpMethod::Delete,
                axum::http::Method::PATCH => HttpMethod::Patch,
                axum::http::Method::OPTIONS => HttpMethod::Options,
                axum::http::Method::HEAD => HttpMethod::Head,
                _ => return Err(AuthError::bad_request("Unsupported HTTP method")),
            };

            let mut headers = HashMap::new();
            for (name, value) in parts.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.to_string(), value_str.to_string());
                }
            }

            let path = parts.uri.path().to_string();

            let mut query = HashMap::new();
            if let Some(query_str) = parts.uri.query() {
                for (key, value) in url::form_urlencoded::parse(query_str.as_bytes()) {
                    query.insert(key.to_string(), value.to_string());
                }
            }

            let body_bytes = axum::body::to_bytes(body, usize::MAX)
                .await
                .map_err(|e| AuthError::bad_request(format!("Failed to read body: {}", e)))?;

            let body_opt = if body_bytes.is_empty() {
                None
            } else {
                Some(body_bytes.to_vec())
            };

            Ok(AuthRequestExt(crate::types::AuthRequest::from_parts(
                method, path, headers, body_opt, query,
            )))
        }
    }

    // -----------------------------------------------------------------------
    // AxumAuthResponse — convert AuthResponse to axum Response
    // -----------------------------------------------------------------------

    /// Wrapper that converts an `AuthResponse` into an axum `Response`.
    pub struct AxumAuthResponse(pub crate::types::AuthResponse);

    impl axum::response::IntoResponse for AxumAuthResponse {
        fn into_response(self) -> axum::response::Response {
            let auth_response = self.0;
            let mut response = axum::response::Response::builder().status(
                axum::http::StatusCode::from_u16(auth_response.status)
                    .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            );

            for (name, value) in &auth_response.headers {
                if let (Ok(header_name), Ok(header_value)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    axum::http::HeaderValue::from_str(value),
                ) {
                    response = response.header(header_name, header_value);
                }
            }

            response
                .body(axum::body::Body::from(auth_response.body))
                .unwrap_or_else(|_| {
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(axum::body::Body::from("Internal server error"))
                        .unwrap()
                })
        }
    }

    // -----------------------------------------------------------------------
    // AdminSession — authenticated session with admin role check
    // -----------------------------------------------------------------------

    /// Extractor that validates the session and checks for admin role.
    ///
    /// Requires `AuthState<DB>` and an `Extension<AdminRole>` to be present
    /// in the router (set by the admin plugin's router).
    pub struct AdminSession<DB: DatabaseAdapter> {
        pub user: DB::User,
        pub session: DB::Session,
    }

    /// The role string required for admin access.
    ///
    /// Injected as an axum `Extension` by the admin plugin router.
    #[derive(Clone)]
    pub struct AdminRole(pub String);

    impl<DB: DatabaseAdapter> FromRequestParts<AuthState<DB>> for AdminSession<DB> {
        type Rejection = AuthError;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AuthState<DB>,
        ) -> Result<Self, Self::Rejection> {
            let current = CurrentSession::<DB>::from_request_parts(parts, state).await?;

            // Try to get AdminRole from extensions, default to "admin"
            let required_role = parts
                .extensions
                .get::<AdminRole>()
                .map(|r| r.0.as_str())
                .unwrap_or("admin");

            let user_role = current.user.role().unwrap_or("user");
            if user_role != required_role {
                return Err(AuthError::forbidden(
                    "You must be an admin to access this endpoint",
                ));
            }

            Ok(AdminSession {
                user: current.user,
                session: current.session,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Pending2faToken — extract a pending 2FA token from Authorization header
    // -----------------------------------------------------------------------

    /// Extractor for pending 2FA authentication tokens.
    ///
    /// Extracts a `Bearer 2fa_*` token from the `Authorization` header, looks up
    /// the corresponding verification record, validates expiry, and returns the
    /// associated user.
    pub struct Pending2faToken<DB: DatabaseAdapter> {
        pub user: DB::User,
        pub verification_id: String,
        pub token: String,
    }

    impl<DB: DatabaseAdapter> FromRequestParts<AuthState<DB>> for Pending2faToken<DB> {
        type Rejection = AuthError;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AuthState<DB>,
        ) -> Result<Self, Self::Rejection> {
            use crate::entity::AuthVerification;

            let token = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(AuthError::Unauthenticated)?;

            if !token.starts_with("2fa_") {
                return Err(AuthError::bad_request("Invalid 2FA pending token"));
            }

            let identifier = format!("2fa_pending:{}", token);
            let verification = state
                .database
                .get_verification_by_identifier(&identifier)
                .await?
                .ok_or_else(|| AuthError::bad_request("Invalid or expired 2FA token"))?;

            if verification.expires_at() < chrono::Utc::now() {
                return Err(AuthError::bad_request("2FA token expired"));
            }

            let user_id = verification.value();
            let user = state
                .database
                .get_user_by_id(user_id)
                .await?
                .ok_or(AuthError::UserNotFound)?;

            Ok(Pending2faToken {
                user,
                verification_id: verification.id().to_string(),
                token: token.to_string(),
            })
        }
    }
}

#[cfg(feature = "axum")]
pub use axum_impl::*;
