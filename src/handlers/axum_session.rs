use std::{marker::PhantomData, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, HeaderName, HeaderValue, request::Parts},
    response::{IntoResponse, IntoResponseParts, Response, ResponseParts},
};
use better_auth_core::{
    AuthError, AuthResponse, AuthSchema,
    session::{SessionData, SessionRead},
    wire::{SessionView, UserView},
};

use crate::BetterAuth;

/// Resolve public session data through the configured cookie cache and server store.
/// Return `(session, response)` to send refresh cookies with the application response.
#[derive(Debug, Clone)]
pub struct CachedSession<T: AuthSchema> {
    pub user: UserView,
    pub session: SessionView,
    headers: HeaderMap,
    schema: PhantomData<T>,
}

/// Resolve an optional session while retaining credential cleanup and refresh headers.
/// Return `(session, response)` even when `data` is `None`.
#[derive(Debug, Clone)]
pub struct OptionalCachedSession<T: AuthSchema> {
    pub data: Option<SessionData>,
    headers: HeaderMap,
    schema: PhantomData<T>,
}

impl<S, T> FromRequestParts<S> for CachedSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let optional = OptionalCachedSession::<T>::from_request_parts(parts, state).await?;
        let Some(data) = optional.data else {
            return Err((optional, AuthError::Unauthenticated.into_response()).into_response());
        };
        Ok(Self {
            user: data.user,
            session: data.session,
            headers: optional.headers,
            schema: PhantomData,
        })
    }
}

impl<S, T> FromRequestParts<S> for OptionalCachedSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Arc::<BetterAuth<T>>::from_ref(state);
        resolve(parts, &auth).await.map_err(|response| *response)
    }
}

impl<T: AuthSchema> IntoResponseParts for CachedSession<T> {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, response: ResponseParts) -> Result<ResponseParts, Self::Error> {
        Ok(append_headers(&self.headers, response))
    }
}

impl<T: AuthSchema> IntoResponseParts for OptionalCachedSession<T> {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, response: ResponseParts) -> Result<ResponseParts, Self::Error> {
        Ok(append_headers(&self.headers, response))
    }
}

fn append_headers(headers: &HeaderMap, mut response: ResponseParts) -> ResponseParts {
    for (name, value) in headers {
        let _ = response.headers_mut().append(name.clone(), value.clone());
    }
    response
}

async fn resolve<T: AuthSchema>(
    parts: &Parts,
    auth: &BetterAuth<T>,
) -> Result<OptionalCachedSession<T>, Box<Response>> {
    let request = super::axum::session_request(parts);
    let resolution = auth
        .session_manager()
        .resolve(&request, SessionRead::Cached)
        .await;
    let failed = resolution.is_err();
    let (data, mut response) = match resolution {
        Ok(resolution) => (resolution.data, AuthResponse::new(200)),
        Err(error) => (None, error.to_auth_response()),
    };
    let _ = response.headers.insert("Cache-Control", "no-store");
    let _ = response.headers.insert("Pragma", "no-cache");
    auth.session_manager()
        .finish_response(&request, &mut response)
        .map_err(|error| Box::new(error.into_response()))?;
    if failed {
        return Err(Box::new(super::axum::convert_auth_response(response)));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            Box::new(
                AuthError::internal(format!("Invalid session response header name: {error}"))
                    .into_response(),
            )
        })?;
        let value = HeaderValue::from_str(&value).map_err(|error| {
            Box::new(
                AuthError::internal(format!("Invalid session response header value: {error}"))
                    .into_response(),
            )
        })?;
        let _ = headers.append(name, value);
    }
    Ok(OptionalCachedSession {
        data,
        headers,
        schema: PhantomData,
    })
}
