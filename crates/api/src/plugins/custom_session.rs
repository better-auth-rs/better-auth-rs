//! Application-defined session responses without changing stored sessions.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod, session::SessionData,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The public session and the optional deferred-refresh signal.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomSessionInput {
    #[serde(flatten)]
    pub data: SessionData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_refresh: Option<bool>,
}

/// Transform a public session with access to the request and typed runtime store.
#[async_trait]
pub trait CustomSessionCallback<S: AuthSchema>: Send + Sync + 'static {
    async fn customize(
        &self,
        session: CustomSessionInput,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Value>;
}

/// Override the session response. Internal authentication retains the original session.
pub struct CustomSessionPlugin<S: AuthSchema> {
    callback: Arc<dyn CustomSessionCallback<S>>,
    mutate_list_device_sessions: bool,
}

impl<S: AuthSchema> Clone for CustomSessionPlugin<S> {
    fn clone(&self) -> Self {
        Self {
            callback: self.callback.clone(),
            mutate_list_device_sessions: self.mutate_list_device_sessions,
        }
    }
}

impl<S: AuthSchema> CustomSessionPlugin<S> {
    pub fn new(callback: impl CustomSessionCallback<S>) -> Self {
        Self {
            callback: Arc::new(callback),
            mutate_list_device_sessions: false,
        }
    }

    /// Apply the same callback to each remembered device session.
    pub fn mutate_list_device_sessions(mut self, enabled: bool) -> Self {
        self.mutate_list_device_sessions = enabled;
        self
    }

    pub(crate) async fn get_session(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        // Upstream customSession catches the nested session read, including store errors.
        // Callback errors propagate after that read and do not retain its response cookies.
        let response = super::session_management::SessionManagementPlugin::new()
            .handle_get_session(request, context)
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(_) => {
                let _ = request.take_response_headers()?;
                return Ok(AuthResponse::json(200, &Value::Null)?);
            }
        };
        let data: Option<CustomSessionInput> = serde_json::from_slice(&response.body)?;
        if let Some(data) = data {
            let value = self.callback.customize(data, request, context).await?;
            response.body = serde_json::to_vec(&value)?;
        }
        Ok(response)
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CustomSessionPlugin<S> {
    fn name(&self) -> &'static str {
        "custom-session"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "getSession")
                .require_headers(true)
                .query_validator(better_auth_core::query::session_query),
        ]
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.extensions.insert(self.clone());
        Ok(())
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (request.method(), request.path()) {
            (HttpMethod::Get, "/get-session") => self.get_session(request, context).await.map(Some),
            (HttpMethod::Post, "/get-session") => Ok(Some(AuthResponse::new(404))),
            _ => Ok(None),
        }
    }

    async fn after_request(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !(self.mutate_list_device_sessions
            && request.path() == "/multi-session/list-device-sessions")
        {
            return Ok(());
        }
        better_auth_core::observability::instrumentation::with_endpoint_hook(
            &context.config,
            request,
            "after",
            "plugin:custom-session",
            async {
                if !self.mutate_list_device_sessions
                    || request.path() != "/multi-session/list-device-sessions"
                    || response.status != 200
                {
                    return Ok(());
                }
                let sessions: Option<Vec<CustomSessionInput>> =
                    serde_json::from_slice(&response.body)?;
                if let Some(sessions) = sessions {
                    let context = Arc::new(context.clone());
                    let request = Arc::new(request.clone());
                    let hook_context = better_auth_core::hooks::current_request_hook_context();
                    // Promise.all rejects early while the other callbacks keep running.
                    // Dropping a JoinHandle detaches the callback instead of cancelling it.
                    let callbacks: Vec<_> = sessions
                        .into_iter()
                        .map(|session| {
                            let callback = self.callback.clone();
                            let context = context.clone();
                            let request = request.clone();
                            let hook_context = hook_context.clone();
                            tokio::spawn(async move {
                                let future = callback.customize(session, &request, &context);
                                match hook_context {
                                    Some(hook_context) => {
                                        better_auth_core::with_request_hook_context_value(
                                            hook_context,
                                            future,
                                        )
                                        .await
                                    }
                                    None => future.await,
                                }
                            })
                        })
                        .collect();
                    let values = futures_util::future::try_join_all(callbacks.into_iter().map(
                        |callback| async {
                            callback.await.map_err(|error| {
                                better_auth_core::AuthError::internal(format!(
                                    "Custom session callback task failed: {error}"
                                ))
                            })?
                        },
                    ))
                    .await?;
                    response.body = serde_json::to_vec(&values)?;
                    for (name, value) in request.take_response_headers()? {
                        if name.eq_ignore_ascii_case("set-cookie") {
                            response.headers.append(name, value);
                        } else {
                            let _ = response.headers.insert(name, value);
                        }
                    }
                }
                Ok(())
            },
        )
        .await
    }
}
