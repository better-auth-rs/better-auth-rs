//! Application-defined session responses without changing stored sessions.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, FieldValue, FromFieldMap, HttpMethod, ResponseBody, session::NativeSessionData,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The public session and the optional deferred-refresh signal.
/// Read individual User values with `data.user_field`, or use `data.user_view` for object slots.
/// Native callbacks retain absent values, null, relationship pages, and object identity.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomSessionInput {
    #[serde(flatten)]
    pub data: NativeSessionData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_refresh: Option<bool>,
}

impl CustomSessionInput {
    fn from_field_value(value: &FieldValue) -> AuthResult<Self> {
        let fields = value.as_object().ok_or_else(|| {
            better_auth_core::AuthError::internal("Custom session input must be an object")
        })?;
        Ok(Self {
            data: NativeSessionData::from_field_values(fields.clone())?,
            needs_refresh: fields
                .get("needsRefresh")
                .cloned()
                .unwrap_or_default()
                .decode()?,
        })
    }

    fn from_response(body: &ResponseBody) -> AuthResult<Option<Self>> {
        match body {
            ResponseBody::Native(FieldValue::Null | FieldValue::Undefined) => Ok(None),
            ResponseBody::Empty => Ok(None),
            ResponseBody::Native(value) => Self::from_field_value(value).map(Some),
            ResponseBody::Bytes(bytes) => Ok(serde_json::from_slice(bytes)?),
            ResponseBody::Binary(_) | ResponseBody::Blob(_) => Err(
                better_auth_core::AuthError::type_error("Custom session input must be an object"),
            ),
        }
    }

    fn list_from_response(body: &ResponseBody) -> AuthResult<Option<Vec<Self>>> {
        match body {
            ResponseBody::Native(FieldValue::Null | FieldValue::Undefined) => Ok(None),
            ResponseBody::Empty => Ok(None),
            ResponseBody::Native(FieldValue::Array(values)) => values
                .iter()
                .map(Self::from_field_value)
                .collect::<AuthResult<_>>()
                .map(Some),
            ResponseBody::Native(_) => Err(better_auth_core::AuthError::internal(
                "Device sessions response must be an array",
            )),
            ResponseBody::Bytes(bytes) => Ok(serde_json::from_slice(bytes)?),
            ResponseBody::Binary(_) | ResponseBody::Blob(_) => {
                Err(better_auth_core::AuthError::type_error(
                    "Device sessions response must be an array",
                ))
            }
        }
    }
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
                return AuthResponse::json(None, &Value::Null);
            }
        };
        let data = CustomSessionInput::from_response(&response.body)?;
        if let Some(data) = data {
            let value = self.callback.customize(data, request, context).await?;
            response.replace_json(&value)?;
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
                let sessions = CustomSessionInput::list_from_response(&response.body)?;
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
                    response.replace_json(&values)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{FieldDate, FieldMap};

    #[test]
    fn custom_session_input_keeps_native_user_values_and_aliases() -> AuthResult<()> {
        let shared: FieldValue = FieldMap::from([
            ("ownUndefined".into(), FieldValue::Undefined),
            ("date".into(), FieldDate::from_milliseconds(123.0).into()),
        ])
        .into();
        for user in [
            FieldValue::Undefined,
            FieldValue::Null,
            7.0.into(),
            vec![shared.clone(), shared.clone()].into(),
            FieldMap::from([("0".into(), shared.clone()), ("1".into(), shared.clone())]).into(),
        ] {
            let body = ResponseBody::Native(
                FieldMap::from([
                    ("session".into(), FieldMap::new().into()),
                    ("user".into(), user.clone()),
                    ("needsRefresh".into(), true.into()),
                ])
                .into(),
            );
            let input = CustomSessionInput::from_response(&body)?.ok_or_else(|| {
                better_auth_core::AuthError::internal("Expected native custom session input")
            })?;
            assert!(input.data.user.strict_equals(&user));
            assert_eq!(input.needs_refresh, Some(true));
        }
        Ok(())
    }

    #[test]
    fn custom_session_bytes_preserve_absent_and_non_object_user_values() -> AuthResult<()> {
        for source in [
            serde_json::json!({"session": {}, "needsRefresh": false}),
            serde_json::json!({"session": {}, "user": null}),
            serde_json::json!({"session": {}, "user": 7}),
            serde_json::json!({"session": {}, "user": [{"id": null}]}),
        ] {
            let input = CustomSessionInput::from_response(&ResponseBody::Bytes(
                serde_json::to_vec(&source)?,
            ))?
            .ok_or_else(|| {
                better_auth_core::AuthError::internal("Expected JSON custom session input")
            })?;
            assert_eq!(input.data.user.is_undefined(), source.get("user").is_none());
            assert_eq!(serde_json::to_value(input)?, source);
        }
        Ok(())
    }
}
