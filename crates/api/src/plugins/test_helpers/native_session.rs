use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
};

use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction, FieldValue, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    observability::{BeforeEndpointHook, EndpointHooks},
    session::NativeSessionData,
    wire::SessionView,
};

#[derive(Clone, Default)]
pub(crate) struct NativeSessionHook(Arc<Mutex<Option<NativeSessionData>>>);

impl NativeSessionHook {
    pub(crate) fn install<S: AuthSchema>(
        context: &mut AuthContext<S>,
        routes: impl IntoIterator<Item = AuthRoute>,
    ) -> Self {
        let hook = Self::default();
        context
            .extensions
            .insert(Arc::new(EndpointDispatcher::<S>::new(
                Arc::new(Vec::new()),
                EndpointHooks {
                    before: Some(Arc::new(hook.clone())),
                    after: None,
                },
                routes,
            )));
        hook
    }

    pub(crate) fn request<S: AuthSchema>(
        &self,
        context: &AuthContext<S>,
        session: &SessionView,
        user: FieldValue,
        method: HttpMethod,
        path: &str,
        body: serde_json::Value,
    ) -> AuthResult<AuthRequest> {
        *self
            .0
            .lock()
            .map_err(|_| AuthError::internal("Native Session fixture lock poisoned"))? =
            Some(NativeSessionData {
                session: session.clone(),
                user,
            });
        let name = context
            .config
            .auth_cookie("session_token", Default::default())
            .name;
        let token = better_auth_core::utils::cookie_utils::sign_cookie_value(
            session.token.typed()?,
            context.config.signing_secret(),
        );
        Ok(AuthRequest::from_parts(
            method,
            path.into(),
            HashMap::from([
                ("cookie".into(), format!("{name}={token}")),
                ("content-type".into(), "application/json".into()),
            ]),
            Some(serde_json::to_vec(&body)?),
            None,
        ))
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> BeforeEndpointHook<S> for NativeSessionHook {
    async fn before(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| AuthError::internal("Native Session fixture lock poisoned"))?
            .clone()
            .map(|session| BeforeRequestAction::InjectNativeSession {
                session: Box::new(session),
            }))
    }
}

pub(crate) async fn dispatch<S, F, Fut>(
    request: &AuthRequest,
    context: &AuthContext<S>,
    handler: F,
) -> AuthResult<AuthResponse>
where
    S: AuthSchema,
    F: FnOnce(AuthRequest) -> Fut,
    Fut: Future<Output = AuthResult<AuthResponse>>,
{
    let dispatcher = context
        .extensions
        .get::<Arc<EndpointDispatcher<S>>>()
        .ok_or_else(|| AuthError::config("Native Session fixture dispatcher is missing"))?;
    let mut input = request.clone();
    let mut scope = better_auth_core::RequestHookContext::from_request(request)?;
    scope.is_http = true;
    let response = better_auth_core::with_request_hook_context_value(
        scope,
        dispatcher.run(&mut input, true, context, None, handler),
    )
    .await?;
    if response.is_api_error() {
        Err(response.into())
    } else {
        Ok(response)
    }
}

pub(crate) async fn dispatch_plugin<S: AuthSchema>(
    request: &AuthRequest,
    context: &AuthContext<S>,
    plugin: &impl AuthPlugin<S>,
) -> AuthResult<Option<AuthResponse>> {
    dispatch(request, context, |request| async move {
        plugin.on_request(&request, context).await?.ok_or_else(|| {
            AuthError::internal("Native Session fixture did not match a plugin endpoint")
        })
    })
    .await
    .map(Some)
}
