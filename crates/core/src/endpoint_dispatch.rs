//! Shared endpoint hooks, validation, handler and response lifecycle.
use crate::hooks::{
    RequestHookContext, update_request_hook_context, with_request_hook_context_value,
};
use crate::observability::EndpointHooks;
use crate::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction, HttpMethod,
};
use std::{future::Future, sync::Arc};

/// Immutable dispatch data. No authentication context is retained by this executor.
pub struct EndpointDispatcher<S: AuthSchema> {
    plugins: Arc<Vec<Box<dyn AuthPlugin<S>>>>,
    hooks: EndpointHooks<S>,
    routes: Vec<AuthRoute>,
}
impl<S: AuthSchema> EndpointDispatcher<S> {
    pub fn new(
        plugins: Arc<Vec<Box<dyn AuthPlugin<S>>>>,
        hooks: EndpointHooks<S>,
        core_routes: impl IntoIterator<Item = AuthRoute>,
    ) -> Self {
        let routes = core_routes
            .into_iter()
            .chain(plugins.iter().flat_map(|plugin| plugin.routes()))
            .collect();
        Self {
            plugins,
            hooks,
            routes,
        }
    }

    /// Dispatch a native endpoint without importing an ambient HTTP Request.
    pub async fn native<F, Fut>(
        &self,
        mut request: AuthRequest,
        route: AuthRoute,
        context: &AuthContext<S>,
        handler: F,
    ) -> AuthResult<AuthResponse>
    where
        F: FnOnce(AuthRequest) -> Fut,
        Fut: Future<Output = AuthResult<AuthResponse>>,
    {
        if route.server_only {
            request.path = "/".into();
            request.set_server_only();
        } else {
            request.path = route.path.clone();
        }
        let mut scope = RequestHookContext::from_request(&request)?;
        scope.path = (!route.server_only).then(|| route.path.clone());
        scope.body = request.input_field_value()?;
        scope.operation_id = Some(route.operation_id.clone());
        scope.meta = crate::RequestMeta::from_request_with_config(
            &request,
            &context.config.advanced.ip_address,
        );
        let method = match request.method() {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Head => "HEAD",
        };
        let route_path = if route.server_only {
            "/:virtual"
        } else {
            &route.path
        };
        let name = format!("{method} {route_path}");
        let operation_id = route.operation_id.clone();
        let route_path = route_path.to_owned();
        with_request_hook_context_value(
            scope,
            crate::observability::with_span(
                &context.config.experimental.instrumentation,
                &name,
                crate::observability::SpanAttributes {
                    route: Some(&route_path),
                    operation_id: Some(&operation_id),
                    ..Default::default()
                },
                self.run(&mut request, false, context, Some(route), handler),
            ),
        )
        .await
    }

    /// Run the same pipeline for HTTP and native endpoints. The handler may borrow an active transaction.
    pub async fn run<F, Fut>(
        &self,
        req: &mut AuthRequest,
        http: bool,
        context: &AuthContext<S>,
        native_route: Option<AuthRoute>,
        handler: F,
    ) -> AuthResult<AuthResponse>
    where
        F: FnOnce(AuthRequest) -> Fut,
        Fut: Future<Output = AuthResult<AuthResponse>>,
    {
        // Strip base_path prefix from the request path for internal routing.
        // This happens BEFORE plugin hooks so that `before_request` sees the
        // same normalised path that `on_request` / core handlers use.
        // HTTP routing already selected a base-relative path. Native callers may include the base path.
        let base_path = context.base_path();
        let stripped_path = if !http && !base_path.is_empty() && base_path != "/" {
            req.path().strip_prefix(base_path).unwrap_or(req.path())
        } else {
            req.path()
        };

        // Build a request with the stripped path for all subsequent dispatch
        let mut internal_req = if stripped_path != req.path() {
            let mut r = req.clone();
            r.path = stripped_path.to_string();
            r
        } else {
            req.clone()
        };
        internal_req.set_endpoint_body(internal_req.unvalidated_input()?);
        update_request_hook_context(&internal_req)?;

        let mut input_patch = crate::endpoint_input::EndpointInputPatch::default();
        if let Some(hook) = &self.hooks.before {
            let action = match crate::observability::instrumentation::with_endpoint_hook(
                &context.config,
                &internal_req,
                "before",
                "user",
                hook.before(&internal_req, context),
            )
            .await
            {
                Ok(action) => action,
                Err(error) => return Err(endpoint_error(error, &internal_req)?),
            };
            if let Some(response) =
                apply_before_action(action, &mut internal_req, req, &mut input_patch)?
            {
                return Ok(response);
            }
        }

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        // Plugins now see the normalised (base_path-stripped) path.
        for plugin in self.plugins.iter() {
            let action = match plugin.before_request(&internal_req, context).await {
                Ok(action) => action,
                Err(error) => return Err(endpoint_error(error, &internal_req)?),
            };
            if let Some(response) =
                apply_before_action(action, &mut internal_req, req, &mut input_patch)?
            {
                return Ok(response);
            }
        }

        if http && internal_req.original_request().is_none() {
            internal_req = internal_req.with_original_request(req.clone());
        }
        input_patch.apply(&mut internal_req)?;
        update_request_hook_context(&internal_req)?;
        let route = native_route.or_else(|| {
            self.routes
                .iter()
                .find(|route| route.matches(internal_req.method(), internal_req.path()))
                .cloned()
        });
        let snapshot = crate::hooks::current_request_hook_context();
        let route_name = if internal_req.is_server_only() {
            "/:virtual"
        } else {
            snapshot.as_ref().map_or(internal_req.path(), |snapshot| {
                snapshot.path.as_deref().unwrap_or("/:virtual")
            })
        };
        let operation_id = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.operation_id.as_deref())
            .unwrap_or(route_name);
        let result = crate::observability::with_span(
            &context.config.experimental.instrumentation,
            &format!("handler {route_name}"),
            crate::observability::SpanAttributes {
                route: Some(route_name),
                operation_id: Some(operation_id),
                ..Default::default()
            },
            async {
                let input = async {
                    let body = match route
                        .as_ref()
                        .and_then(|route| route.body_validator.as_ref())
                    {
                        Some(validate) => validate.validate(&internal_req).await?,
                        None => internal_req.unvalidated_input()?,
                    };
                    let query = match route.as_ref().and_then(|route| route.query_validator) {
                        Some(validate) => validate(internal_req.query.clone())?,
                        None => internal_req.query.clone(),
                    };
                    if route.as_ref().is_some_and(|route| route.require_headers)
                        && internal_req.endpoint_headers().is_none()
                    {
                        return Err(AuthError::Upstream {
                            status: 400,
                            code: "VALIDATION_ERROR",
                            message: "Headers is required",
                        });
                    }
                    let mut request = internal_req.clone();
                    request.set_endpoint_body(body);
                    request.query = query;
                    Ok(request)
                }
                .await;
                match input {
                    Ok(mut request) => {
                        if request.is_server_only() {
                            request.path = "virtual:".into();
                        }
                        let future = crate::endpoint_input::with_validated_input(
                            request.input_field_value()?,
                            request.query.clone(),
                            handler(request.clone()),
                        );
                        if request.is_server_only() {
                            let mut scope = match crate::hooks::current_request_hook_context() {
                                Some(scope) => scope,
                                None => RequestHookContext::from_request(&request)?,
                            };
                            scope.path = Some("virtual:".into());
                            scope.request = request.clone();
                            scope.query = request.query.clone();
                            scope.body = request.input_field_value()?;
                            scope.operation_id =
                                route.as_ref().map(|route| route.operation_id.clone());
                            with_request_hook_context_value(scope, future).await
                        } else {
                            future.await
                        }
                    }
                    Err(error) => Err(error),
                }
            },
        )
        .await;
        let mut response = match result {
            Ok(response) => response,
            Err(error) if error.is_api_error() => error.to_auth_response(),
            Err(error) => return Err(error),
        };
        context
            .session_manager()
            .finish_response(&internal_req, &mut response)?;
        if let Some(hook) = &self.hooks.after {
            let result = crate::observability::instrumentation::with_endpoint_hook(
                &context.config,
                &internal_req,
                "after",
                "user",
                hook.after(&internal_req, &mut response, context),
            )
            .await;
            apply_after_result(result, &internal_req, &mut response)?;
        }
        for plugin in self.plugins.iter() {
            let result = plugin
                .after_request(&internal_req, &mut response, context)
                .await;
            apply_after_result(result, &internal_req, &mut response)?;
        }
        if response.is_api_error() && !http {
            response.capture_error_headers(response.headers.clone());
            Err(response.into())
        } else {
            Ok(response)
        }
    }
}
fn endpoint_error(error: AuthError, request: &AuthRequest) -> AuthResult<AuthError> {
    if !error.is_api_error() {
        return Ok(error);
    }
    Ok(error.capture_endpoint_headers(request.take_response_headers()?))
}

fn apply_before_action(
    action: Option<BeforeRequestAction>,
    internal: &mut AuthRequest,
    original: &mut AuthRequest,
    input_patch: &mut crate::endpoint_input::EndpointInputPatch,
) -> AuthResult<Option<AuthResponse>> {
    match action {
        Some(BeforeRequestAction::Respond(mut response)) => {
            response.headers.merge(internal.take_response_headers()?);
            return Ok(Some(response));
        }
        Some(BeforeRequestAction::MergeContext(patch)) => input_patch.merge(patch),
        Some(BeforeRequestAction::ReplaceBody(body)) => {
            internal.body = Some(body.clone());
            original.body = Some(body);
            let raw_body = internal.input_body()?;
            internal.set_endpoint_body(crate::endpoint_input::ValidatedBody::unvalidated(raw_body));
            update_request_hook_context(internal)?;
        }
        Some(BeforeRequestAction::InjectSession { session }) => {
            internal.set_session_snapshot(None)?;
            internal.set_virtual_session(*session);
        }
        Some(BeforeRequestAction::InjectNativeSession { session }) => {
            internal.set_session_snapshot(Some((*session).into()))?;
            internal.virtual_session = None;
        }
        None => (),
    }
    Ok(None)
}
fn apply_after_result(
    result: AuthResult<()>,
    request: &AuthRequest,
    response: &mut AuthResponse,
) -> AuthResult<()> {
    match result {
        Ok(()) => response.headers.merge(request.take_response_headers()?),
        Err(error) if error.is_api_error() => {
            response.headers.merge(request.take_response_headers()?);
            response.replace_returned(error.to_auth_response());
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

impl<S: AuthSchema> AuthContext<S> {
    /// Invoke a native endpoint with the instance's shared hook and validation pipeline.
    pub async fn dispatch_native<F, Fut>(
        &self,
        source: crate::NativeRequest<'_>,
        route: AuthRoute,
        body: Option<serde_json::Value>,
        query: Option<serde_json::Value>,
        handler: F,
    ) -> AuthResult<AuthResponse>
    where
        F: FnOnce(AuthRequest, Arc<AuthContext<S>>) -> Fut + Send,
        Fut: Future<Output = AuthResult<AuthResponse>> + Send,
    {
        let mut request = native_request(source, &route);
        request.body = body.as_ref().map(serde_json::to_vec).transpose()?;
        request.set_endpoint_body(crate::endpoint_input::ValidatedBody::unvalidated(body));
        request.query = query;
        self.dispatch_native_request(source, route, request, handler)
            .await
    }

    /// Invoke a native endpoint while retaining Date, undefined, and object identities.
    pub async fn dispatch_native_value<F, Fut>(
        &self,
        source: crate::NativeRequest<'_>,
        route: AuthRoute,
        body: crate::FieldValue,
        query: Option<serde_json::Value>,
        handler: F,
    ) -> AuthResult<AuthResponse>
    where
        F: FnOnce(AuthRequest, Arc<AuthContext<S>>) -> Fut + Send,
        Fut: Future<Output = AuthResult<AuthResponse>> + Send,
    {
        let mut request = native_request(source, &route);
        request.set_endpoint_body(crate::endpoint_input::ValidatedBody::unvalidated_native(
            body,
        ));
        request.query = query;
        self.dispatch_native_request(source, route, request, handler)
            .await
    }

    async fn dispatch_native_request<F, Fut>(
        &self,
        source: crate::NativeRequest<'_>,
        route: AuthRoute,
        request: AuthRequest,
        handler: F,
    ) -> AuthResult<AuthResponse>
    where
        F: FnOnce(AuthRequest, Arc<AuthContext<S>>) -> Fut + Send,
        Fut: Future<Output = AuthResult<AuthResponse>> + Send,
    {
        self.with_native_context(source, |context| async move {
            let dispatcher = context
                .extensions
                .get::<Arc<EndpointDispatcher<S>>>()
                .ok_or_else(|| AuthError::config("Endpoint dispatcher is not initialized"))?;
            dispatcher
                .native(request, route, &context, |request| {
                    handler(request, context.clone())
                })
                .await
        })
        .await
    }
}

fn native_request(source: crate::NativeRequest<'_>, route: &AuthRoute) -> AuthRequest {
    let method = source
        .request
        .map_or_else(|| route.method.clone(), |request| request.method.clone());
    let mut request = AuthRequest::new(method, "/").with_optional_headers(source.headers.cloned());
    if let Some(original) = source.request {
        request = request.with_original_request(original.clone());
    }
    request
}
