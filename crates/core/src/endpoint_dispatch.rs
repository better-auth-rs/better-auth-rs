//! Shared endpoint hooks, validation, handler and response lifecycle.
use crate::hooks::{
    RequestHookContext, update_request_hook_context, upstream_route_path,
    with_request_hook_context_value,
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
        F: FnOnce(AuthRequest, Arc<AuthContext<S>>) -> Fut,
        Fut: Future<Output = AuthResult<AuthResponse>>,
    {
        let route_path = if route.server_only {
            "/:virtual".into()
        } else {
            upstream_route_path(&route.path)
        };
        if route.server_only {
            request.path = "/".into();
            request.set_server_only();
        } else {
            request.path = route_path.clone();
        }
        let mut scope = RequestHookContext::from_request(&request)?;
        scope.path = (!route.server_only).then(|| route_path.clone());
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
        let name = format!("{method} {route_path}");
        let operation_id = route.operation_id.clone();
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
        F: FnOnce(AuthRequest, Arc<AuthContext<S>>) -> Fut,
        Fut: Future<Output = AuthResult<AuthResponse>>,
    {
        context
            .with_endpoint_context(|context| async move {
                let handler_context = context.clone();
                self.run_in_context(req, http, &context, native_route, |request| {
                    handler(request, handler_context)
                })
                .await
            })
            .await
    }

    async fn run_in_context<F, Fut>(
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
            let mut r = req.with_separate_response_headers();
            r.path = stripped_path.to_string();
            r
        } else {
            req.with_separate_response_headers()
        };
        internal_req.set_endpoint_body(internal_req.unvalidated_input()?);
        internal_req.set_endpoint_query(internal_req.unvalidated_query()?);
        update_request_hook_context(&internal_req)?;

        let mut input_patch = crate::endpoint_input::EndpointInputPatch::default();
        if let Some(hook) = &self.hooks.before {
            let hook_request = internal_req.with_separate_response_headers();
            let action = match crate::observability::instrumentation::with_endpoint_hook(
                &context.config,
                &hook_request,
                "before",
                "user",
                hook.before(&hook_request, context),
            )
            .await
            {
                Ok(action) => action,
                Err(error) => return Err(before_error(error, &hook_request, context)?),
            };
            merge_before_headers(&internal_req, &hook_request)?;
            if let Some(response) =
                apply_before_action(action, &mut internal_req, req, &mut input_patch, http)?
            {
                return if http {
                    response.into_http_response()
                } else {
                    Ok(response)
                };
            }
        }

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        // Plugins now see the normalised (base_path-stripped) path.
        for plugin in self.plugins.iter() {
            let hook_request = internal_req.with_separate_response_headers();
            let action = match plugin.before_request(&hook_request, context).await {
                Ok(action) => action,
                Err(error) => return Err(before_error(error, &hook_request, context)?),
            };
            merge_before_headers(&internal_req, &hook_request)?;
            if let Some(response) =
                apply_before_action(action, &mut internal_req, req, &mut input_patch, http)?
            {
                return if http {
                    response.into_http_response()
                } else {
                    Ok(response)
                };
            }
        }

        // The endpoint owns a fresh accumulator; before-hook headers survive only a short circuit.
        internal_req = internal_req.with_separate_response_headers();
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
                    let query = match route
                        .as_ref()
                        .and_then(|route| route.query_validator.as_ref())
                    {
                        Some(validate) => validate.validate(&internal_req).await?,
                        None => internal_req.unvalidated_query()?,
                    };
                    if route.as_ref().is_some_and(|route| route.require_headers)
                        && internal_req.endpoint_headers().is_none()
                    {
                        return Err(AuthError::RequestValidation {
                            message: "Headers is required".into(),
                        });
                    }
                    let mut request = internal_req.clone();
                    request.set_endpoint_body(body);
                    request.set_endpoint_query(query);
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
                            request.input_query_field_value()?,
                            handler(request.clone()),
                        );
                        let result = if request.is_server_only() {
                            let mut scope = match crate::hooks::current_request_hook_context() {
                                Some(scope) => scope,
                                None => RequestHookContext::from_request(&request)?,
                            };
                            scope.path = Some("virtual:".into());
                            scope.request = request.clone();
                            scope.query = request.input_query_field_value()?;
                            scope.body = request.input_field_value()?;
                            scope.operation_id =
                                route.as_ref().map(|route| route.operation_id.clone());
                            with_request_hook_context_value(scope, future).await
                        } else {
                            future.await
                        };
                        match result {
                            Ok(response) => Ok(response),
                            Err(error) => {
                                let error = endpoint_error(error, &request)?;
                                // Better Call's endpoint catch classifies again before the dispatch catch.
                                let _ = error.is_api_error()?;
                                Err(error)
                            }
                        }
                    }
                    Err(error) => Err(error),
                }
            },
        )
        .await;
        let endpoint_status = internal_req.response_status()?;
        let mut response = match result {
            Ok(mut response) => {
                response.initialize_endpoint_headers(internal_req.snapshot_response_headers()?);
                let status = endpoint_status.map_or(
                    response.native_status(),
                    crate::NativeResponseStatus::Present,
                );
                response.set_native_status(status);
                response
            }
            Err(error) if error.is_api_error()? => {
                let status = error.status_code()?;
                let headers = merge_api_error_headers(&error)?;
                let mut response = error.to_auth_response()?;
                response.set_endpoint_headers(headers);
                response.set_native_status(crate::NativeResponseStatus::Present(status));
                response
            }
            Err(error) => return Err(error),
        };
        let native_status = response.native_status();
        context
            .session_manager()
            .finish_response_policy(&internal_req, &mut response)?;
        if let Some(hook) = &self.hooks.after {
            let hook_request = internal_req.with_separate_response_headers();
            let result = crate::observability::instrumentation::with_endpoint_hook(
                &context.config,
                &hook_request,
                "after",
                "user",
                hook.after(&hook_request, &mut response, context),
            )
            .await;
            apply_after_result(result, &hook_request, &mut response, context)?;
            response.set_native_status(native_status.clone());
        }
        for plugin in self.plugins.iter() {
            let hook_request = internal_req.with_separate_response_headers();
            let result = plugin
                .after_request(&hook_request, &mut response, context)
                .await;
            apply_after_result(result, &hook_request, &mut response, context)?;
            response.set_native_status(native_status.clone());
        }
        if response.is_api_error()? && publishes_debug(context) {
            restore_error_stack(&response.body.field_value()?)?;
        }
        if response.is_api_error()? && !http {
            let captured = response.endpoint_headers_value();
            if captured.is_truthy() {
                response.capture_native_error_headers(captured);
            }
            Err(AuthError::from_returned_response(response)?)
        } else if http {
            response.into_http_response()
        } else {
            Ok(response)
        }
    }
}
pub(crate) fn endpoint_error(error: AuthError, request: &AuthRequest) -> AuthResult<AuthError> {
    if !error.is_api_error()? {
        return Ok(error);
    }
    Ok(error.capture_native_headers(request.response_headers_value()?))
}

fn merge_before_headers(internal: &AuthRequest, hook: &AuthRequest) -> AuthResult<()> {
    for (name, value) in hook.snapshot_response_headers()? {
        if name.eq_ignore_ascii_case("set-cookie") {
            internal.append_response_header(&name, value)?;
        } else {
            internal.set_response_header(&name, value)?;
        }
    }
    Ok(())
}

fn apply_before_action(
    action: Option<BeforeRequestAction>,
    internal: &mut AuthRequest,
    original: &mut AuthRequest,
    input_patch: &mut crate::endpoint_input::EndpointInputPatch,
    http: bool,
) -> AuthResult<Option<AuthResponse>> {
    match action {
        Some(BeforeRequestAction::Respond(mut response)) => {
            response.prepare_before_return(http);
            if !response.stops_before_hooks() {
                for (name, value) in response.headers {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        internal.append_response_header(&name, value)?;
                    } else {
                        internal.set_response_header(&name, value)?;
                    }
                }
                return Ok(None);
            }
            response.set_native_status(crate::NativeResponseStatus::Absent);
            response.merge_endpoint_headers(internal.snapshot_response_headers()?);
            return Ok(Some(response));
        }
        Some(BeforeRequestAction::MergeContext(patch)) => input_patch.merge(patch)?,
        Some(BeforeRequestAction::ReplaceBody(body)) => {
            internal.body = Some(body.clone());
            original.body = Some(body);
            internal.set_endpoint_body(internal.unvalidated_input()?);
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
fn publishes_debug<S: AuthSchema>(context: &AuthContext<S>) -> bool {
    context
        .logger()
        .publishes(crate::observability::LogLevel::Debug)
}

fn restore_error_stack(value: &crate::FieldValue) -> AuthResult<()> {
    if let Some(object) = value.as_object() {
        let stack = object.get("errorStack")?.unwrap_or_default();
        object.set("stack", stack)?;
    }
    Ok(())
}

fn before_error<S: AuthSchema>(
    error: AuthError,
    request: &AuthRequest,
    context: &AuthContext<S>,
) -> AuthResult<AuthError> {
    let error = match request.take_hook_error_stage() {
        crate::types::HookErrorStage::Matcher => return Ok(error),
        crate::types::HookErrorStage::Handler => error,
        crate::types::HookErrorStage::Unhandled => endpoint_error(error, request)?,
    };
    if error.is_api_error()?
        && publishes_debug(context)
        && let Some(value) = error.raw_value()
    {
        restore_error_stack(value)?;
    }
    Ok(error)
}

fn merge_api_error_headers(error: &AuthError) -> AuthResult<Option<crate::Headers>> {
    let captured = error.captured_headers_value().unwrap_or_default();
    let explicit =
        if error.headers_value()?.is_truthy() && !error.headers_value()?.strict_equals(&captured) {
            Some(crate::Headers::from_field_value(&error.headers_value()?)?)
        } else {
            None
        };
    if !captured.is_truthy() && explicit.is_none() {
        return Ok(None);
    }
    let mut headers = crate::Headers::new();
    if captured.is_truthy() {
        for (name, value) in crate::Headers::from_field_value(&captured)? {
            headers.append(name, value);
        }
    }
    if let Some(explicit) = explicit {
        headers.merge(explicit);
    }
    Ok(Some(headers))
}

fn apply_after_result<S: AuthSchema>(
    result: AuthResult<()>,
    request: &AuthRequest,
    response: &mut AuthResponse,
    context: &AuthContext<S>,
) -> AuthResult<()> {
    match result {
        Ok(()) => response.merge_endpoint_headers(request.snapshot_response_headers()?),
        Err(error) => {
            let error = match request.take_hook_error_stage() {
                crate::types::HookErrorStage::Unhandled => endpoint_error(error, request)?,
                crate::types::HookErrorStage::Handler | crate::types::HookErrorStage::Matcher => {
                    error
                }
            };
            if !error.is_api_error()? {
                return Err(error);
            }
            if publishes_debug(context)
                && let Some(value) = error.raw_value()
            {
                restore_error_stack(value)?;
            }
            let headers = merge_api_error_headers(&error)?;
            let mut returned = error.to_auth_response()?;
            returned.set_endpoint_headers(headers);
            response.replace_returned(returned);
        }
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
        query: crate::FieldValue,
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
        request.set_endpoint_query(crate::endpoint_input::ValidatedInput::unvalidated_native(
            query,
        ));
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
            dispatcher.native(request, route, &context, handler).await
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

#[cfg(test)]
mod logger_tests {
    use super::*;
    use crate::{
        ApiErrorInit, AuthConfig, FieldMap, FieldValue,
        store::{EphemeralStore, StatelessSchema},
    };

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The dispatch contract asserts original error identity and stack publication across hook phases."
    )]
    fn hook_errors_publish_stacks_for_unknown_levels_even_when_logging_is_disabled()
    -> AuthResult<()> {
        for (level, publishes) in [
            (FieldValue::from("debug"), true),
            (FieldValue::from("unknown"), true),
            (FieldValue::from(false), true),
            (FieldValue::from(FieldMap::new()), true),
            (FieldValue::from("info"), false),
            (FieldValue::from("warn"), false),
        ] {
            for disabled in [false, true] {
                let config = Arc::new(AuthConfig {
                    logger: crate::FieldObject::from(FieldMap::from([
                        ("level".into(), level.clone()),
                        ("disabled".into(), disabled.into()),
                    ]))
                    .into(),
                    ..Default::default()
                });
                let context = AuthContext::<StatelessSchema>::new(
                    config.clone(),
                    Arc::new(EphemeralStore::new(config)),
                )?;
                for after in [false, true] {
                    let error = AuthError::try_api_error(ApiErrorInit {
                        status: "BAD_REQUEST".into(),
                        ..Default::default()
                    })?;
                    let raw = error.raw_value().cloned().ok_or_else(|| {
                        AuthError::internal("Hook error must retain its native value")
                    })?;
                    let object = raw
                        .as_object()
                        .ok_or_else(|| AuthError::internal("Hook error must be an object"))?;
                    let original_stack: FieldValue =
                        FieldMap::from([("stack".into(), "original".into())]).into();
                    object.set("stack", "hidden".into())?;
                    object.set("errorStack", original_stack.clone())?;
                    let request = AuthRequest::new(HttpMethod::Get, "/hook-error");
                    let retained = if after {
                        let mut response = AuthResponse::new(200);
                        apply_after_result(Err(error), &request, &mut response, &context)?;
                        response.body.field_value()?
                    } else {
                        before_error(error, &request, &context)?.into_thrown_value()?
                    };
                    assert!(retained.strict_equals(&raw));
                    let stack = raw.model_property("stack")?;
                    if publishes {
                        assert!(stack.strict_equals(&original_stack));
                    } else {
                        assert_eq!(stack, "hidden".into());
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "endpoint_dispatch/phase_ownership_tests.rs"]
mod phase_ownership_tests;
