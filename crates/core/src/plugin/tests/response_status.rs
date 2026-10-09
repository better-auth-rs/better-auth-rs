#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired status contracts compare complete pinned observations and private event locks"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    HttpMethod, NativeResponseStatus,
    endpoint_dispatch::EndpointDispatcher,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema as S},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Output {
    Json,
    Response,
    ReturnError,
    ThrowError,
}

fn returned(kind: Output, phase: &str, error_status: u16) -> AuthResult<AuthResponse> {
    match kind {
        Output::Json => AuthResponse::json(None, &json!({"phase":phase})),
        Output::Response => Ok(AuthResponse::text(207, phase)),
        Output::ReturnError | Output::ThrowError => {
            let error = AuthResponse::json(
                error_status,
                &json!({"code":"STATUS_ERROR", "message":phase}),
            )?
            .into_api_error();
            if kind == Output::ThrowError {
                Err(error.into())
            } else {
                Ok(error)
            }
        }
    }
}

fn observation(response: &AuthResponse) -> AuthResult<Value> {
    if let Some(status) = response.api_error_status() {
        Ok(json!({"kind":"error", "status":status, "body":response.body.json()?}))
    } else if response.is_json() {
        Ok(json!({"kind":"json", "body":response.body.json()?}))
    } else {
        Ok(
            json!({"kind":"response", "status":response.status, "body":String::from_utf8(response.body.bytes()?.into_owned()).unwrap()}),
        )
    }
}

fn expected_observation(kind: Output, phase: &str, error_status: u16) -> Value {
    match kind {
        Output::Json => json!({"kind":"json", "body":{"phase":phase}}),
        Output::Response => json!({"kind":"response", "status":207, "body":phase}),
        Output::ReturnError | Output::ThrowError => {
            json!({"kind":"error", "status":error_status, "body":{"code":"STATUS_ERROR", "message":phase}})
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    before: Option<Output>,
    endpoint: Output,
    status: Option<u16>,
    after: Option<Output>,
    native: NativeResponseStatus,
    http: u16,
}

#[derive(Clone)]
struct Hooks {
    case: Case,
    events: Arc<Mutex<Vec<Value>>>,
    retained_before: Arc<Mutex<Option<AuthRequest>>>,
}

#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        request.set_response_status(202)?;
        *self.retained_before.lock().unwrap() = Some(request.clone());
        self.case
            .before
            .map(|kind| returned(kind, "before", 418).map(BeforeRequestAction::Respond))
            .transpose()
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push(observation(response)?);
        request.set_response_status(203)?;
        if let Some(kind) = self.case.after {
            response.replace_returned(returned(kind, "after", 409)?);
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Hooks {
    fn name(&self) -> &'static str {
        "response-status-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push(observation(response)?);
        request.set_response_status(206)?;
        Ok(())
    }
}

#[tokio::test]
async fn native_status_tracks_endpoint_provenance_across_hook_replacements() -> AuthResult<()> {
    use NativeResponseStatus::{Absent, Undefined, Value as Status};
    use Output::{Json, Response, ReturnError, ThrowError};
    let cases = [
        ("default-json", None, Json, None, None, Undefined, 200),
        (
            "set-200-json",
            None,
            Json,
            Some(200),
            None,
            Status(200),
            200,
        ),
        (
            "set-201-json",
            None,
            Json,
            Some(201),
            None,
            Status(201),
            201,
        ),
        (
            "default-response",
            None,
            Response,
            None,
            None,
            Undefined,
            207,
        ),
        (
            "set-response",
            None,
            Response,
            Some(201),
            None,
            Status(201),
            207,
        ),
        (
            "throw-error",
            None,
            ThrowError,
            None,
            None,
            Status(400),
            400,
        ),
        (
            "set-throw-error",
            None,
            ThrowError,
            Some(201),
            None,
            Status(400),
            400,
        ),
        (
            "return-error",
            None,
            ReturnError,
            None,
            None,
            Undefined,
            400,
        ),
        (
            "set-return-error",
            None,
            ReturnError,
            Some(201),
            None,
            Status(201),
            201,
        ),
        (
            "replace-json",
            None,
            Json,
            Some(201),
            Some(Json),
            Status(201),
            201,
        ),
        (
            "replace-response",
            None,
            Json,
            Some(201),
            Some(Response),
            Status(201),
            207,
        ),
        (
            "replace-return-error",
            None,
            Json,
            Some(201),
            Some(ReturnError),
            Status(201),
            201,
        ),
        (
            "replace-throw-error",
            None,
            Json,
            Some(201),
            Some(ThrowError),
            Status(201),
            201,
        ),
        (
            "error-to-json",
            None,
            ThrowError,
            None,
            Some(Json),
            Status(400),
            400,
        ),
        (
            "error-to-response",
            None,
            ThrowError,
            None,
            Some(Response),
            Status(400),
            207,
        ),
        (
            "error-to-error",
            None,
            ThrowError,
            None,
            Some(ThrowError),
            Status(400),
            400,
        ),
        (
            "response-to-json",
            None,
            Response,
            None,
            Some(Json),
            Undefined,
            200,
        ),
        (
            "default-to-error",
            None,
            Json,
            None,
            Some(ThrowError),
            Undefined,
            409,
        ),
        (
            "returned-error-to-json",
            None,
            ReturnError,
            None,
            Some(Json),
            Undefined,
            200,
        ),
        (
            "before-json",
            Some(Json),
            Json,
            Some(201),
            None,
            Absent,
            200,
        ),
        (
            "before-response",
            Some(Response),
            Json,
            Some(201),
            None,
            Absent,
            207,
        ),
        (
            "before-return-error",
            Some(ReturnError),
            Json,
            Some(201),
            None,
            Absent,
            418,
        ),
        (
            "before-throw-error",
            Some(ThrowError),
            Json,
            Some(201),
            None,
            Absent,
            418,
        ),
    ];
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    for (name, before, endpoint, status, after, native, expected_http) in cases {
        let case = Case {
            name,
            before,
            endpoint,
            status,
            after,
            native,
            http: expected_http,
        };
        for http in [false, true] {
            let hooks = Hooks {
                case,
                events: Default::default(),
                retained_before: Default::default(),
            };
            let route = AuthRoute::get("/status-contract", "statusContract");
            let dispatcher = EndpointDispatcher::new(
                Arc::new(vec![Box::new(hooks.clone()) as Box<dyn AuthPlugin<S>>]),
                EndpointHooks {
                    before: Some(Arc::new(hooks.clone())),
                    after: Some(Arc::new(hooks.clone())),
                },
                [route.clone()],
            );
            let mut request = AuthRequest::new(HttpMethod::Get, "/status-contract");
            let retained_before = hooks.retained_before.clone();
            let handler = move |request: AuthRequest| async move {
                if let Some(status) = case.status {
                    request.set_response_status(status)?;
                }
                retained_before
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .set_response_status(205)?;
                returned(case.endpoint, "endpoint", 400)
            };
            let result = if http {
                dispatcher
                    .run(&mut request, true, &context, None, handler)
                    .await
            } else {
                dispatcher.native(request, route, &context, handler).await
            };
            let final_kind = case.before.or(case.after).unwrap_or(case.endpoint);
            let error = matches!(final_kind, ReturnError | ThrowError);
            let should_throw =
                case.before == Some(ThrowError) || (!http && case.before.is_none() && error);
            assert_eq!(result.is_err(), should_throw, "{} HTTP={http}", case.name);
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    let error_status = if case.before.is_some() {
                        418
                    } else if case.after.is_some() {
                        409
                    } else {
                        400
                    };
                    assert_eq!(
                        error.status_code(),
                        error_status,
                        "{} native APIError",
                        case.name
                    );
                    error.to_auth_response()
                }
            };
            assert_eq!(
                response.status, case.http,
                "{} effective HTTP status",
                case.name
            );
            if case.before != Some(ThrowError) {
                assert_eq!(
                    response.native_status(),
                    case.native,
                    "{} native status",
                    case.name
                );
            }
            let phase = if case.before.is_some() {
                "before"
            } else if case.after.is_some() {
                "after"
            } else {
                "endpoint"
            };
            if final_kind == Response {
                assert_eq!(response.body.bytes()?.as_ref(), phase.as_bytes());
            } else {
                let expected_body = if error {
                    json!({"code":"STATUS_ERROR", "message":phase})
                } else {
                    json!({"phase":phase})
                };
                assert_eq!(
                    response.body.json()?,
                    Some(expected_body),
                    "{} body",
                    case.name
                );
            }
            let expected_events = if case.before.is_some() {
                Vec::new()
            } else {
                vec![
                    expected_observation(case.endpoint, "endpoint", 400),
                    expected_observation(
                        final_kind,
                        phase,
                        if case.after.is_some() { 409 } else { 400 },
                    ),
                ]
            };
            assert_eq!(
                *hooks.events.lock().unwrap(),
                expected_events,
                "{} hooks",
                case.name
            );
        }
    }
    Ok(())
}
