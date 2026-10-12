//! Router catch and response-hook contracts paired with contracts/http-json-router.mjs.

use async_trait::async_trait;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, BeforeRequestAction,
    FieldFunction, FieldMap, FieldValue, HttpMethod, ResponseBody,
    api_error::{ApiErrorHandler, ApiErrorTask},
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::StatelessSchema as S,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const ORIGIN: &str = "http://http-json-router.test";
const PATH: &str = "/http-json-router";

#[derive(Default)]
struct Trace {
    events: Mutex<Vec<&'static str>>,
    error_allocation: AtomicUsize,
    error_callbacks: AtomicUsize,
}

impl Trace {
    fn push(&self, event: &'static str) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Router trace lock poisoned"))?
            .push(event);
        Ok(())
    }

    fn events(&self) -> AuthResult<Vec<&'static str>> {
        Ok(self
            .events
            .lock()
            .map_err(|_| AuthError::internal("Router trace lock poisoned"))?
            .clone())
    }
}

#[derive(Clone)]
struct Contract {
    phase: &'static str,
    specimen: &'static str,
    value: FieldValue,
    trace: Arc<Trace>,
}

impl Contract {
    fn new(phase: &'static str, specimen: &'static str) -> AuthResult<Self> {
        let trace = Arc::new(Trace::default());
        let value: FieldValue = if specimen == "cycle" {
            let value: FieldValue = FieldMap::new().into();
            let fields = value
                .as_object()
                .ok_or_else(|| AuthError::internal("Missing cycle object"))?;
            fields.set("self", value.clone())?;
            value
        } else {
            let observed = trace.clone();
            FieldMap::from([(
                "toJSON".into(),
                FieldFunction::contextual(move |_, arguments| {
                    assert_eq!(arguments.len(), 1);
                    assert_eq!(arguments.first().and_then(FieldValue::as_str), Some(""));
                    observed.push("serialize")?;
                    if specimen == "method-error" {
                        let message = "original HTTP JSON router method error".to_owned();
                        observed
                            .error_allocation
                            .store(message.as_ptr() as usize, Ordering::SeqCst);
                        Err(AuthError::Internal(message))
                    } else {
                        Ok(FieldValue::Undefined)
                    }
                })
                .into(),
            )])
            .into()
        };
        Ok(Self {
            phase,
            specimen,
            value,
            trace,
        })
    }

    fn before(&self) -> bool {
        self.phase.starts_with("before")
    }

    fn failed(&self) -> bool {
        self.specimen == "method-error" || self.phase == "before-json" && self.specimen == "cycle"
    }

    fn response(&self) -> AuthResponse {
        if self.phase == "before-raw" {
            AuthResponse::native(None, self.value.clone())
        } else {
            AuthResponse::json_value(None, self.value.clone())
        }
    }

    fn assert_http(&self, response: &AuthResponse) -> AuthResult<()> {
        assert!(!response.is_native());
        let failed = self.failed();
        assert_eq!(
            response.status,
            if failed {
                500
            } else if self.before() {
                200
            } else {
                201
            }
        );
        assert_eq!(
            matches!(response.body, ResponseBody::Empty),
            failed || self.specimen == "omitted"
        );
        assert_eq!(
            response.body.bytes()?.as_ref(),
            if failed || self.specimen == "omitted" {
                b"".as_slice()
            } else {
                br#"{"self":"[Circular ref-0]"}"#.as_slice()
            }
        );
        let headers: &[(&str, &str)] = if failed {
            &[]
        } else if self.before() {
            &[("content-type", "application/json"), ("x-before", "1")]
        } else {
            &[
                ("content-type", "application/json"),
                ("x-endpoint", "1"),
                ("x-after", "1"),
            ]
        };
        assert_eq!(response.headers.iter().count(), headers.len());
        for (name, value) in headers {
            assert_eq!(
                response.headers.get(name).map(String::as_str),
                Some(*value),
                "{name}"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Contract {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.trace.push("before")?;
        request.set_response_header("x-before", "1")?;
        Ok(self
            .before()
            .then(|| BeforeRequestAction::Respond(self.response())))
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Contract {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.trace.push("after")?;
        request.set_response_header("x-after", "1")?;
        let value = response.body.field_value()?;
        if self.phase == "endpoint" {
            assert!(value.strict_equals(&self.value));
        } else {
            assert_eq!(value.json()?, Some(serde_json::json!({"endpoint": true})));
            response.replace_returned(self.response());
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Contract {
    fn name(&self) -> &'static str {
        "http-json-router"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get(PATH, "httpJsonRouter")]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.path() != PATH {
            return Ok(None);
        }
        self.trace.push("endpoint")?;
        request.set_response_status(201)?;
        request.set_response_header("x-endpoint", "1")?;
        Ok(Some(if self.phase == "endpoint" {
            self.response()
        } else {
            AuthResponse::json_value(
                None,
                FieldMap::from([("endpoint".into(), true.into())]).into(),
            )
        }))
    }

    async fn after_request(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.trace.push("plugin-after")?;
        assert!(response.body.field_value()?.strict_equals(&self.value));
        Ok(())
    }

    async fn on_http_response(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.trace.push("on-response")?;
        self.assert_http(response)?;
        Ok(None)
    }
}

impl ApiErrorHandler<S> for Contract {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        self.trace.push("on-error")?;
        let _ = self.trace.error_callbacks.fetch_add(1, Ordering::SeqCst);
        assert!(!error.is_api_error()?);
        if self.specimen == "method-error" {
            assert!(matches!(error, AuthError::Internal(message)
                if message == "original HTTP JSON router method error"
                && message.as_ptr() as usize == self.trace.error_allocation.load(Ordering::SeqCst)));
        } else {
            assert!(matches!(error, AuthError::TypeError(_)));
        }
        Ok(None)
    }
}

#[tokio::test]
async fn http_json_router_preserves_catch_headers_and_response_hook_order() -> AuthResult<()> {
    for phase in ["before-raw", "before-json", "endpoint", "after-json"] {
        for specimen in ["cycle", "method-error", "omitted"] {
            let contract = Contract::new(phase, specimen)?;
            let mut config = AuthConfig::new("http-json-router-contract-at-least-32-characters")
                .base_url(ORIGIN);
            config.logger = better_auth_core::LoggerConfig {
                disabled: Some(true),
                ..Default::default()
            }
            .into();
            let auth = BetterAuth::stateless(config)
                .hooks(EndpointHooks {
                    before: Some(Arc::new(contract.clone())),
                    after: Some(Arc::new(contract.clone())),
                })
                .plugin(contract.clone())
                .on_api_error(Arc::new(contract.clone()))
                .build()
                .await?;
            let request = AuthRequest::new(HttpMethod::Get, "/api/auth/http-json-router").with_url(
                format!("{ORIGIN}/api/auth/http-json-router")
                    .parse()
                    .map_err(|error| {
                        AuthError::config(format!("Invalid router fixture URL: {error}"))
                    })?,
            );
            let response = auth.handle_request(request).await?;
            contract.assert_http(&response)?;
            let mut events = vec!["before"];
            if !contract.before() {
                events.extend(["endpoint", "after", "plugin-after"]);
            }
            if specimen != "cycle" {
                events.push("serialize");
            }
            if contract.failed() {
                events.push("on-error");
            }
            events.push("on-response");
            assert_eq!(contract.trace.events()?, events, "{phase}/{specimen}");
            assert_eq!(
                contract.trace.error_callbacks.load(Ordering::SeqCst),
                usize::from(contract.failed())
            );
            if specimen == "cycle" {
                let _ = contract
                    .value
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Missing cycle object"))?
                    .delete("self")?;
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct RawBeforeError {
    value: FieldValue,
    trace: Arc<Trace>,
}

#[async_trait]
impl BeforeEndpointHook<S> for RawBeforeError {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.trace.push("before")?;
        request.set_response_header("x-before", "1")?;
        request.append_response_header("set-cookie", "context=1".into())?;
        Err(AuthError::from_thrown(self.value.clone()))
    }
}

impl ApiErrorHandler<S> for RawBeforeError {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        self.trace.push("on-error")?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&self.value))
        );
        let captured = better_auth_core::Headers::from_field_value(
            &error
                .captured_headers_value()
                .ok_or_else(|| AuthError::internal("Missing captured headers"))?,
        )?;
        assert_eq!(captured.iter().count(), 2);
        assert_eq!(captured.get("x-before").map(String::as_str), Some("1"));
        assert_eq!(
            captured.get("set-cookie").map(String::as_str),
            Some("context=1")
        );
        Ok(None)
    }
}

#[tokio::test]
async fn structural_api_error_reaches_router_callback_without_losing_owned_headers()
-> AuthResult<()> {
    let contract = RawBeforeError {
        value: FieldMap::from([
            ("name".into(), "APIError".into()),
            ("status".into(), "BAD_REQUEST".into()),
            ("statusCode".into(), 418.0.into()),
            (
                "body".into(),
                FieldMap::from([
                    ("code".into(), "RAW_API_ERROR".into()),
                    ("message".into(), "raw failure".into()),
                ])
                .into(),
            ),
            (
                "headers".into(),
                FieldMap::from([
                    ("x-owned".into(), "1".into()),
                    ("set-cookie".into(), "owned=1".into()),
                ])
                .into(),
            ),
        ])
        .into(),
        trace: Arc::new(Trace::default()),
    };
    let mut config = AuthConfig::new("raw-router-contract-at-least-32-characters").base_url(ORIGIN);
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.experimental.instrumentation.enabled = false;
    let auth = BetterAuth::stateless(config)
        .hooks(EndpointHooks {
            before: Some(Arc::new(contract.clone())),
            after: None,
        })
        .on_api_error(Arc::new(contract.clone()))
        .build()
        .await?;
    let response = auth
        .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
        .await?;
    assert_eq!(contract.trace.events()?, ["before", "on-error"]);
    assert_eq!(response.status, 418);
    assert_eq!(response.status_text, "BAD_REQUEST".into());
    assert_eq!(response.headers.iter().count(), 3);
    for (name, value) in [
        ("content-type", "application/json"),
        ("x-owned", "1"),
        ("set-cookie", "owned=1"),
    ] {
        assert_eq!(response.headers.get(name).map(String::as_str), Some(value));
    }
    assert_eq!(
        response.body.bytes()?.as_ref(),
        br#"{"code":"RAW_API_ERROR","message":"raw failure"}"#
    );
    Ok(())
}
