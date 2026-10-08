#![allow(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "tracing callbacks cannot return capture failures; Result tests propagate setup errors and assert observable contracts"
)]
use better_auth::config::{FieldTransforms, UserFieldTransform};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::__private_core::store::{
    StatelessSchema,
    database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
};
use better_auth::__private_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, BeforeRequestAction, HttpMethod,
};
use better_auth::observability::{
    AfterEndpointHook, BeforeEndpointHook, EndpointHooks, LogArgument, LogLevel, LogSink,
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, database_hooks};
use serde_json::{Map, Value, json};
use tracing::Instrument;
use tracing::{
    Id, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

type S = StatelessSchema;

#[derive(Clone)]
struct InputProjection {
    invalid: bool,
    events: Arc<Mutex<Vec<Value>>>,
}

impl InputProjection {
    fn record(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("projection capture poisoned"))?
            .push(json!([phase, request.input_body()?]));
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for InputProjection {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("user-before", request)?;
        Ok(Some(BeforeRequestAction::MergeContext(
            better_auth::__private_core::endpoint_input::EndpointInputPatch {
                body: Some(
                    json!({"value": if self.invalid { json!(7) } else { json!("user") }, "user": true}),
                ),
                ..Default::default()
            },
        )))
    }
}

#[async_trait]
impl AfterEndpointHook<S> for InputProjection {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("user-after", request)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ProjectionBody {
    value: String,
    user: bool,
    plugin: bool,
}

fn projection_body(
    request: &AuthRequest,
) -> AuthResult<better_auth::__private_core::endpoint_input::ValidatedBody> {
    let parsed: ProjectionBody =
        serde_json::from_value(request.input_body()?.unwrap_or(Value::Null))
            .map_err(|error| AuthError::bad_request(error.to_string()))?;
    Ok(
        better_auth::__private_core::endpoint_input::ValidatedBody::new(
            Some(serde_json::to_value(&parsed)?),
            parsed,
        ),
    )
}

#[async_trait]
impl AuthPlugin<S> for InputProjection {
    fn name(&self) -> &'static str {
        "projection"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/projection", "projection").body_validator(projection_body)]
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("plugin-before", request)?;
        Ok(Some(BeforeRequestAction::MergeContext(
            better_auth::__private_core::endpoint_input::EndpointInputPatch {
                body: Some(json!({"plugin": true})),
                ..Default::default()
            },
        )))
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.record("handler", request)?;
        Ok(Some(AuthResponse::json(200, &request.input_body()?)?))
    }
}

#[tokio::test]
async fn global_input_patches_are_deferred_and_schema_errors_are_traced() -> AuthResult<()> {
    for invalid in [false, true] {
        let projection = InputProjection {
            invalid,
            events: Arc::default(),
        };
        let auth = BetterAuth::stateless(config())
            .hooks(EndpointHooks {
                before: Some(Arc::new(projection.clone())),
                after: Some(Arc::new(projection.clone())),
            })
            .plugin(projection.clone())
            .build()
            .await?;
        let capture = Capture::default();
        let raw = json!({"value":"raw", "extra":true});
        let result = auth
            .call_endpoint(
                HttpMethod::Post,
                "/projection",
                better_auth::server_api::EndpointInput {
                    body: Some(raw.clone()),
                    ..Default::default()
                },
            )
            .instrument(capture.span())
            .await;
        let mut expected = vec![json!(["user-before", raw]), json!(["plugin-before", raw])];
        if invalid {
            assert_eq!(
                result
                    .expect_err("invalid schema input must fail")
                    .to_auth_response()
                    .status,
                400
            );
        } else {
            assert_eq!(result?.status, 200);
            expected.push(json!(["handler", {"value":"user", "user":true, "plugin":true}]));
        }
        expected.push(json!(["user-after", {"value":if invalid {json!(7)} else {json!("user")}, "extra":true, "user":true, "plugin":true}]));
        assert_eq!(
            *projection
                .events
                .lock()
                .map_err(|_| AuthError::internal("projection capture poisoned"))?,
            expected
        );
        let records = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?;
        let handler = records
            .iter()
            .find(|record| record.fields.get("otel.name") == Some(&json!("handler /projection")))
            .expect("validation must run inside the handler span");
        assert_eq!(handler.exceptions.len(), usize::from(invalid));
    }
    Ok(())
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Record>>>, Arc<tokio::sync::Notify>);
#[derive(Clone, Debug, Default)]
struct Record {
    id: u64,
    fields: Map<String, Value>,
    parent: Option<String>,
    exceptions: Vec<String>,
    closed: usize,
}
#[derive(Default)]
struct Fields(Map<String, Value>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = self
            .0
            .insert(field.name().into(), format!("{value:?}").into());
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        let _ = self.0.insert(field.name().into(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        let _ = self.0.insert(field.name().into(), value.into());
    }
}

struct CaptureLayer;
fn init_tracing() {
    static TRACING: std::sync::Once = std::sync::Once::new();
    TRACING.call_once(|| {
        // SQLx drops spans on its worker. Registry closes parents through that
        // thread's default dispatcher, so all test spans must share one registry.
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(CaptureLayer))
            .expect("initialize the test process subscriber once");
    });
}
impl Capture {
    async fn wait_closed(&self) -> AuthResult<()> {
        // SQLx workers can retain spans after delivering query results.
        // A single waiter consumes notify_one's stored permit, including notifications before await.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let all_closed = self
                    .0
                    .lock()
                    .map_err(|_| AuthError::internal("capture poisoned"))?
                    .iter()
                    .all(|record| record.closed > 0);
                if all_closed {
                    return Ok(());
                }
                self.1.notified().await;
            }
        })
        .await
        .map_err(|_| AuthError::internal("Captured spans did not close before timeout"))?
    }

    fn span(&self) -> tracing::Span {
        init_tracing();
        let span = tracing::info_span!(target: "better-auth-test", "capture");
        tracing::dispatcher::get_default(|dispatch| {
            use tracing_subscriber::registry::LookupSpan;
            let registry = dispatch
                .downcast_ref::<tracing_subscriber::Registry>()
                .expect("the test subscriber uses Registry");
            let id = span.id().expect("capture span is enabled");
            registry
                .span(&id)
                .expect("capture span exists")
                .extensions_mut()
                .insert(self.clone());
        });
        span
    }
}
impl<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> Layer<S>
    for CaptureLayer
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("new span exists");
        let Some(parent) = span.parent() else {
            return;
        };
        let Some(capture) = parent.extensions().get::<Capture>().cloned() else {
            return;
        };
        span.extensions_mut().insert(capture.clone());
        if attrs.metadata().target() != "better-auth" {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let mut records = capture.0.lock().expect("capture mutex is not poisoned");
        let parent = records
            .iter()
            .find(|record| record.id == parent.id().into_u64())
            .and_then(|record| record.fields.get("otel.name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        records.push(Record {
            id: id.into_u64(),
            fields: fields.0,
            parent,
            ..Default::default()
        });
    }
    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("recorded span exists");
        let Some(capture) = span.extensions().get::<Capture>().cloned() else {
            return;
        };
        let mut fields = Fields::default();
        values.record(&mut fields);
        if let Some(record) = capture
            .0
            .lock()
            .expect("capture mutex is not poisoned")
            .iter_mut()
            .find(|record| record.id == id.into_u64())
        {
            record.fields.extend(fields.0);
        }
    }
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().name() != "exception" {
            return;
        }
        let Some(span) = ctx.event_span(event) else {
            return;
        };
        let Some(capture) = span.extensions().get::<Capture>().cloned() else {
            return;
        };
        let mut fields = Fields::default();
        event.record(&mut fields);
        if let Some(record) = capture
            .0
            .lock()
            .expect("capture mutex is not poisoned")
            .iter_mut()
            .find(|record| record.id == span.id().into_u64())
            && let Some(message) = fields.0.get("exception.message").and_then(Value::as_str)
        {
            record.exceptions.push(message.into());
        }
    }
    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("closing span exists");
        let Some(capture) = span.extensions().get::<Capture>().cloned() else {
            return;
        };
        {
            if let Some(record) = capture
                .0
                .lock()
                .expect("capture mutex is not poisoned")
                .iter_mut()
                .find(|record| record.id == id.into_u64())
            {
                record.closed += 1;
            }
        }
        capture.1.notify_one();
    }
}
#[derive(Clone, Copy)]
struct UserHooks;
#[async_trait]
impl BeforeEndpointHook<S> for UserHooks {
    async fn before(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(None)
    }
}
#[async_trait]
impl AfterEndpointHook<S> for UserHooks {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        Ok(())
    }
}
struct Probe;
#[async_trait]
impl AuthPlugin<S> for Probe {
    fn name(&self) -> &'static str {
        "observe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/probe", "probe")]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        better_auth::__private_core::observability::instrumentation::with_endpoint_hook(
            &ctx.config,
            req,
            "before",
            "plugin:observe",
            async { Ok(None) },
        )
        .await
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        better_auth::__private_core::observability::instrumentation::with_endpoint_hook(
            &ctx.config,
            req,
            "after",
            "plugin:observe",
            async { Ok(()) },
        )
        .await
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        ctx.config.logger.info(
            "literal %s",
            &[
                LogArgument::Value(&json!({"value":1})),
                LogArgument::Value(&json!("tail")),
            ],
        );
        match request
            .query
            .as_ref()
            .and_then(|query| query.get("kind"))
            .and_then(Value::as_str)
        {
            Some("api") => Err(AuthError::bad_request("api failure")),
            Some("ordinary") => Err(AuthError::internal("ordinary failure")),
            Some("redirect") => Err(AuthError::redirect("/next")),
            _ => Ok(Some(AuthResponse::json(200, &json!({"ok":true}))?)),
        }
    }
}
fn config() -> AuthConfig {
    init_tracing();
    let mut config = AuthConfig::new("observability-reference-secret-more-than-32-characters")
        .base_url("http://observability.test");
    config.logger.disabled = Some(true);
    config
}
async fn build(config: AuthConfig) -> AuthResult<BetterAuth<S>> {
    BetterAuth::stateless(config)
        .hooks(EndpointHooks {
            before: Some(Arc::new(UserHooks)),
            after: Some(Arc::new(UserHooks)),
        })
        .plugin(Probe)
        .build()
        .await
}

// Mirrors the fixed 1.7.6 OTEL oracle, including HTTP/native error classification.
#[tokio::test]
async fn spans_preserve_dispatch_order_parentage_and_original_outcomes() -> AuthResult<()> {
    for native in [false, true] {
        for kind in ["success", "api", "ordinary", "redirect"] {
            let auth = build(config()).await?;
            let capture = Capture::default();
            let capture_span = capture.span();
            let result = async {
                if native {
                    auth.call_endpoint(
                        HttpMethod::Get,
                        "/probe",
                        better_auth::server_api::EndpointInput {
                            query: Some(json!({"kind": kind})),
                            ..Default::default()
                        },
                    )
                    .await
                } else {
                    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/probe");
                    request.query = Some(json!({"kind": kind}));
                    auth.handle_request(request).await
                }
            }
            .instrument(capture_span)
            .await;
            if native {
                assert_eq!(result.is_err(), kind != "success");
            } else {
                assert_eq!(
                    result?.status,
                    match kind {
                        "api" => 400,
                        "ordinary" => 500,
                        "redirect" => 302,
                        _ => 200,
                    }
                );
            }
            capture.wait_closed().await?;
            let records = capture
                .0
                .lock()
                .map_err(|_| AuthError::internal("capture poisoned"))?;
            let names: Vec<_> = records
                .iter()
                .filter_map(|record| record.fields.get("otel.name").and_then(Value::as_str))
                .collect();
            let mut expected = vec![
                "GET /probe",
                "hook before /probe user",
                "hook before /probe plugin:observe",
                "handler /probe",
            ];
            if kind != "ordinary" {
                expected.extend(["hook after /probe user", "hook after /probe plugin:observe"]);
            }
            assert_eq!(names, expected, "{native} {kind}");
            for record in records.iter() {
                assert_eq!(record.closed, 1);
                assert_eq!(
                    record.fields.get("otel.scope.name"),
                    Some(&json!("better-auth"))
                );
                assert_eq!(
                    record.fields.get("otel.scope.version"),
                    Some(&json!("1.7.6"))
                );
            }
            let handler = records
                .iter()
                .find(|record| record.fields.get("otel.name") == Some(&json!("handler /probe")))
                .ok_or_else(|| AuthError::internal("missing handler span"))?;
            assert_eq!(handler.parent.as_deref(), Some("GET /probe"));
            assert_eq!(
                handler.exceptions.len(),
                usize::from(kind == "api" || kind == "ordinary")
            );
            if kind == "redirect" {
                assert_eq!(handler.fields.get("otel.status_code"), Some(&json!("OK")));
                assert_eq!(
                    handler.fields.get("http.response.status_code"),
                    Some(&json!(302))
                );
            }
            let outer = records
                .first()
                .ok_or_else(|| AuthError::internal("missing outer span"))?;
            assert_eq!(
                outer.exceptions.len(),
                usize::from(kind == "ordinary" || (native && kind == "api"))
            );
        }
    }
    Ok(())
}
struct RejectHook {
    ordinary: bool,
    completed: std::sync::atomic::AtomicBool,
}
impl RejectHook {
    async fn reject(&self) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(if self.ordinary {
            AuthError::internal("global rejection")
        } else {
            AuthError::bad_request("global rejection")
        })
    }
}
#[async_trait]
impl BeforeEndpointHook<S> for RejectHook {
    async fn before(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.reject().await?;
        Ok(None)
    }
}
#[async_trait]
impl AfterEndpointHook<S> for RejectHook {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.reject().await
    }
}
#[tokio::test]
async fn global_hook_errors_preserve_awaiting_and_api_error_continuation() -> AuthResult<()> {
    for before in [true, false] {
        for ordinary in [true, false] {
            let hook = Arc::new(RejectHook {
                ordinary,
                completed: Default::default(),
            });
            let mut hooks = EndpointHooks::default();
            if before {
                hooks.before = Some(hook.clone());
            } else {
                hooks.after = Some(hook.clone());
            }
            let auth = BetterAuth::stateless(config())
                .hooks(hooks)
                .plugin(Probe)
                .build()
                .await?;
            let capture = Capture::default();
            let capture_span = capture.span();
            let result = auth
                .call_endpoint(HttpMethod::Get, "/probe", Default::default())
                .instrument(capture_span)
                .await;
            let error = result
                .err()
                .ok_or_else(|| AuthError::internal("hook error was swallowed"))?;
            assert_eq!(error.instrumentation_message(), "global rejection");
            assert_eq!(matches!(error, AuthError::Internal(_)), ordinary);
            assert!(hook.completed.load(std::sync::atomic::Ordering::SeqCst));
            let records = capture
                .0
                .lock()
                .map_err(|_| AuthError::internal("capture poisoned"))?;
            let expected = if before {
                vec!["GET /probe", "hook before /probe user"]
            } else if ordinary {
                vec![
                    "GET /probe",
                    "hook before /probe plugin:observe",
                    "handler /probe",
                    "hook after /probe user",
                ]
            } else {
                vec![
                    "GET /probe",
                    "hook before /probe plugin:observe",
                    "handler /probe",
                    "hook after /probe user",
                    "hook after /probe plugin:observe",
                ]
            };
            assert_eq!(
                records
                    .iter()
                    .filter_map(|r| r.fields.get("otel.name").and_then(Value::as_str))
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
    Ok(())
}

struct Lifecycle;
#[database_hooks]
impl DatabaseHooks<S> for Lifecycle {
    async fn before_create_user(
        &self,
        _: &mut better_auth::__private_core::CreateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_user(
        &self,
        _: &better_auth::wire::UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
}
#[tokio::test]
async fn database_spans_trace_only_declared_callbacks_and_instance_enablement() -> AuthResult<()> {
    for enabled in [false, true] {
        let mut options = config();
        options.experimental.instrumentation.enabled = enabled;
        let auth = BetterAuth::stateless(options)
            .database_hooks(vec![Arc::new(Lifecycle)])
            .plugin(better_auth::plugins::EmailPasswordPlugin::new())
            .build()
            .await?;
        let capture = Capture::default();
        let capture_span = capture.span();
        let response=auth.call_endpoint(HttpMethod::Post,"/sign-up/email",better_auth::server_api::EndpointInput { body:Some(json!({"email":"example@example.test","name":"Example","password":"Password123!"})),..Default::default() }).instrument(capture_span).await?;
        assert_eq!(response.status, 200);
        capture.wait_closed().await?;
        let records = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?;
        if !enabled {
            assert!(records.is_empty());
            continue;
        }
        let db: Vec<_> = records
            .iter()
            .filter(|record| {
                record
                    .fields
                    .get("otel.name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.starts_with("db "))
            })
            .collect();
        assert_eq!(
            db.iter()
                .filter_map(|record| record.fields.get("otel.name").and_then(Value::as_str))
                .collect::<Vec<_>>(),
            vec![
                "db findOne user",
                "db create.before user",
                "db create user",
                "db create account",
                "db create session",
                "db create.after user"
            ]
        );
        assert!(db.iter().all(|record| record.closed == 1
            && record.parent.as_deref() == Some("handler /sign-up/email")));
    }
    Ok(())
}

#[derive(Default)]
struct Logs(Mutex<Vec<(LogLevel, String, Vec<Value>)>>);
impl LogSink for Logs {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, args: &[LogArgument<'_>]) {
        let values = args
            .iter()
            .map(|argument| match argument {
                LogArgument::Text(value) => json!(value),
                LogArgument::Value(value) => (*value).clone(),
                LogArgument::Error(error) => json!(error.to_string()),
            })
            .collect();
        self.0.lock().expect("capture mutex is not poisoned").push((
            level,
            message.to_string(),
            values,
        ));
    }
}
#[tokio::test]
async fn loggers_are_instance_scoped_and_instrumentation_is_independent() -> AuthResult<()> {
    let left = Arc::new(Logs::default());
    let right = Arc::new(Logs::default());
    let mut a = config();
    a.logger.disabled = Some(false);
    a.logger.level = Some(LogLevel::Info);
    a.logger.log = Some(left.clone());
    a.experimental.instrumentation.enabled = false;
    let mut b = config();
    b.logger.disabled = Some(false);
    b.logger.level = Some(LogLevel::Error);
    b.logger.log = Some(right.clone());
    let a = build(a).await?;
    let b = build(b).await?;
    let request = || AuthRequest::new(HttpMethod::Get, "/api/auth/probe");
    let (a, b) = tokio::join!(a.handle_request(request()), b.handle_request(request()));
    assert_eq!(a?.status, 200);
    assert_eq!(b?.status, 200);
    assert_eq!(
        *left
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?,
        vec![(
            LogLevel::Info,
            "literal %s".into(),
            vec![json!({"value":1}), json!("tail")]
        )]
    );
    assert!(
        right
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?
            .is_empty()
    );
    Ok(())
}
#[derive(Default)]
struct Reports {
    events: Mutex<Vec<Value>>,
    fail: bool,
}
#[async_trait]
impl better_auth::observability::TelemetryTransport for Reports {
    async fn send(&self, event: &better_auth::observability::TelemetryEvent) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?
            .push(serde_json::to_value(event)?);
        if self.fail {
            Err(AuthError::internal("controlled failure"))
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn telemetry_opt_in_controls_sink_and_preserves_auth_when_sink_rejects() -> AuthResult<()> {
    let disabled = Arc::new(Reports::default());
    let mut options = config();
    options.telemetry.track = Some(disabled.clone());
    let auth = build(options).await?;
    assert!(
        disabled
            .events
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?
            .is_empty()
    );
    assert_eq!(
        auth.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/probe"))
            .await?
            .status,
        200
    );
    let enabled = Arc::new(Reports {
        fail: true,
        ..Default::default()
    });
    let logs = Arc::new(Logs::default());
    let mut options = config();
    options.telemetry.enabled = true;
    options.telemetry.debug = true;
    options.telemetry.track = Some(enabled.clone());
    options.logger.disabled = Some(false);
    options.logger.log = Some(logs.clone());
    let auth = build(options).await?;
    assert_eq!(
        auth.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/probe"))
            .await?
            .status,
        200
    );
    let events = enabled
        .events
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(events.len(), 1);
    let event = events
        .first()
        .ok_or_else(|| AuthError::internal("missing event"))?;
    assert_eq!(event.get("type"), Some(&json!("init")));
    assert_eq!(
        event.pointer("/payload/config/plugins"),
        Some(&json!(["observe"]))
    );
    assert_eq!(
        event.pointer("/payload/config/hooks"),
        Some(&json!({"before":true,"after":true}))
    );
    let json = serde_json::to_string(event)?;
    assert!(!json.contains("observability-reference-secret"));
    assert_eq!(
        event.pointer("/payload/config/emailAndPassword/password"),
        Some(&json!({"hash":false,"verify":false}))
    );
    assert!(
        !logs
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?
            .iter()
            .any(|(level, _, _)| *level == LogLevel::Error)
    );
    Ok(())
}

#[cfg(feature = "seaorm2")]
#[expect(unreachable_pub, reason = "SeaORM derives require public model types.")]
mod sqlite {
    use super::*;
    use better_auth::seaorm::{
        AuthEntity, Database, DatabaseHookUpdate, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
        sea_orm,
    };
    use better_auth_core::store::UserStore;
    use better_auth_core::{AuthSchema, CreateUser, UpdateUser};
    use sea_orm::{ConnectionTrait, Schema, entity::prelude::*};
    use serde_json::Value;
    mod passkey {
        use super::*;
        #[derive(Clone, Debug, DeriveEntityModel, AuthEntity)]
        #[auth(role = "passkey")]
        #[sea_orm(table_name = "traced_authenticators")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: Option<String>,
            pub public_key: String,
            pub user_id: String,
            pub credential_id: String,
            pub counter: i64,
            pub device_type: String,
            pub backed_up: bool,
            pub transports: Option<String>,
            pub credential: String,
            pub aaguid: Option<String>,
            pub created_at: DateTimeUtc,
            pub updated_at: DateTimeUtc,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
    #[tokio::test]
    async fn plugin_adapter_spans_use_physical_collections_and_logical_updates() -> AuthResult<()> {
        use better_auth_seaorm::store::entities;
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let schema = Schema::new(db.get_database_backend());
        for table in [
            schema.create_table_from_entity(passkey::Entity),
            schema.create_table_from_entity(entities::jwk::Entity),
            schema.create_table_from_entity(entities::wallet_address::Entity),
        ] {
            let _ = db
                .execute(&table)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        let store = SeaOrmStore::<Tables>::new(config(), db)
            .with_plugin_schema::<better_auth_seaorm::PluginModels<
                entities::api_key::Model,
                entities::device_code::Model,
                passkey::Model,
            >>();
        check_plugin_operations(&store, "traced_authenticators", "wallet_address").await
    }

    #[tokio::test]
    async fn two_factor_lockout_traces_actual_increment_branches() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(
                &Schema::new(db.get_database_backend()).create_table_from_entity(
                    better_auth_seaorm::store::entities::two_factor::Entity,
                ),
            )
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        check_two_factor_operations(&SeaOrmStore::<Tables>::new(config(), db), "two_factor").await
    }

    #[tokio::test]
    async fn device_claims_trace_guards_without_marking_misses_as_errors() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(
                &Schema::new(db.get_database_backend()).create_table_from_entity(
                    better_auth_seaorm::store::entities::device_code::Entity,
                ),
            )
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        check_device_operations(&SeaOrmStore::<Tables>::new(config(), db), "device_code").await
    }

    #[tokio::test]
    async fn api_key_list_traces_default_limited_find_many_and_unlimited_count() -> AuthResult<()> {
        use better_auth_core::store::ApiKeyStore;
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(
                &Schema::new(db.get_database_backend())
                    .create_table_from_entity(better_auth_seaorm::store::entities::api_key::Entity),
            )
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut config = config();
        config.advanced.database.default_find_many_limit = Some(2.0);
        let store = SeaOrmStore::<Tables>::new(config, db.clone());
        check_api_key_list(&store, "api_keys").await?;
        let _ = db
            .execute_unprepared("DROP TABLE api_keys")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let capture = Capture::default();
        assert!(
            store
                .count_api_keys_by_reference("owner")
                .instrument(capture.span())
                .await
                .is_err()
        );
        capture.wait_closed().await?;
        let records = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("capture poisoned"))?;
        assert_eq!(records.len(), 1);
        let record = records.first().expect("count span");
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!("count"))
        );
        assert_eq!(record.fields.get("otel.status_code"), Some(&json!("ERROR")));
        assert_eq!(record.exceptions.len(), 1);
        assert_eq!(record.closed, 1);
        Ok(())
    }

    #[tokio::test]
    async fn api_key_usage_traces_independent_guarded_writes() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(
                &Schema::new(db.get_database_backend())
                    .create_table_from_entity(better_auth_seaorm::store::entities::api_key::Entity),
            )
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        check_api_key_operations(&SeaOrmStore::<Tables>::new(config(), db), "api_keys").await
    }

    #[tokio::test]
    async fn api_key_failed_later_writes_preserve_quota_and_rate_changes() -> AuthResult<()> {
        use better_auth_core::store::ApiKeyStore;
        for field in ["remaining", "request_count", "updated_at"] {
            let db = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let _ = db
                .execute(
                    &Schema::new(db.get_database_backend()).create_table_from_entity(
                        better_auth_seaorm::store::entities::api_key::Entity,
                    ),
                )
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let store = SeaOrmStore::<Tables>::new(config(), db.clone());
            let key = store.create_api_key(api_key_input()).await?;
            let sql = format!(
                "CREATE TRIGGER reject_write BEFORE UPDATE OF {field} ON api_keys BEGIN SELECT RAISE(ABORT, 'controlled storage failure'); END"
            );
            let _ = db
                .execute_unprepared(&sql)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let expected: &[&str] = match field {
                "remaining" => &["incrementOne"],
                "request_count" => &["incrementOne", "incrementOne"],
                _ => &["incrementOne", "incrementOne", "update"],
            };
            assert!(
                trace_api_key_usage(&store, &key, expected, "api_keys")
                    .await
                    .is_err()
            );
            let stored = store
                .get_api_key_by_id_value(&key.id)
                .await?
                .expect("key remains");
            assert_eq!(
                stored.remaining,
                Some(if field == "remaining" { 3.0 } else { 2.0 })
            );
            assert_eq!(
                stored.request_count,
                Some(if field == "updated_at" { 1.0 } else { 0.0 })
            );
            assert_eq!(
                stored.last_request.typed()?.is_none(),
                field != "updated_at"
            );
            assert_eq!(stored.updated_at, key.updated_at);
        }
        Ok(())
    }
    mod user {
        use super::*;
        #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
        #[auth(role = "user")]
        #[sea_orm(table_name = "traced_people")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: Option<String>,
            #[sea_orm(unique)]
            pub email: Option<String>,
            pub email_verified: bool,
            pub image: Option<String>,
            pub created_at: DateTimeUtc,
            pub updated_at: DateTimeUtc,
            pub note: Option<String>,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
    struct Tables;
    impl AuthSchema for Tables {
        type User = user::Model;
        type Session = better_auth_seaorm::store::entities::session::Model;
        type Account = better_auth_seaorm::store::entities::account::Model;
        type Verification = better_auth_seaorm::store::entities::verification::Model;
    }
    struct UpdateHooks;
    #[database_hooks]
    impl SeaOrmHooks<Tables> for UpdateHooks {
        async fn before_update_user(
            &self,
            _: &better_auth_core::FieldValue,
            _: &UpdateUser,
            _: &SeaOrmHookContext<'_, Tables>,
        ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
            Ok(DatabaseHookUpdate::Continue)
        }
        async fn after_update_user(
            &self,
            _: Option<&better_auth::wire::UserView>,
            _: &SeaOrmHookContext<'_, Tables>,
        ) -> AuthResult<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn physical_collections_and_logical_updates_preserve_hook_and_transform_boundaries()
    -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut options = config();
        let _ = options.user.fields_mut().insert(
            "note".into(),
            better_auth_core::user_fields::UserFieldConfig {
                required: Some(false),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|value| {
                        if value.as_str() == Some("reject") {
                            Err(AuthError::internal("rejected transform"))
                        } else {
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let store = SeaOrmStore::<Tables>::new(options, db).hook(UpdateHooks);
        let first = store
            .create_user(
                CreateUser::new()
                    .with_email("first@example.test")
                    .with_name("First"),
            )
            .await?;
        let second = store
            .create_user(
                CreateUser::new()
                    .with_email("second@example.test")
                    .with_name("Second"),
            )
            .await?;
        for kind in ["success", "missing", "duplicate", "transform"] {
            let capture = Capture::default();
            let capture_span = capture.span();
            let id = if kind == "missing" {
                "missing"
            } else {
                second.id.typed()?
            };
            let mut update = UpdateUser {
                name: Some("Changed".into()).into(),
                ..Default::default()
            };
            if kind == "duplicate" {
                update.email = first.email.clone();
            }
            if kind == "transform" {
                let _ = update
                    .additional_fields
                    .insert("note".into(), "reject".into());
            }
            let result = store.update_user(id, update).instrument(capture_span).await;
            match kind {
                "success" => assert_eq!(result?.name.typed().unwrap().as_deref(), Some("Changed")),
                "missing" => assert!(matches!(result, Err(AuthError::UserNotFound))),
                _ => assert!(result.is_err()),
            }
            capture.wait_closed().await?;
            let records = capture
                .0
                .lock()
                .map_err(|_| AuthError::internal("capture poisoned"))?;
            let expected = match kind {
                "transform" => vec!["db update.before user"],
                "duplicate" => vec!["db update.before user", "db update traced_people"],
                _ => vec![
                    "db update.before user",
                    "db update traced_people",
                    "db update.after user",
                ],
            };
            assert_eq!(
                records
                    .iter()
                    .filter_map(|r| r.fields.get("otel.name").and_then(Value::as_str))
                    .collect::<Vec<_>>(),
                expected,
                "{kind}"
            );
            assert!(records.iter().all(|r| r.parent.is_none() && r.closed == 1));
            for record in records.iter() {
                let raw = record.fields.get("otel.name") == Some(&json!("db update traced_people"));
                assert_eq!(
                    record.fields.get("db.collection.name"),
                    Some(&json!(if raw { "traced_people" } else { "user" }))
                );
                assert_eq!(
                    record.exceptions.len(),
                    usize::from(raw && kind == "duplicate")
                );
                if raw && kind == "duplicate" {
                    assert_eq!(record.fields.get("otel.status_code"), Some(&json!("ERROR")));
                }
                if raw && kind == "missing" {
                    assert!(!record.fields.contains_key("otel.status_code"));
                }
            }
        }
        assert_eq!(
            store
                .get_user_by_id(second.id.typed()?)
                .await?
                .and_then(|user| user.email),
            Some("second@example.test".into())
        );
        Ok(())
    }
}

#[tokio::test]
async fn memory_plugin_adapter_spans_preserve_null_update_success() -> AuthResult<()> {
    let store = better_auth_core::store::EphemeralStore::new(Arc::new(config()));
    check_plugin_operations(&store, "passkey", "walletAddress").await
}

#[tokio::test]
async fn memory_two_factor_lockout_traces_actual_increment_branches() -> AuthResult<()> {
    check_two_factor_operations(
        &better_auth_core::store::EphemeralStore::new(Arc::new(config())),
        "twoFactor",
    )
    .await
}

async fn check_two_factor_operations(
    store: &impl better_auth_core::store::TwoFactorStore,
    collection: &str,
) -> AuthResult<()> {
    let factor = store
        .create_two_factor(better_auth_core::CreateTwoFactor {
            additional_fields: Default::default(),
            user_id: "owner".into(),
            secret: "secret".into(),
            backup_codes: "codes".into(),
            verified: true,
        })
        .await?;
    let capture = Capture::default();
    let capture_span = capture.span();
    async {
        let until = chrono::Utc::now() + chrono::Duration::minutes(5);
        store
            .record_two_factor_failure(&factor.id, 2, &|| Ok(until))
            .await?;
        store
            .record_two_factor_failure(&factor.id, 2, &|| Ok(until))
            .await?;
        let locked = store
            .get_two_factor_by_user_id("owner")
            .await?
            .expect("created factor");
        assert_eq!(locked.failed_verification_count, Some(2));
        assert!(locked.locked_until.is_some());
        store.reset_two_factor_failures(&factor.id, None).await?;
        let reset = store
            .get_two_factor_by_user_id("owner")
            .await?
            .expect("created factor");
        assert_eq!(reset.failed_verification_count, Some(0));
        assert!(reset.locked_until.is_none());
        store
            .record_two_factor_failure(&factor.id, 2, &|| Ok(until))
            .await?;
        store
            .record_two_factor_failure(&factor.id, 2, &|| Ok(until))
            .await?;
        store
            .reset_two_factor_failures(&factor.id, Some(until + chrono::Duration::minutes(1)))
            .await?;
        let expired = store
            .get_two_factor_by_user_id("owner")
            .await?
            .expect("created factor");
        assert_eq!(expired.failed_verification_count, Some(0));
        assert!(expired.locked_until.is_none());
        Ok::<_, AuthError>(())
    }
    .instrument(capture_span)
    .await?;
    let expected = [
        "incrementOne",
        "incrementOne",
        "incrementOne",
        "findOne",
        "update",
        "findOne",
        "incrementOne",
        "incrementOne",
        "incrementOne",
        "incrementOne",
        "findOne",
    ];
    capture.wait_closed().await?;
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(records.len(), expected.len(), "{records:#?}");
    for (record, operation) in records.iter().zip(expected) {
        assert_eq!(
            record.fields.get("otel.name"),
            Some(&json!(format!("db {operation} {collection}")))
        );
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!(operation))
        );
        assert_eq!(
            record.fields.get("db.collection.name"),
            Some(&json!(collection))
        );
        assert!(record.exceptions.is_empty());
        assert!(!record.fields.contains_key("otel.status_code"));
        assert_eq!(record.closed, 1);
    }
    Ok(())
}

async fn check_plugin_operations(
    store: &(
         impl better_auth_core::store::PasskeyStore
         + better_auth_core::store::JwksStore
         + better_auth_core::store::WalletStore
     ),
    passkeys: &str,
    wallets: &str,
) -> AuthResult<()> {
    let capture = Capture::default();
    let capture_span = capture.span();
    async {
        let row = store
            .create_passkey(better_auth_core::CreatePasskey {
                additional_fields: Default::default(),
                user_id: "owner".into(),
                name: None.into(),
                credential_id: "credential".into(),
                public_key: "public".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                credential: "private".into(),
                aaguid: None.into(),
            })
            .await?;
        assert_eq!(
            store
                .get_passkey_by_credential_id("credential")
                .await?
                .map(|row| row.id),
            Some(row.id.clone())
        );
        assert_eq!(
            store
                .update_passkey_name(row.id.typed()?, "Renamed")
                .await?
                .name
                .typed()
                .unwrap()
                .as_deref(),
            Some("Renamed")
        );
        assert!(
            store
                .update_passkey_name("missing", "Ignored")
                .await
                .is_err()
        );
        assert_eq!(store.list_passkeys_by_user("owner").await?.len(), 1);
        store.delete_passkey(row.id.typed()?).await?;
        assert!(store.list_passkeys_by_user("owner").await?.is_empty());
        let key = store
            .create_jwk(better_auth_core::CreateJwk {
                additional_fields: Default::default(),
                created_at: chrono::Utc::now().into(),
                public_key: "public".into(),
                private_key: "private".into(),
                expires_at: None,
                alg: "EdDSA".into(),
                crv: None,
            })
            .await?;
        assert_eq!(
            store.get_jwk(key.id.typed()?).await?.map(|key| key.id),
            Some(key.id.clone())
        );
        assert_eq!(store.list_jwks().await?.len(), 1);
        let wallet = store
            .create_wallet_address(better_auth_core::CreateWalletAddress {
                additional_fields: Default::default(),
                user_id: "owner".into(),
                address: "0x123".into(),
                chain_id: 1,
                is_primary: true,
                created_at: chrono::Utc::now().into(),
            })
            .await?;
        assert_eq!(
            store
                .get_wallet_address("0x123", Some(1))
                .await?
                .map(|row| row.id),
            Some(wallet.id)
        );
        Ok::<_, AuthError>(())
    }
    .instrument(capture_span)
    .await?;
    let expected = [
        ("create", passkeys),
        ("findOne", passkeys),
        ("update", passkeys),
        ("update", passkeys),
        ("findMany", passkeys),
        ("delete", passkeys),
        ("findMany", passkeys),
        ("create", "jwks"),
        ("findOne", "jwks"),
        ("findMany", "jwks"),
        ("create", wallets),
        ("findOne", wallets),
    ];
    capture.wait_closed().await?;
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(records.len(), expected.len(), "{records:#?}");
    for (record, (operation, collection)) in records.iter().zip(expected) {
        assert_eq!(
            record.fields.get("otel.name"),
            Some(&json!(format!("db {operation} {collection}")))
        );
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!(operation))
        );
        assert_eq!(
            record.fields.get("db.collection.name"),
            Some(&json!(collection))
        );
        assert!(record.exceptions.is_empty());
        assert!(!record.fields.contains_key("otel.status_code"));
        assert_eq!(record.closed, 1);
        assert!(record.parent.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_claims_trace_guards_without_marking_misses_as_errors() -> AuthResult<()> {
    check_device_operations(
        &better_auth_core::store::EphemeralStore::new(Arc::new(config())),
        "deviceCode",
    )
    .await
}

async fn check_device_operations(
    store: &impl better_auth_core::store::DeviceCodeStore,
    collection: &str,
) -> AuthResult<()> {
    let capture = Capture::default();
    let capture_span = capture.span();
    async {
        let code = store
            .create_device_code(better_auth_core::CreateDeviceCode {
                additional_fields: Default::default(),
                device_code: "device-secret".into(),
                user_code: "ABCD2345".into(),
                user_id: None,
                expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).into(),
                status: "pending".into(),
                last_polled_at: None,
                polling_interval: Some(5_000.0),
                client_id: Some("client".into()),
                scope: Default::default(),
            })
            .await?;
        assert_eq!(
            store
                .get_device_code_by_user_code("ABCD2345")
                .await?
                .expect("created code")
                .id,
            code.id
        );
        assert!(
            store
                .claim_device_code(&code.id, &"owner".to_owned().into())
                .await?
        );
        assert!(
            !store
                .claim_device_code(&code.id, &"other".to_owned().into())
                .await?
        );
        assert!(
            store
                .update_device_code_if_status(
                    &code.id,
                    "pending",
                    better_auth_core::UpdateDeviceCode {
                        status: Some("approved".into()),
                        ..Default::default()
                    }
                )
                .await?
        );
        let approved = store
            .get_device_code_by_device_code("device-secret")
            .await?
            .expect("approved code");
        assert_eq!(approved.user_id.typed()?.as_deref(), Some("owner"));
        assert_eq!(approved.status, "approved");
        assert!(
            !store
                .update_device_code_if_status(
                    &code.id,
                    "pending",
                    better_auth_core::UpdateDeviceCode {
                        status: Some("denied".into()),
                        ..Default::default()
                    }
                )
                .await?
        );
        let renamed = store
            .update_device_code(
                &code.id,
                better_auth_core::UpdateDeviceCode {
                    last_polled_at: Some(Some(chrono::Utc::now().into())),
                    ..Default::default()
                },
            )
            .await?;
        assert!(renamed.last_polled_at.typed()?.is_some());
        assert!(
            store
                .update_device_code(
                    &"missing".into(),
                    better_auth_core::UpdateDeviceCode {
                        status: Some("denied".into()),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        assert!(
            !store
                .delete_device_code_if_status(&code.id, "pending")
                .await?
        );
        assert!(
            store
                .delete_device_code_if_status(&code.id, "approved")
                .await?
        );
        assert!(
            store
                .get_device_code_by_device_code("device-secret")
                .await?
                .is_none()
        );
        store.delete_device_code(&code.id).await?;
        Ok::<_, AuthError>(())
    }
    .instrument(capture_span)
    .await?;
    let expected = [
        "create",
        "findOne",
        "incrementOne",
        "incrementOne",
        "update",
        "findOne",
        "update",
        "update",
        "update",
        "delete",
        "delete",
        "findOne",
        "delete",
    ];
    capture.wait_closed().await?;
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(records.len(), expected.len(), "{records:#?}");
    for (record, operation) in records.iter().zip(expected) {
        assert_eq!(
            record.fields.get("otel.name"),
            Some(&json!(format!("db {operation} {collection}")))
        );
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!(operation))
        );
        assert_eq!(
            record.fields.get("db.collection.name"),
            Some(&json!(collection))
        );
        assert!(record.exceptions.is_empty());
        assert!(!record.fields.contains_key("otel.status_code"));
        assert_eq!(record.closed, 1);
    }
    Ok(())
}

#[path = "observability/admin_counts.rs"]
mod admin_counts;

fn api_key_input() -> better_auth_core::CreateApiKey {
    better_auth_core::CreateApiKey {
        additional_fields: Default::default(),
        reference_id: "owner".into(),
        config_id: "default".into(),
        name: None.into(),
        prefix: None,
        key_hash: "stored-secret".into(),
        start: None,
        expires_at: None,
        remaining: Some(3.0),
        enabled: true.into(),
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000.0),
        rate_limit_max: Some(1.0),
        refill_interval: None,
        refill_amount: None,
        permissions: None,
        metadata: None,
    }
}

async fn trace_api_key_usage(
    store: &impl better_auth_core::store::ApiKeyStore,
    snapshot: &better_auth_core::ApiKey,
    expected: &[&str],
    collection: &str,
) -> AuthResult<better_auth_core::store::ConsumeApiKeyResult> {
    let capture = Capture::default();
    let result = store
        .consume_api_key_usage(snapshot, true)
        .instrument(capture.span())
        .await;
    capture.wait_closed().await?;
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(records.len(), expected.len(), "{records:#?}");
    for (index, (record, operation)) in records.iter().zip(expected).enumerate() {
        assert_eq!(
            record.fields.get("otel.name"),
            Some(&json!(format!("db {operation} {collection}")))
        );
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!(operation))
        );
        assert_eq!(
            record.fields.get("db.collection.name"),
            Some(&json!(collection))
        );
        assert_eq!(record.closed, 1);
        if result.is_err() && index + 1 == expected.len() {
            assert_eq!(record.fields.get("otel.status_code"), Some(&json!("ERROR")));
            assert_eq!(record.exceptions.len(), 1);
            assert!(
                record
                    .exceptions
                    .first()
                    .expect("recorded failure")
                    .contains("controlled storage failure")
            );
        } else {
            assert!(record.exceptions.is_empty());
            assert!(!record.fields.contains_key("otel.status_code"));
        }
    }
    result
}

async fn check_api_key_operations(
    store: &impl better_auth_core::store::ApiKeyStore,
    collection: &str,
) -> AuthResult<()> {
    use better_auth_core::store::ConsumeApiKeyResult;
    let key = store.create_api_key(api_key_input()).await?;
    let allowed = trace_api_key_usage(
        store,
        &key,
        &["incrementOne", "incrementOne", "update"],
        collection,
    )
    .await?;
    let ConsumeApiKeyResult::Allowed(allowed) = allowed else {
        return Err(AuthError::internal("first usage must succeed"));
    };
    assert_eq!(allowed.remaining, Some(2.0));
    assert_eq!(allowed.request_count, Some(1.0));
    let mut snapshot = *allowed;
    for remaining in [1.0, 0.0] {
        let result = trace_api_key_usage(store, &snapshot, &["incrementOne"], collection).await?;
        assert!(matches!(result, ConsumeApiKeyResult::RateLimited { .. }));
        let stored = store
            .get_api_key_by_id_value(&key.id)
            .await?
            .expect("quota write remains");
        assert_eq!(stored.remaining, Some(remaining));
        assert_eq!(stored.request_count, snapshot.request_count);
        assert_eq!(stored.last_request, snapshot.last_request);
        assert_eq!(stored.updated_at, snapshot.updated_at);
        snapshot = stored;
    }
    let exhausted = trace_api_key_usage(store, &snapshot, &["delete"], collection).await?;
    assert!(matches!(exhausted, ConsumeApiKeyResult::UsageExhausted));
    assert!(store.get_api_key_by_id_value(&key.id).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn memory_api_key_usage_traces_independent_guarded_writes() -> AuthResult<()> {
    check_api_key_operations(
        &better_auth_core::store::EphemeralStore::new(Arc::new(config())),
        "apikey",
    )
    .await
}

async fn check_api_key_list(
    store: &impl better_auth_core::store::ApiKeyStore,
    collection: &str,
) -> AuthResult<()> {
    for (index, name) in ["D", "A", "E", "C", "B"].into_iter().enumerate() {
        let mut input = api_key_input();
        input.name = Some(name.into()).into();
        input.key_hash = format!("secret-{index}");
        let _ = store.create_api_key(input).await?;
    }
    let capture = Capture::default();
    let (keys, count) = async {
        tokio::join!(
            store.find_api_keys_by_reference("owner", Some(("name", "desc"))),
            store.count_api_keys_by_reference("owner"),
        )
    }
    .instrument(capture.span())
    .await;
    assert_eq!(
        keys?
            .iter()
            .map(|key| key.name.typed().unwrap().as_deref())
            .collect::<Vec<_>>(),
        [Some("E"), Some("D")]
    );
    assert_eq!(count?, 5);
    capture.wait_closed().await?;
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    assert_eq!(records.len(), 2);
    for (record, operation) in records.iter().zip(["findMany", "count"]) {
        assert_eq!(
            record.fields.get("db.operation.name"),
            Some(&json!(operation))
        );
        assert_eq!(
            record.fields.get("db.collection.name"),
            Some(&json!(collection))
        );
        assert!(record.exceptions.is_empty());
        assert_eq!(record.closed, 1);
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_list_traces_default_limited_find_many_and_unlimited_count() -> AuthResult<()>
{
    let mut config = config();
    config.advanced.database.default_find_many_limit = Some(2.0);
    check_api_key_list(
        &better_auth_core::store::EphemeralStore::new(Arc::new(config)),
        "apikey",
    )
    .await
}

#[path = "observability/native_endpoints.rs"]
mod native_endpoints;

#[path = "observability/two_factor_clock.rs"]
mod two_factor_clock;
