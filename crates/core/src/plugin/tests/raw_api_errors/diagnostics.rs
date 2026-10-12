#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};

struct MatcherFailure {
    value: FieldValue,
    events: Events,
}

#[async_trait]
impl AuthPlugin<S> for MatcherFailure {
    fn name(&self) -> &'static str {
        "matcher-failure"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        crate::hooks::run_before_hook_matcher(
            &context.config,
            Some(request),
            "plugin:matcher-failure",
            || {
                self.events.lock().unwrap().push("matcher".into());
                Err(AuthError::from_thrown(self.value.clone()))
            },
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

impl crate::observability::LogSink for MatcherFailure {
    fn log(
        &self,
        level: LogLevel,
        message: crate::observability::LogArgument<'_>,
        arguments: &[crate::observability::LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        assert!(matches!(
            message,
            crate::observability::LogArgument::Text(
                "An error occurred during plugin:matcher-failure hook matcher execution:"
            )
        ));
        let [crate::observability::LogArgument::Error(error)] = arguments else {
            panic!("Expected the original matcher error as one logger argument");
        };
        assert_raw(error.downcast_ref::<AuthError>().unwrap(), &self.value);
        self.events.lock().unwrap().push("log".into());
        Ok(())
    }
}

#[tokio::test]
async fn matcher_failures_preserve_log_identity_and_skip_handler_error_recovery() -> AuthResult<()>
{
    for http in [false, true] {
        let events = Events::default();
        let unread: Getter = Arc::new(|| {
            Err(AuthError::internal(
                "Matcher wrappers must not read the original error",
            ))
        });
        let value = probe(
            FieldMap::new(),
            ["name", "message", "headers", "errorStack", "stack"]
                .map(|name| (name, unread.clone()))
                .into(),
        );
        let mut config = (*crate::test_store::test_config()).clone();
        {
            let crate::LoggerSource::Config(logger_options) = &mut config.logger else {
                #[allow(
                    clippy::panic,
                    clippy::panic_in_result_fn,
                    reason = "The fixture modifies its existing authored logger options."
                )]
                {
                    panic!("fixture requires authored logger options");
                }
            };
            logger_options.level = Some(LogLevel::Debug);
            logger_options.disabled = Some(false);
            logger_options.log = Some(Arc::new(MatcherFailure {
                value: value.clone(),
                events: events.clone(),
            }));
        }
        let config = Arc::new(config);
        let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
            .expect("fixture context initializes");
        let hook = Arc::new(Hooks::new("none", FieldValue::Undefined, &events));
        let route = AuthRoute::get("/matcher-error", "matcherError");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![Box::new(MatcherFailure {
                value: value.clone(),
                events: events.clone(),
            }) as Box<dyn AuthPlugin<S>>]),
            EndpointHooks {
                before: Some(hook.clone()),
                after: Some(hook),
            },
            [route.clone()],
        );
        let mut request = AuthRequest::new(HttpMethod::Get, "/matcher-error");
        let handler = |_: AuthRequest, _context| async {
            Err(AuthError::internal(
                "A matcher failure must stop before the endpoint handler",
            ))
        };
        let result = if http {
            dispatcher
                .run(&mut request, true, &context, None, handler)
                .await
        } else {
            dispatcher.native(request, route, &context, handler).await
        };
        let error = result.unwrap_err();
        assert!(error.is_api_error_instance(crate::ApiErrorClass::BetterAuth));
        assert!(!error.raw_value().unwrap().strict_equals(&value));
        assert_eq!(error.status_value()?, "INTERNAL_SERVER_ERROR".into());
        assert_eq!(error.status_code()?, 500);
        assert_eq!(
            error.body_value()?.enumerable_fields()?,
            FieldMap::from([(
                "message".into(),
                "An error occurred during hook matcher execution. Check the logs for more details."
                    .into(),
            )])
        );
        assert_eq!(error.headers_value()?.enumerable_fields()?, FieldMap::new());
        assert!(error.captured_headers_value().is_none());
        assert!(!error.raw_value().unwrap().has_property("stack")?);
        assert_eq!(*events.lock().unwrap(), ["before", "matcher", "log"]);
    }
    Ok(())
}

struct AccessProbe {
    inner: FieldObject,
    events: Events,
    presence: bool,
    stack: Option<(FieldValue, Option<&'static str>, FieldValue)>,
}

impl FieldObjectSource for AccessProbe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.inner.own_keys()
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        self.inner.own_property_descriptor(name)
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        if self.presence {
            self.events.lock().unwrap().push(format!("has:{name}"));
        }
        self.inner.has_property(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.inner.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        if name == "stack"
            && let Some((expected, failed_at, failure)) = &self.stack
        {
            self.events.lock().unwrap().push("set".into());
            assert!(value.strict_equals(expected));
            if *failed_at == Some("set") {
                return Err(AuthError::from_thrown(failure.clone()));
            }
            return Ok(true);
        }
        self.inner.set_with_receiver(&name, value, receiver)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.inner.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.inner.snapshot_fields()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.inner.define_own_property(name, definition)
    }
}

#[tokio::test]
async fn debug_stack_preserves_getter_setter_order_and_original_failure() -> AuthResult<()> {
    for failed_at in [None, Some("get"), Some("set")] {
        let events = Events::default();
        let failure: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let stack: FieldValue = FieldMap::from([("identity".into(), true.into())]).into();
        let getter: Getter = Arc::new({
            let events = events.clone();
            let stack = stack.clone();
            let failure = failure.clone();
            move || observed(&events, failed_at, &failure, "get", stack.clone())
        });
        let raw = raw_error(&events, &["APIError"], None, vec![("errorStack", getter)]);
        let value: FieldValue = FieldObject::from_source(Arc::new(AccessProbe {
            inner: raw.as_object().unwrap().clone(),
            events: events.clone(),
            presence: false,
            stack: Some((stack, failed_at, failure.clone())),
        }))
        .into();
        let mut hooks = Hooks::new("handler-return", value.clone(), &events);
        hooks.debug = true;
        let error = hooks.run(false, SchemaValue::Undefined).await.unwrap_err();
        assert_raw(
            &error,
            if failed_at.is_some() {
                &failure
            } else {
                &value
            },
        );
        let mut expected: Vec<String> = [
            "before",
            "handler",
            "after",
            "plugin-after",
            "name:1",
            "get",
        ]
        .map(Into::into)
        .into();
        if failed_at != Some("get") {
            expected.push("set".into());
        }
        if failed_at.is_none() {
            expected.push("name:2".into());
        }
        assert_eq!(*events.lock().unwrap(), expected, "{failed_at:?}");
    }
    Ok(())
}

#[derive(Default)]
struct TraceFields(Vec<(String, String)>);

impl Visit for TraceFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().into(), value.into()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().into(), format!("{value:?}")));
    }
}

struct TraceCapture {
    events: Events,
    references: AtomicUsize,
    dynamic_status: String,
}

impl Subscriber for TraceCapture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut fields = TraceFields::default();
        attributes.record(&mut fields);
        assert_eq!(
            fields.0,
            [
                ("otel.name".into(), "raw-error".into()),
                ("otel.scope.name".into(), "better-auth".into()),
                ("otel.scope.version".into(), "1.7.6".into()),
            ]
        );
        assert_eq!(self.references.fetch_add(1, Ordering::Relaxed), 0);
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, values: &Record<'_>) {
        let mut fields = TraceFields::default();
        values.record(&mut fields);
        assert_eq!(fields.0.len(), 1);
        let (name, value) = &fields.0[0];
        let event = match name.as_str() {
            "http.response.status_code" => {
                assert_eq!(value, &self.dynamic_status);
                "attribute:http.response.status_code".into()
            }
            "otel.status_code" => format!("span-status:{value}"),
            "otel.status_description" => format!("span-message:{value}"),
            other => panic!("Unexpected trace attribute: {other}"),
        };
        self.events.lock().unwrap().push(event);
    }

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        assert_eq!(event.metadata().name(), "exception");
        let mut fields = TraceFields::default();
        event.record(&mut fields);
        assert_eq!(
            fields.0,
            [("exception.message".into(), "Native endpoint error".into())]
        );
        self.events.lock().unwrap().push("exception".into());
    }

    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}

    fn clone_span(&self, id: &Id) -> Id {
        let _ = self.references.fetch_add(1, Ordering::Relaxed);
        id.clone()
    }

    fn try_close(&self, _: Id) -> bool {
        let closed = self.references.fetch_sub(1, Ordering::Relaxed) == 1;
        if closed {
            self.events.lock().unwrap().push("end".into());
        }
        closed
    }
}

#[tokio::test]
async fn tracing_checks_presence_and_live_properties_before_recording_status() -> AuthResult<()> {
    for kind in ["redirect", "nonredirect", "renamed-instance"] {
        let events = Events::default();
        let status: FieldValue = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let events = events.clone();
                move |_, arguments| {
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push("number".into());
                    Ok(if kind == "redirect" { 302.0 } else { 418.0 }.into())
                }
            })
            .into(),
        )])
        .into();
        let message: FieldValue = FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual({
                let events = events.clone();
                move |_, arguments| {
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push("message-string".into());
                    Ok("traced".into())
                }
            })
            .into(),
        )])
        .into();
        let getters: Vec<(&str, Getter)> = vec![
            (
                "name",
                Arc::new({
                    let events = events.clone();
                    move || {
                        events.lock().unwrap().push("name".into());
                        Ok(if kind == "renamed-instance" {
                            "Other"
                        } else {
                            "APIError"
                        }
                        .into())
                    }
                }),
            ),
            (
                "statusCode",
                Arc::new({
                    let events = events.clone();
                    let status = status.clone();
                    let reads = Mutex::new(0);
                    move || {
                        let mut reads = reads.lock().unwrap();
                        *reads += 1;
                        events.lock().unwrap().push(format!("status:{reads}"));
                        Ok(status.clone())
                    }
                }),
            ),
            (
                "message",
                Arc::new({
                    let events = events.clone();
                    move || {
                        events.lock().unwrap().push("message".into());
                        Ok(message.clone())
                    }
                }),
            ),
        ];
        let raw = probe(FieldMap::new(), getters);
        let fields = FieldObject::from_source(Arc::new(AccessProbe {
            inner: raw.as_object().unwrap().clone(),
            events: events.clone(),
            presence: true,
            stack: None,
        }));
        let value = if kind == "renamed-instance" {
            crate::error::brand_api_error_object(fields, crate::ApiErrorClass::BetterCall)
        } else {
            fields.into()
        };
        let capture = TraceCapture {
            events: events.clone(),
            references: AtomicUsize::new(0),
            dynamic_status: format!("{status:?}"),
        };
        let result = async {
            crate::observability::with_span(
                &crate::observability::InstrumentationConfig { enabled: true },
                "raw-error",
                Default::default(),
                async { Err::<(), _>(AuthError::from_thrown(value.clone())) },
            )
            .await
        }
        .with_subscriber(capture)
        .await;
        assert_raw(&result.unwrap_err(), &value);
        let mut expected: Vec<String> = ["has:name", "name"].map(Into::into).into();
        if kind != "renamed-instance" {
            expected.extend(["has:statusCode", "status:1", "number", "number"].map(Into::into));
        }
        if kind == "redirect" {
            expected.extend(
                [
                    "status:2",
                    "attribute:http.response.status_code",
                    "span-status:OK",
                    "end",
                ]
                .map(Into::into),
            );
        } else {
            expected.extend(
                [
                    "exception",
                    "message",
                    "message-string",
                    "span-status:ERROR",
                    "span-message:traced",
                    "end",
                ]
                .map(Into::into),
            );
        }
        assert_eq!(*events.lock().unwrap(), expected, "{kind}");
    }
    Ok(())
}

#[tokio::test]
async fn actual_hook_classifies_and_captures_before_trace_message_consumption() -> AuthResult<()> {
    let events = Events::default();
    let getter: Getter = Arc::new({
        let events = events.clone();
        let reads = Mutex::new(0);
        move || {
            let mut reads = reads.lock().unwrap();
            *reads += 1;
            events.lock().unwrap().push(format!("message:{reads}"));
            Ok("hook rejection".into())
        }
    });
    let value = raw_error(&events, &["APIError"], None, vec![("message", getter)]);
    let mut hooks = Hooks::new("before-throw", value.clone(), &events);
    hooks.instrumentation = true;
    let error = hooks
        .run(false, SchemaValue::Undefined)
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
        .unwrap_err();
    assert_raw(&error, &value);
    assert_eq!(
        *events.lock().unwrap(),
        [
            "before",
            "name:1",
            "name:2",
            "message:1",
            "name:3",
            "name:4",
            "message:2"
        ]
    );
    assert_headers(
        &Headers::from_field_value(&error.captured_headers_value().unwrap())?,
        &[("x-before", "1")],
        &[],
    );
    Ok(())
}
