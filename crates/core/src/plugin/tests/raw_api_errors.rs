#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired raw error contracts assert original identities, exact callback order, and complete HTTP output."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, FieldFunction, FieldMap, FieldObject, FieldValue, Headers, HttpMethod,
    NativeResponseStatus, SchemaValue,
    endpoint_dispatch::EndpointDispatcher,
    field_value::FieldObjectSource,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks, LogLevel},
    store::{EphemeralStore, StatelessSchema as S},
};

mod diagnostics;
mod headers;

type Events = Arc<Mutex<Vec<String>>>;
type Getter = Arc<dyn Fn() -> AuthResult<FieldValue> + Send + Sync>;
type Mutation = Arc<dyn Fn() -> AuthResult<()> + Send + Sync>;

struct Probe {
    fields: FieldObject,
    getters: Vec<(&'static str, Getter)>,
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.getters.iter().any(|(key, _)| *key == name) || self.fields.has_property(name)?)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if let Some((_, getter)) = self.getters.iter().find(|(key, _)| *key == name) {
            return getter().map(Some);
        }
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(&name, &FieldValue::Undefined)?
                        .unwrap(),
                ))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
}

fn probe(fields: FieldMap, getters: Vec<(&'static str, Getter)>) -> FieldValue {
    FieldObject::from_source(Arc::new(Probe {
        fields: fields.into(),
        getters,
    }))
    .into()
}

fn payload() -> FieldValue {
    FieldMap::from([
        ("code".into(), "RAW_API_ERROR".into()),
        ("message".into(), "raw failure".into()),
    ])
    .into()
}

fn error_fields() -> FieldMap {
    FieldMap::from([
        ("body".into(), payload()),
        ("status".into(), "BAD_REQUEST".into()),
        ("statusCode".into(), 418.0.into()),
        (
            "headers".into(),
            FieldMap::from([
                ("x-owned".into(), "1".into()),
                ("set-cookie".into(), "owned=1".into()),
            ])
            .into(),
        ),
    ])
}

fn raw_error(
    events: &Events,
    names: &[&str],
    failure: Option<(usize, FieldValue)>,
    extra: Vec<(&'static str, Getter)>,
) -> FieldValue {
    let events = events.clone();
    let names: Vec<String> = names.iter().map(|name| (*name).into()).collect();
    let reads = Mutex::new(0);
    let name: Getter = Arc::new(move || {
        let mut reads = reads.lock().unwrap();
        *reads += 1;
        events.lock().unwrap().push(format!("name:{reads}"));
        if let Some((index, value)) = &failure
            && *index == *reads
        {
            return Err(AuthError::from_thrown(value.clone()));
        }
        Ok(names[(*reads - 1).min(names.len() - 1)].clone().into())
    });
    let mut getters = vec![("name", name)];
    getters.extend(extra);
    probe(error_fields(), getters)
}

#[derive(Clone)]
struct Hooks {
    phase: &'static str,
    value: FieldValue,
    events: Events,
    observed: Arc<Mutex<Vec<FieldValue>>>,
    mutate: Option<Mutation>,
    debug: bool,
    instrumentation: bool,
    router: bool,
}

impl Hooks {
    fn new(phase: &'static str, value: FieldValue, events: &Events) -> Self {
        Self {
            phase,
            value,
            events: events.clone(),
            observed: Default::default(),
            mutate: None,
            debug: false,
            instrumentation: false,
            router: false,
        }
    }

    fn emit(&self, location: &str) -> AuthResult<Option<AuthResponse>> {
        if self.phase == format!("{location}-throw") {
            Err(AuthError::from_thrown(self.value.clone()))
        } else if self.phase == format!("{location}-return") {
            Ok(Some(AuthResponse::native(None, self.value.clone())))
        } else {
            Ok(None)
        }
    }

    async fn run(&self, http: bool, status: SchemaValue<u16>) -> AuthResult<AuthResponse> {
        let mut config = (*crate::test_store::test_config()).clone();
        config.experimental.instrumentation.enabled = self.instrumentation;
        config.logger = crate::LoggerConfig {
            disabled: Some(true),
            level: Some(if self.debug {
                LogLevel::Debug
            } else {
                LogLevel::Warn
            }),
            ..Default::default()
        }
        .into();
        let config = Arc::new(config);
        let mut context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
            .expect("fixture context initializes");
        if self.router {
            context
                .extensions
                .insert(Arc::new(self.clone()) as Arc<dyn crate::api_error::ApiErrorHandler<S>>);
        }
        let route = AuthRoute::get("/raw-api-error", "rawApiError");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![Box::new(self.clone()) as Box<dyn AuthPlugin<S>>]),
            EndpointHooks {
                before: Some(Arc::new(self.clone())),
                after: Some(Arc::new(self.clone())),
            },
            [route.clone()],
        );
        let mut request = AuthRequest::new(HttpMethod::Get, "/raw-api-error");
        let hook = self.clone();
        let handler = move |request: AuthRequest, _context| async move {
            hook.events.lock().unwrap().push("handler".into());
            request.set_response_header("x-handler", "1")?;
            request.set_response_status(status)?;
            Ok(hook.emit("handler")?.unwrap_or_else(|| {
                AuthResponse::native(None, FieldMap::from([("ok".into(), true.into())]).into())
            }))
        };
        if http {
            match dispatcher
                .run(&mut request, true, &context, None, handler)
                .await
            {
                Err(error) if self.router => {
                    crate::api_error::handle_http_error(error, &context).await
                }
                result => result,
            }
        } else {
            dispatcher.native(request, route, &context, handler).await
        }
    }
}

impl crate::api_error::ApiErrorHandler<S> for Hooks {
    fn on_error(
        &self,
        error: &AuthError,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<crate::api_error::ApiErrorTask>> {
        self.events.lock().unwrap().push("on-error".into());
        assert_raw(error, &self.value);
        Ok(None)
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.events.lock().unwrap().push("before".into());
        request.set_response_header("x-before", "1")?;
        self.emit("before")
            .map(|response| response.map(BeforeRequestAction::Respond))
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
        self.events.lock().unwrap().push("after".into());
        self.observed
            .lock()
            .unwrap()
            .push(response.body.field_value()?);
        request.set_response_header("x-after", "1")?;
        if let Some(mutate) = &self.mutate {
            mutate()?;
        }
        if let Some(returned) = self.emit("after")? {
            response.replace_returned(returned);
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Hooks {
    fn name(&self) -> &'static str {
        "raw-api-error"
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
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("plugin-after".into());
        self.observed
            .lock()
            .unwrap()
            .push(response.body.field_value()?);
        Ok(())
    }
}

fn assert_headers(headers: &Headers, expected: &[(&str, &str)], cookies: &[&str]) {
    let mut ordinary: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.as_str() != "set-cookie")
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    ordinary.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(ordinary, expected);
    assert_eq!(
        headers
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        cookies
    );
}

fn assert_raw(error: &AuthError, value: &FieldValue) {
    assert!(error.raw_value().unwrap().strict_equals(value));
}

#[tokio::test]
async fn phases_preserve_raw_error_identity_and_repeated_classification() -> AuthResult<()> {
    let cases: &[(&str, &[&str])] = &[
        ("before-return", &["before"]),
        ("before-throw", &["before", "name:1", "name:2"]),
        (
            "handler-return",
            &[
                "before",
                "handler",
                "after",
                "plugin-after",
                "name:1",
                "name:2",
            ],
        ),
        (
            "handler-throw",
            &[
                "before",
                "handler",
                "name:1",
                "name:2",
                "name:3",
                "after",
                "plugin-after",
                "name:4",
                "name:5",
            ],
        ),
        (
            "after-return",
            &[
                "before",
                "handler",
                "after",
                "plugin-after",
                "name:1",
                "name:2",
            ],
        ),
        (
            "after-throw",
            &[
                "before",
                "handler",
                "after",
                "name:1",
                "name:2",
                "plugin-after",
                "name:3",
                "name:4",
            ],
        ),
    ];
    for &(phase, baseline) in cases {
        for http in [false, true] {
            let events = Events::default();
            let value = raw_error(&events, &["APIError"], None, vec![]);
            let owned = value.model_property("headers")?;
            let hook = Hooks::new(phase, value.clone(), &events);
            let outcome = hook.run(http, SchemaValue::Typed(201)).await;
            let rejected = phase == "before-throw" || !http && !phase.starts_with("before");
            assert_eq!(outcome.is_err(), rejected, "{phase}/{http}");
            let mut expected: Vec<String> = baseline.iter().map(|event| (*event).into()).collect();
            if http && !rejected {
                expected.push(format!(
                    "name:{}",
                    baseline
                        .iter()
                        .filter(|event| event.starts_with("name:"))
                        .count()
                        + 1
                ));
            }
            assert_eq!(*events.lock().unwrap(), expected, "{phase}/{http}");
            assert!(value.model_property("headers")?.strict_equals(&owned));
            if !phase.starts_with("before") {
                let observed = hook.observed.lock().unwrap();
                assert_eq!(observed.len(), 2);
                assert!(observed[1].strict_equals(&value));
                if phase.starts_with("handler") {
                    assert!(observed[0].strict_equals(&value));
                } else {
                    assert_eq!(
                        observed[0],
                        FieldMap::from([("ok".into(), true.into())]).into()
                    );
                }
            } else {
                assert!(hook.observed.lock().unwrap().is_empty());
            }
            let mut headers = if phase.starts_with("before") {
                vec![("x-before", "1")]
            } else {
                vec![("x-handler", "1"), ("x-after", "1")]
            };
            let merged = phase == "handler-throw" || phase == "after-throw";
            if merged {
                headers.push(("x-owned", "1"));
            }
            match outcome {
                Err(error) => {
                    assert_raw(&error, &value);
                    let captured = error
                        .to_auth_response()
                        .expect("fixture response succeeds")
                        .captured_headers()?
                        .unwrap();
                    assert_headers(&captured, &headers, if merged { &["owned=1"] } else { &[] });
                }
                Ok(response) if !http => {
                    assert_eq!(response.native_status(), NativeResponseStatus::Absent);
                    assert!(response.body.field_value()?.strict_equals(&value));
                    assert_headers(&response.headers, &headers, &[]);
                }
                Ok(response) => {
                    assert_eq!(
                        response.status,
                        if phase == "before-return" || phase == "handler-throw" {
                            418
                        } else {
                            201
                        }
                    );
                    assert_eq!(response.status_text, "BAD_REQUEST".into());
                    headers.push(("content-type", "application/json"));
                    assert_headers(
                        &response.headers,
                        &headers,
                        if merged { &["owned=1"] } else { &[] },
                    );
                    assert_eq!(
                        response.body.bytes()?.as_ref(),
                        br#"{"code":"RAW_API_ERROR","message":"raw failure"}"#
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn final_classification_is_live_and_native_return_does_not_read_error_fields()
-> AuthResult<()> {
    for (names, rejected) in [
        (["APIError", "Other"], false),
        (["Other", "APIError"], true),
    ] {
        let events = Events::default();
        let value = raw_error(&events, &names, None, vec![]);
        let outcome = Hooks::new("handler-return", value.clone(), &events)
            .run(false, SchemaValue::Undefined)
            .await;
        assert_eq!(outcome.is_err(), rejected);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "before",
                "handler",
                "after",
                "plugin-after",
                "name:1",
                "name:2"
            ]
        );
        match outcome {
            Err(error) => assert_raw(&error, &value),
            Ok(response) => {
                assert!(response.body.field_value()?.strict_equals(&value));
                assert_eq!(
                    response.native_status(),
                    NativeResponseStatus::Present(SchemaValue::Undefined)
                );
                assert_headers(
                    &response.headers,
                    &[("x-handler", "1"), ("x-after", "1")],
                    &[],
                );
            }
        }
    }
    let events = Events::default();
    let blocked: Getter = Arc::new(|| {
        Err(AuthError::internal(
            "Native return must not consume error fields",
        ))
    });
    let value = raw_error(
        &events,
        &["APIError"],
        None,
        ["body", "statusCode", "status", "headers"]
            .map(|name| (name, blocked.clone()))
            .into(),
    );
    let error = Hooks::new("handler-return", value.clone(), &events)
        .run(false, SchemaValue::Undefined)
        .await
        .unwrap_err();
    assert_raw(&error, &value);
    assert_eq!(
        *events.lock().unwrap(),
        [
            "before",
            "handler",
            "after",
            "plugin-after",
            "name:1",
            "name:2"
        ]
    );
    for read in 1..=3 {
        let events = Events::default();
        let failure: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let value = raw_error(
            &events,
            &["APIError"],
            Some((read, failure.clone())),
            vec![],
        );
        let error = Hooks::new("handler-return", value, &events)
            .run(read == 3, SchemaValue::Undefined)
            .await
            .unwrap_err();
        assert_raw(&error, &failure);
        let mut expected = vec![
            "before".into(),
            "handler".into(),
            "after".into(),
            "plugin-after".into(),
        ];
        expected.extend((1..=read).map(|index| format!("name:{index}")));
        assert_eq!(*events.lock().unwrap(), expected);
    }
    for (names, encoded) in [
        (["Other", "Other", "APIError"], true),
        (["APIError", "APIError", "Other"], false),
    ] {
        let events = Events::default();
        let value = raw_error(&events, &names, None, vec![]);
        let response = Hooks::new("handler-return", value, &events)
            .run(true, SchemaValue::Undefined)
            .await?;
        assert_eq!(
            *events.lock().unwrap(),
            [
                "before",
                "handler",
                "after",
                "plugin-after",
                "name:1",
                "name:2",
                "name:3"
            ]
        );
        assert_eq!(response.status, if encoded { 418 } else { 200 });
        assert_eq!(
            response.status_text,
            if encoded { "BAD_REQUEST" } else { "" }.into()
        );
        assert_headers(
            &response.headers,
            &[
                ("content-type", "application/json"),
                ("x-handler", "1"),
                ("x-after", "1"),
            ],
            &[],
        );
        let bytes: &[u8] = if encoded {
            br#"{"code":"RAW_API_ERROR","message":"raw failure"}"#
        } else {
            br#"{"body":{"code":"RAW_API_ERROR","message":"raw failure"},"status":"BAD_REQUEST","statusCode":418,"headers":{"x-owned":"1","set-cookie":"owned=1"}}"#
        };
        assert_eq!(response.body.bytes()?.as_ref(), bytes);
    }
    Ok(())
}

#[tokio::test]
async fn thrown_status_snapshots_preserve_nullish_rereads_and_dynamic_handles() -> AuthResult<()> {
    for (initial, count, status) in [
        (418.0.into(), 1, 418),
        (FieldValue::Null, 2, 409),
        (FieldValue::Undefined, 2, 409),
    ] {
        let events = Events::default();
        let current = Arc::new(Mutex::new(initial));
        let reads = Arc::new(Mutex::new(0));
        let getter: Getter = Arc::new({
            let events = events.clone();
            let current = current.clone();
            let reads = reads.clone();
            move || {
                let mut reads = reads.lock().unwrap();
                *reads += 1;
                events.lock().unwrap().push(format!("status:{reads}"));
                Ok(current.lock().unwrap().clone())
            }
        });
        let value = raw_error(&events, &["APIError"], None, vec![("statusCode", getter)]);
        let mut hook = Hooks::new("handler-throw", value, &events);
        hook.mutate = Some(Arc::new(move || {
            *current.lock().unwrap() = 409.0.into();
            Ok(())
        }));
        let response = hook.run(true, SchemaValue::Undefined).await?;
        assert_eq!(response.status, status);
        assert_eq!(*reads.lock().unwrap(), count);
        let mut expected: Vec<String> = [
            "before",
            "handler",
            "name:1",
            "name:2",
            "name:3",
            "status:1",
            "after",
            "plugin-after",
            "name:4",
            "name:5",
            "name:6",
        ]
        .map(Into::into)
        .into();
        if count == 2 {
            expected.push("status:2".into());
        }
        assert_eq!(*events.lock().unwrap(), expected);
    }
    let events = Events::default();
    let number = Arc::new(Mutex::new(418.0));
    let dynamic: FieldValue = FieldMap::from([(
        "valueOf".into(),
        FieldFunction::contextual({
            let events = events.clone();
            let number = number.clone();
            move |_, arguments| {
                assert!(arguments.is_empty());
                events.lock().unwrap().push("number".into());
                Ok((*number.lock().unwrap()).into())
            }
        })
        .into(),
    )])
    .into();
    let getter: Getter = Arc::new({
        let events = events.clone();
        move || {
            events.lock().unwrap().push("status".into());
            Ok(dynamic.clone())
        }
    });
    let value = raw_error(&events, &["APIError"], None, vec![("statusCode", getter)]);
    let mut hook = Hooks::new("handler-throw", value, &events);
    hook.mutate = Some(Arc::new(move || {
        *number.lock().unwrap() = 409.0;
        Ok(())
    }));
    let response = hook.run(true, SchemaValue::Undefined).await?;
    assert_eq!(response.status, 409);
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "status")
            .count(),
        1
    );
    assert_eq!(
        events.lock().unwrap().last().map(String::as_str),
        Some("number")
    );
    for phase in ["handler-return", "after-throw"] {
        let events = Events::default();
        let number = Arc::new(Mutex::new(202.0));
        let dynamic = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let events = events.clone();
                let number = number.clone();
                move |_, arguments| {
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push("number".into());
                    Ok((*number.lock().unwrap()).into())
                }
            })
            .into(),
        )])
        .into();
        let getter: Getter = Arc::new(|| {
            Err(AuthError::internal(
                "A defined endpoint status suppresses statusCode",
            ))
        });
        let value = raw_error(&events, &["APIError"], None, vec![("statusCode", getter)]);
        let mut hook = Hooks::new(phase, value, &events);
        hook.mutate = Some(Arc::new(move || {
            *number.lock().unwrap() = 207.0;
            Ok(())
        }));
        let response = hook.run(true, SchemaValue::Dynamic(dynamic)).await?;
        assert_eq!(response.status, 207);
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.as_str() == "number")
                .count(),
            1
        );
        assert_eq!(
            events.lock().unwrap().last().map(String::as_str),
            Some("number")
        );
    }
    Ok(())
}

#[tokio::test]
async fn headers_preserve_independent_reads_and_stop_at_the_original_failure() -> AuthResult<()> {
    for failed_read in [None, Some(1), Some(2), Some(3), Some(4)] {
        let events = Events::default();
        let failure: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let convert = FieldFunction::contextual({
            let events = events.clone();
            let failure = failure.clone();
            move |_, arguments| {
                assert!(arguments.is_empty());
                events.lock().unwrap().push("convert".into());
                if failed_read == Some(4) {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok("third".into())
            }
        });
        let final_headers: FieldValue = FieldMap::from([(
            "x-final".into(),
            FieldMap::from([("toString".into(), convert.into())]).into(),
        )])
        .into();
        let getter: Getter = Arc::new({
            let events = events.clone();
            let failure = failure.clone();
            let reads = Mutex::new(0);
            move || {
                let mut reads = reads.lock().unwrap();
                *reads += 1;
                events.lock().unwrap().push(format!("headers:{reads}"));
                if failed_read == Some(*reads) {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok(if *reads < 3 {
                    FieldMap::from([("x-ignored".into(), "first".into())]).into()
                } else {
                    final_headers.clone()
                })
            }
        });
        let value = raw_error(&events, &["APIError"], None, vec![("headers", getter)]);
        let error = Hooks::new("handler-throw", value.clone(), &events)
            .run(false, SchemaValue::Undefined)
            .await
            .unwrap_err();
        assert_raw(
            &error,
            if failed_read.is_some() {
                &failure
            } else {
                &value
            },
        );
        let count = failed_read.unwrap_or(3).min(3);
        let mut expected: Vec<String> = ["before", "handler", "name:1", "name:2", "name:3"]
            .map(Into::into)
            .into();
        expected.extend((1..=count).map(|read| format!("headers:{read}")));
        if failed_read.is_none() || failed_read == Some(4) {
            expected.push("convert".into());
        }
        if failed_read.is_none() {
            expected.extend(["after", "plugin-after", "name:4", "name:5"].map(Into::into));
        }
        assert_eq!(*events.lock().unwrap(), expected);
        if failed_read.is_none() {
            let captured = error
                .to_auth_response()
                .expect("fixture response succeeds")
                .captured_headers()?
                .unwrap();
            assert_headers(
                &captured,
                &[("x-handler", "1"), ("x-after", "1"), ("x-final", "third")],
                &[],
            );
        }
    }
    Ok(())
}

fn observed(
    events: &Events,
    failed_at: Option<&str>,
    failure: &FieldValue,
    label: &str,
    value: FieldValue,
) -> AuthResult<FieldValue> {
    events.lock().unwrap().push(label.into());
    if failed_at == Some(label) {
        Err(AuthError::from_thrown(failure.clone()))
    } else {
        Ok(value)
    }
}

#[test]
fn http_error_conversion_preserves_method_receiver_order_and_original_failures() -> AuthResult<()> {
    let order = [
        "name",
        "body",
        "statusCode",
        "status",
        "method",
        "call",
        "headers",
        "serialize",
    ];
    for failed_at in std::iter::once(None).chain(order.into_iter().map(Some)) {
        let events = Events::default();
        let failure: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let method = FieldFunction::contextual({
            let events = events.clone();
            let failure = failure.clone();
            move |receiver, arguments| {
                assert!(arguments.is_empty());
                assert_eq!(receiver.model_property("marker")?.as_str(), Some("status"));
                observed(&events, failed_at, &failure, "call", "DYNAMIC".into())
            }
        });
        let dynamic = probe(
            FieldMap::from([("marker".into(), "status".into())]),
            vec![(
                "toString",
                Arc::new({
                    let events = events.clone();
                    let failure = failure.clone();
                    move || {
                        observed(
                            &events,
                            failed_at,
                            &failure,
                            "method",
                            method.clone().into(),
                        )
                    }
                }),
            )],
        );
        let body: FieldValue = FieldMap::from([
            ("marker".into(), "body".into()),
            (
                "toJSON".into(),
                FieldFunction::contextual({
                    let events = events.clone();
                    let failure = failure.clone();
                    move |receiver, arguments| {
                        assert_eq!(arguments, &[FieldValue::from("")]);
                        assert_eq!(receiver.model_property("marker")?.as_str(), Some("body"));
                        observed(&events, failed_at, &failure, "serialize", payload())
                    }
                })
                .into(),
            ),
        ])
        .into();
        let getters = [
            ("name", "APIError".into()),
            ("body", body),
            ("statusCode", 418.0.into()),
            ("status", dynamic),
            (
                "headers",
                FieldMap::from([("x-error".into(), "1".into())]).into(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| {
            let events = events.clone();
            let failure = failure.clone();
            let getter: Getter =
                Arc::new(move || observed(&events, failed_at, &failure, name, value.clone()));
            (name, getter)
        })
        .collect();
        let value = probe(FieldMap::new(), getters);
        // Upstream calls toResponse(value) without an endpoint status or header accumulator.
        let result = AuthResponse::native(NativeResponseStatus::Absent, value).into_http_response();
        let count = failed_at.map_or(order.len(), |label| {
            order.iter().position(|event| *event == label).unwrap() + 1
        });
        assert_eq!(*events.lock().unwrap(), order[..count]);
        match (failed_at, result) {
            (Some(_), Err(error)) => assert_raw(&error, &failure),
            (None, Ok(response)) => {
                assert_eq!(response.status, 418);
                assert_eq!(response.status_text, "DYNAMIC".into());
                assert_headers(
                    &response.headers,
                    &[("content-type", "application/json"), ("x-error", "1")],
                    &[],
                );
                assert_eq!(
                    response.body.bytes()?.as_ref(),
                    br#"{"code":"RAW_API_ERROR","message":"raw failure"}"#
                );
            }
            (failure, result) => panic!("Unexpected HTTP conversion: {failure:?}, {result:?}"),
        }
    }
    for status in [
        FieldValue::Null,
        FieldValue::Undefined,
        FieldMap::from([("toString".into(), 1.0.into())]).into(),
    ] {
        let mut fields = error_fields();
        let _ = fields.insert("name".into(), "APIError".into());
        let _ = fields.insert("status".into(), status);
        assert!(matches!(
            AuthResponse::native(NativeResponseStatus::Absent, fields.into()).into_http_response(),
            Err(AuthError::TypeError(_))
        ));
    }
    Ok(())
}
