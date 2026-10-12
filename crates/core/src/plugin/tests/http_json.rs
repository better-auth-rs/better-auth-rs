#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::{AuthError, FieldArray, FieldFunction, field_value::FieldArraySource};
use std::sync::{
    Weak,
    atomic::{AtomicUsize, Ordering},
};

struct SelfArray(Weak<Self>, crate::FieldObject);

impl FieldArraySource for SelfArray {
    fn properties(&self) -> &crate::FieldObject {
        &self.1
    }
    fn len(&self) -> AuthResult<usize> {
        Ok(1)
    }

    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        Ok(vec![0])
    }

    fn get(&self, index: usize, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok((index == 0).then(|| FieldArray::from_source(self.0.upgrade().unwrap()).into()))
    }

    fn own_property_descriptor(
        &self,
        index: usize,
    ) -> AuthResult<Option<crate::FieldPropertyDescriptor>> {
        Ok((index == 0).then(|| {
            crate::FieldPropertyDescriptor::data(
                FieldArray::from_source(self.0.upgrade().unwrap()).into(),
            )
        }))
    }
    fn length_descriptor(&self) -> AuthResult<crate::FieldPropertyDescriptor> {
        Ok(crate::FieldPropertyDescriptor {
            enumerable: false,
            configurable: false,
            property: crate::FieldProperty::Data {
                value: 1.into(),
                writable: true,
            },
        })
    }
    fn set(&self, _: usize, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cyclic fixture does not assign indices",
        ))
    }
    fn define_index(&self, _: usize, _: crate::FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cyclic fixture does not define indices",
        ))
    }
    fn define_length(&self, _: crate::FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cyclic fixture does not define length",
        ))
    }
    fn delete(&self, _: usize) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cyclic fixture does not delete indices",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

type Calls = Arc<Mutex<Vec<(String, FieldValue)>>>;

fn converting(output: FieldValue, calls: &Calls) -> FieldValue {
    let calls = calls.clone();
    FieldMap::from([(
        "toJSON".into(),
        FieldFunction::contextual(move |receiver, arguments| {
            assert_eq!(arguments.len(), 1);
            let key = arguments.first().unwrap().as_str().unwrap();
            calls.lock().unwrap().push((key.into(), receiver.clone()));
            Ok(output.clone())
        })
        .into(),
    )])
    .into()
}

struct Sample {
    value: FieldValue,
    bytes: Option<&'static str>,
    cyclic: bool,
    calls: Calls,
    method: Option<(FieldValue, &'static str)>,
    cleanup: Vec<(FieldValue, &'static str)>,
}

impl Sample {
    fn new(name: &str) -> AuthResult<Self> {
        let root: FieldValue = FieldMap::new().into();
        let mut sample = Self {
            value: root.clone(),
            bytes: None,
            cyclic: true,
            calls: Default::default(),
            method: None,
            cleanup: Vec::new(),
        };
        let fields = root.as_object().unwrap();
        match name {
            "object-self" => {
                fields.set("self", root.clone())?;
                sample.cleanup.push((root.clone(), "self"));
                sample.bytes = Some(r#"{"self":"[Circular ref-0]"}"#);
            }
            "array-self" => {
                sample.value = FieldArray::from_source(Arc::new_cyclic(|weak| {
                    SelfArray(weak.clone(), FieldMap::new().into())
                }))
                .into();
                sample.bytes = Some(r#"["[Circular ref-0]"]"#);
            }
            "indirect" => {
                let child: FieldValue = FieldMap::from([("root".into(), root.clone())]).into();
                fields.set("child", child.clone())?;
                sample.cleanup.push((child, "root"));
                sample.bytes = Some(r#"{"child":{"root":"[Circular ref-0]"}}"#);
            }
            "aliases" => {
                let shared: FieldValue = FieldMap::new().into();
                shared.as_object().unwrap().set("self", shared.clone())?;
                fields.set("first", FieldMap::new().into())?;
                fields.set("a", shared.clone())?;
                fields.set("b", shared.clone())?;
                sample.cleanup.push((shared, "self"));
                sample.bytes = Some(
                    r#"{"first":{},"a":{"self":"[Circular ref-2]"},"b":{"self":"[Circular ref-2]"}}"#,
                );
            }
            "returned-date" => {
                let date = converting(FieldDate::from_milliseconds(0.0).into(), &sample.calls);
                let child: FieldValue = FieldMap::new().into();
                child.as_object().unwrap().set("self", child.clone())?;
                fields.set("date", date.clone())?;
                fields.set("child", child.clone())?;
                sample.method = Some((date, "date"));
                sample.cleanup.push((child, "self"));
                sample.bytes = Some(r#"{"date":{},"child":{"self":"[Circular ref-2]"}}"#);
            }
            "toJSON-ancestor" => {
                let child = converting(root.clone(), &sample.calls);
                fields.set("child", child.clone())?;
                sample.method = Some((child, "child"));
                sample.cleanup.push((root.clone(), "child"));
                sample.bytes = Some(r#"{"child":"[Circular ref-0]"}"#);
            }
            "ordinary-alias" => {
                let shared: FieldValue = FieldMap::from([("leaf".into(), 1.0.into())]).into();
                fields.set("a", shared.clone())?;
                fields.set("b", shared)?;
                sample.bytes = Some(r#"{"a":{"leaf":1},"b":{"leaf":1}}"#);
                sample.cyclic = false;
            }
            "root-undefined" | "root-function" | "root-date" | "root-returned-object" => {
                let output = match name {
                    "root-undefined" => FieldValue::Undefined,
                    "root-function" => FieldFunction::contextual(|_, _| {
                        Err(AuthError::internal(
                            "JSON must not invoke a returned function",
                        ))
                    })
                    .into(),
                    "root-returned-object" => FieldMap::from([
                        (
                            "toJSON".into(),
                            FieldFunction::contextual(|_, _| {
                                Err(AuthError::internal("prepared twice"))
                            })
                            .into(),
                        ),
                        ("kept".into(), 1.0.into()),
                    ])
                    .into(),
                    _ => FieldDate::from_milliseconds(0.0).into(),
                };
                sample.value = converting(output, &sample.calls);
                sample.method = Some((sample.value.clone(), ""));
                sample.bytes = match name {
                    "root-date" => Some("{}"),
                    "root-returned-object" => Some(r#"{"kept":1}"#),
                    _ => None,
                };
                sample.cyclic = false;
            }
            _ => return Err(AuthError::internal("Unknown HTTP JSON sample")),
        }
        Ok(sample)
    }

    fn assert_calls(&self, encoded: bool) {
        let calls = self.calls.lock().unwrap();
        if let Some((receiver, key)) = &self.method
            && encoded
        {
            assert_eq!(calls.len(), 1);
            let (actual_key, actual_receiver) = calls.first().unwrap();
            assert_eq!(actual_key, key);
            assert!(actual_receiver.strict_equals(receiver));
        } else {
            assert!(calls.is_empty());
        }
    }

    fn cleanup(&self) -> AuthResult<()> {
        self.calls.lock().unwrap().clear();
        for (value, property) in &self.cleanup {
            let _ = value.as_object().unwrap().delete(property)?;
        }
        Ok(())
    }
}

fn phase_name(phase: &str) -> &'static str {
    match phase {
        "before-raw" | "before-json" => "before",
        "after-json" => "after",
        _ => "endpoint",
    }
}

fn returned(phase: &str, value: FieldValue) -> AuthResponse {
    if phase == "before-raw" {
        AuthResponse::native(None, value)
    } else {
        AuthResponse::json_value(None, value)
    }
}

async fn dispatch(
    phase: &str,
    returned: AuthResponse,
    http: bool,
    status: Option<u16>,
) -> (AuthResult<AuthResponse>, Vec<ResponseBody>, usize) {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
        .expect("fixture context initializes");
    let hooks = Hooks {
        phase: phase_name(phase),
        returned: returned.clone(),
        observed: Default::default(),
    };
    let route = AuthRoute::get("/http-json-contract", "httpJsonContract");
    let dispatcher = EndpointDispatcher::new(
        Arc::new(vec![Box::new(hooks.clone()) as Box<dyn AuthPlugin<S>>]),
        EndpointHooks {
            before: Some(Arc::new(hooks.clone())),
            after: Some(Arc::new(hooks.clone())),
        },
        [route.clone()],
    );
    let mut request = AuthRequest::new(HttpMethod::Get, "/http-json-contract");
    let endpoint = if phase_name(phase) == "endpoint" {
        returned
    } else {
        AuthResponse::native(
            None,
            FieldMap::from([("endpoint".into(), true.into())]).into(),
        )
    };
    let endpoint_calls = Arc::new(AtomicUsize::new(0));
    let calls = endpoint_calls.clone();
    let handler = move |request: AuthRequest, _context| async move {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        if let Some(status) = status {
            request.set_response_status(status)?;
        }
        Ok(endpoint)
    };
    let result = if http {
        dispatcher
            .run(&mut request, true, &context, None, handler)
            .await
    } else {
        dispatcher.native(request, route, &context, handler).await
    };
    let observed = hooks.observed.lock().unwrap().clone();
    (result, observed, endpoint_calls.load(Ordering::SeqCst))
}

fn assert_observed(phase: &str, observed: &[ResponseBody], value: &FieldValue) {
    if phase_name(phase) == "before" {
        assert!(observed.is_empty());
    } else {
        assert_eq!(observed.len(), 2);
        if phase_name(phase) == "endpoint" {
            same_body(
                observed.first().unwrap(),
                &ResponseBody::Native(value.clone()),
            );
        } else {
            assert_eq!(
                observed.first().unwrap().json().unwrap(),
                Some(serde_json::json!({"endpoint": true}))
            );
        }
        same_body(
            observed.last().unwrap(),
            &ResponseBody::Native(value.clone()),
        );
    }
}

#[tokio::test]
async fn http_json_cycles_aliases_and_method_results_match_pinned_dispatch() -> AuthResult<()> {
    for name in [
        "object-self",
        "array-self",
        "indirect",
        "aliases",
        "returned-date",
        "toJSON-ancestor",
        "ordinary-alias",
        "root-undefined",
        "root-function",
        "root-date",
        "root-returned-object",
    ] {
        for phase in ["before-raw", "before-json", "endpoint", "after-json"] {
            for http in [false, true] {
                let sample = Sample::new(name)?;
                let (result, observed, calls) = dispatch(
                    phase,
                    returned(phase, sample.value.clone()),
                    http,
                    Some(201),
                )
                .await;
                let before = phase_name(phase) == "before";
                assert_eq!(calls, usize::from(!before), "{name}/{phase}/{http}");
                assert_observed(phase, &observed, &sample.value);
                sample.assert_calls(http);
                if http && phase == "before-json" && sample.cyclic {
                    assert!(
                        matches!(result, Err(AuthError::TypeError(ref message))
                        if message == "Converting circular structure to JSON"),
                        "{name}/{phase}"
                    );
                } else {
                    let result = result?;
                    assert_eq!(
                        result.native_status(),
                        if before {
                            NativeResponseStatus::Absent
                        } else {
                            NativeResponseStatus::Present(crate::SchemaValue::Typed(201))
                        },
                        "{name}/{phase}/{http}"
                    );
                    if http {
                        assert_eq!(
                            result.status,
                            if before { 200 } else { 201 },
                            "{name}/{phase}"
                        );
                        assert_eq!(
                            result.headers.get("content-type").map(String::as_str),
                            Some("application/json")
                        );
                        assert_eq!(
                            result.body.bytes()?.as_ref(),
                            sample.bytes.unwrap_or_default().as_bytes(),
                            "{name}/{phase}"
                        );
                        assert_eq!(
                            matches!(result.body, ResponseBody::Empty),
                            sample.bytes.is_none(),
                            "{name}/{phase}"
                        );
                    } else {
                        assert!(result.is_native());
                        same_body(&result.body, &ResponseBody::Native(sample.value.clone()));
                    }
                }
                if name == "ordinary-alias" {
                    assert!(
                        sample
                            .value
                            .model_property("a")?
                            .strict_equals(&sample.value.model_property("b")?)
                    );
                }
                sample.cleanup()?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn http_before_json_wraps_scalars_while_native_and_raw_returns_fall_through() -> AuthResult<()>
{
    for (name, value, bytes) in [
        ("undefined", FieldValue::Undefined, None),
        ("null", FieldValue::Null, Some("null")),
        ("empty-string", "".into(), Some(r#""""#)),
        ("string", "text".into(), Some(r#""text""#)),
        ("false", false.into(), Some("false")),
        ("zero", 0.0.into(), Some("0")),
    ] {
        for phase in ["before-raw", "before-json"] {
            for http in [false, true] {
                let short = phase == "before-json" && http;
                let (result, observed, calls) =
                    dispatch(phase, returned(phase, value.clone()), http, Some(201)).await;
                let result = result?;
                assert_eq!(calls, usize::from(!short), "{name}/{phase}/{http}");
                assert_eq!(result.status, if short { 200 } else { 201 });
                assert_eq!(
                    result.native_status(),
                    if short {
                        NativeResponseStatus::Absent
                    } else {
                        NativeResponseStatus::Present(crate::SchemaValue::Typed(201))
                    }
                );
                if short {
                    assert!(observed.is_empty());
                } else {
                    assert_eq!(observed.len(), 2);
                    let first = observed.first().unwrap();
                    assert!(matches!(first, ResponseBody::Native(_)));
                    assert_eq!(first.json()?, Some(serde_json::json!({"endpoint": true})));
                    same_body(first, observed.last().unwrap());
                }
                if http {
                    assert_eq!(
                        result.headers.get("content-type").map(String::as_str),
                        Some("application/json")
                    );
                    assert_eq!(
                        matches!(result.body, ResponseBody::Empty),
                        short && bytes.is_none()
                    );
                    assert_eq!(
                        result.body.bytes()?.as_ref(),
                        if short {
                            bytes.unwrap_or_default().as_bytes()
                        } else {
                            br#"{"endpoint":true}"#
                        },
                        "{name}/{phase}"
                    );
                } else {
                    assert!(result.is_native());
                    same_body(&result.body, observed.first().unwrap());
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn json_errors_keep_original_allocation_before_invalid_http_status() -> AuthResult<()> {
    for phase in ["before-raw", "before-json", "endpoint", "after-json"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let allocation = Arc::new(AtomicUsize::new(0));
        let value: FieldValue = FieldMap::from([(
            "toJSON".into(),
            FieldFunction::contextual({
                let calls = calls.clone();
                let allocation = allocation.clone();
                move |receiver, arguments| {
                    assert_eq!(arguments.len(), 1);
                    assert_eq!(arguments.first().unwrap().as_str(), Some(""));
                    calls.lock().unwrap().push(receiver.clone());
                    let message = "original HTTP JSON method error".to_owned();
                    allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
                    Err(AuthError::Internal(message))
                }
            })
            .into(),
        )])
        .into();
        let (native, observed, endpoint_calls) =
            dispatch(phase, returned(phase, value.clone()), false, Some(199)).await;
        assert_eq!(endpoint_calls, usize::from(phase_name(phase) != "before"));
        let native = native?;
        same_body(&native.body, &ResponseBody::Native(value.clone()));
        assert_eq!(
            native.native_status(),
            if phase_name(phase) == "before" {
                NativeResponseStatus::Absent
            } else {
                NativeResponseStatus::Present(crate::SchemaValue::Typed(199))
            }
        );
        assert_observed(phase, &observed, &value);
        assert!(calls.lock().unwrap().is_empty());
        let (result, observed, endpoint_calls) =
            dispatch(phase, returned(phase, value.clone()), true, Some(199)).await;
        assert_eq!(endpoint_calls, usize::from(phase_name(phase) != "before"));
        assert_observed(phase, &observed, &value);
        let error = result.unwrap_err();
        assert!(matches!(&error, AuthError::Internal(message)
            if message == "original HTTP JSON method error"
                && message.as_ptr() as usize == allocation.load(Ordering::SeqCst)));
        let mut calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls.first().unwrap().strict_equals(&value));
        calls.clear();
    }
    let sample = Sample::new("root-date")?;
    let error = AuthResponse::native(199, sample.value.clone())
        .into_http_response()
        .unwrap_err();
    sample.assert_calls(true);
    assert!(matches!(error, AuthError::RangeError(ref message)
        if message == "The status provided (199) must be 101 or in the range of [200, 599]"));
    sample.cleanup()?;
    Ok(())
}

#[tokio::test]
async fn api_error_and_explicit_responses_keep_their_http_paths() -> AuthResult<()> {
    for phase in ["before-raw", "before-json", "endpoint", "after-json"] {
        let sample = Sample::new("object-self")?;
        let response = AuthError::from(AuthResponse::json_value(418, sample.value.clone()))
            .to_auth_response()
            .expect("fixture response succeeds");
        let raw_error = response.body.field_value()?;
        assert!(
            raw_error
                .model_property("body")?
                .strict_equals(&sample.value)
        );
        let (result, observed, calls) = dispatch(phase, response, true, None).await;
        assert_eq!(calls, usize::from(phase_name(phase) != "before"));
        let result = result?;
        assert_eq!(result.status, 418);
        assert!(!result.is_api_error()?);
        assert_eq!(
            result.body.bytes()?.as_ref(),
            sample.bytes.unwrap().as_bytes()
        );
        assert_observed(phase, &observed, &raw_error);
        for returned in &observed {
            let value = returned.field_value()?;
            if value.strict_equals(&raw_error) {
                assert!(value.model_property("body")?.strict_equals(&sample.value));
                assert_eq!(value.model_property("statusCode")?, 418.0.into());
            }
        }
        sample.cleanup()?;
        for http in [false, true] {
            let response = AuthResponse::text(207, "explicit").with_header("x-owned", "retained");
            let (result, observed, calls) = dispatch(phase, response, http, Some(199)).await;
            assert_eq!(calls, usize::from(phase_name(phase) != "before"));
            let result = result?;
            assert!(!result.is_native());
            assert_eq!(result.status, 207);
            assert_eq!(result.body.bytes()?.as_ref(), b"explicit");
            let headers = if http {
                &result.headers
            } else {
                result.explicit_response_headers().unwrap()
            };
            assert_eq!(headers.get("x-owned").map(String::as_str), Some("retained"));
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some(if http && phase_name(phase) == "before" {
                    "application/queued"
                } else {
                    "text/plain"
                })
            );
            assert_eq!(
                observed.len(),
                if phase_name(phase) == "before" { 0 } else { 2 }
            );
        }
    }
    Ok(())
}

#[test]
fn strict_json_retains_cycle_errors_after_http_safe_serialization() -> AuthResult<()> {
    for name in [
        "object-self",
        "array-self",
        "indirect",
        "aliases",
        "returned-date",
        "toJSON-ancestor",
    ] {
        let sample = Sample::new(name)?;
        let response = AuthResponse::native(None, sample.value.clone()).into_http_response()?;
        assert_eq!(
            response.body.bytes()?.as_ref(),
            sample.bytes.unwrap().as_bytes()
        );
        sample.assert_calls(true);
        sample.calls.lock().unwrap().clear();
        assert!(
            matches!(sample.value.stringify(), Err(AuthError::TypeError(ref message))
            if message == "Converting circular structure to JSON"),
            "{name}"
        );
        sample.assert_calls(true);
        sample.cleanup()?;
    }
    Ok(())
}
