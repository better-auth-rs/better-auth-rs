#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired response contracts require exact native identity and complete HTTP observations."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    FieldDate, FieldMap, FieldValue, HttpMethod, NativeResponseStatus, ResponseBlob, ResponseBody,
    Utf16String,
    endpoint_dispatch::EndpointDispatcher,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema as S},
};

#[derive(Clone)]
struct Hooks {
    phase: &'static str,
    returned: AuthResponse,
    observed: Arc<Mutex<Vec<ResponseBody>>>,
}

#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.phase == "before" {
            request.set_response_header("x-before", "1")?;
            request.set_response_header("authorization", "queued")?;
            request.set_response_header("content-type", "application/queued")?;
            Ok(Some(BeforeRequestAction::Respond(self.returned.clone())))
        } else {
            Ok(None)
        }
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
        self.observed.lock().unwrap().push(response.body.clone());
        request.set_response_header("x-after", "1")?;
        if self.phase == "after" {
            response.replace_returned(self.returned.clone());
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Hooks {
    fn name(&self) -> &'static str {
        "response-values"
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
        self.observed.lock().unwrap().push(response.body.clone());
        Ok(())
    }
}

fn same_body(actual: &ResponseBody, expected: &ResponseBody) {
    match (actual, expected) {
        (ResponseBody::Native(actual), ResponseBody::Native(expected)) => {
            assert!(actual.same_value_zero(expected))
        }
        (ResponseBody::Binary(actual), ResponseBody::Binary(expected)) => {
            assert!(Arc::ptr_eq(actual, expected))
        }
        (ResponseBody::Blob(actual), ResponseBody::Blob(expected)) => {
            assert!(Arc::ptr_eq(actual, expected))
        }
        (ResponseBody::Bytes(actual), ResponseBody::Bytes(expected)) => {
            assert_eq!(actual, expected)
        }
        (ResponseBody::Empty, ResponseBody::Empty) => {}
        _ => panic!("Different native kinds: {actual:?}, {expected:?}"),
    }
}

#[tokio::test]
async fn native_values_and_http_bodies_match_the_pinned_response_contract() -> AuthResult<()> {
    let date = FieldValue::Date(FieldDate::from_milliseconds(0.0));
    let values = [
        ("undefined", FieldValue::Undefined, "application/json", ""),
        ("null", FieldValue::Null, "application/json", "null"),
        ("false", false.into(), "application/json", "false"),
        ("true", true.into(), "application/json", "true"),
        ("zero", 0.0.into(), "application/json", "0"),
        ("negative-zero", (-0.0).into(), "application/json", "0"),
        ("number", 1.25.into(), "application/json", "1.25"),
        ("nan", f64::NAN.into(), "application/json", "NaN"),
        ("infinity", f64::INFINITY.into(), "application/json", "null"),
        (
            "negative-infinity",
            f64::NEG_INFINITY.into(),
            "application/json",
            "null",
        ),
        ("empty-string", "".into(), "application/json", ""),
        ("string", "hello 中".into(), "text/plain", "hello 中"),
        (
            "utf16",
            Utf16String::from_units(vec![0xd800, 65, 0xdc00]).into(),
            "text/plain",
            "�A�",
        ),
        (
            "array",
            vec![FieldValue::Undefined, f64::NAN.into(), date.clone()].into(),
            "application/json",
            "[null,null,\"1970-01-01T00:00:00.000Z\"]",
        ),
        (
            "object",
            FieldMap::from([
                ("value".into(), "hello".into()),
                ("omitted".into(), FieldValue::Undefined),
            ])
            .into(),
            "application/json",
            "{\"value\":\"hello\"}",
        ),
        (
            "date",
            date,
            "application/json",
            "\"1970-01-01T00:00:00.000Z\"",
        ),
        (
            "invalid-date",
            FieldDate::invalid().into(),
            "application/json",
            "null",
        ),
    ];
    let mut cases: Vec<_> = values
        .into_iter()
        .map(|(name, value, content_type, body)| {
            (
                name,
                AuthResponse::native(None, value),
                content_type,
                body.as_bytes().to_vec(),
            )
        })
        .collect();
    cases.push((
        "binary",
        AuthResponse::binary(None, vec![0, 255, 65]),
        "application/octet-stream",
        vec![0, 255, 65],
    ));
    for (name, mime, expected) in [
        ("blob", "IMAGE/PNG", "image/png"),
        ("blob-json-type", "APPLICATION/JSON", "application/json"),
        ("blob-empty-type", "", "application/octet-stream"),
        ("blob-invalid-type", "text/中", "application/octet-stream"),
    ] {
        cases.push((
            name,
            AuthResponse::blob(None, ResponseBlob::new(vec![0, 255, 65], mime)),
            expected,
            vec![0, 255, 65],
        ));
    }
    cases.push((
        "response",
        AuthResponse::text(207, "explicit"),
        "text/plain",
        b"explicit".to_vec(),
    ));
    cases.push((
        "html",
        AuthResponse::html(207, "<p>explicit</p>"),
        "text/html; charset=utf-8",
        b"<p>explicit</p>".to_vec(),
    ));
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let fallback = AuthResponse::json(None, &serde_json::json!({"endpoint":true}))?;
    for (name, returned, content_type, bytes) in cases {
        for phase in ["endpoint", "before", "after"] {
            for http in [false, true] {
                let hooks = Hooks {
                    phase,
                    returned: returned.clone(),
                    observed: Default::default(),
                };
                let route = AuthRoute::get("/value-contract", "valueContract");
                let dispatcher = EndpointDispatcher::new(
                    Arc::new(vec![Box::new(hooks.clone()) as Box<dyn AuthPlugin<S>>]),
                    EndpointHooks {
                        before: Some(Arc::new(hooks.clone())),
                        after: Some(Arc::new(hooks.clone())),
                    },
                    [route.clone()],
                );
                let mut request = AuthRequest::new(HttpMethod::Get, "/value-contract");
                let endpoint = if phase == "endpoint" {
                    returned.clone()
                } else {
                    fallback.clone()
                };
                let initial = endpoint.body.clone();
                let handler = move |request: AuthRequest| async move {
                    request.set_response_status(201)?;
                    request.set_response_header("x-endpoint", "1")?;
                    request.set_response_header("authorization", "queued")?;
                    request.set_response_header("content-type", "application/queued")?;
                    Ok(endpoint)
                };
                let result = if http {
                    dispatcher
                        .run(&mut request, true, &context, None, handler)
                        .await?
                } else {
                    dispatcher.native(request, route, &context, handler).await?
                };
                let short = phase == "before" && returned.stops_before_hooks();
                let ignored =
                    (phase == "before" && !short) || (phase == "after" && name == "undefined");
                let expected = if ignored { &fallback } else { &returned };
                let explicit = matches!(name, "response" | "html") && !ignored;
                assert_eq!(
                    result.status,
                    if explicit {
                        207
                    } else if short {
                        200
                    } else {
                        201
                    },
                    "{name}/{phase}/{http}"
                );
                assert_eq!(
                    result.native_status(),
                    if short {
                        NativeResponseStatus::Absent
                    } else {
                        NativeResponseStatus::Value(201)
                    }
                );
                let observed = hooks.observed.lock().unwrap();
                if short {
                    assert!(observed.is_empty());
                } else {
                    assert_eq!(observed.len(), 2);
                    same_body(&observed[0], &initial);
                    same_body(&observed[1], &expected.body);
                }
                assert_eq!(result.headers.get("x-before").is_some(), short);
                assert_eq!(result.headers.get("x-after").is_some(), !short);
                assert_eq!(result.headers.get("x-endpoint").is_some(), !short);
                if http {
                    assert!(!result.is_native());
                    assert_eq!(result.headers.get("authorization"), None);
                    let expected_type = if explicit {
                        "application/queued"
                    } else if ignored {
                        "application/json"
                    } else {
                        content_type
                    };
                    assert_eq!(
                        result.headers.get("content-type").map(String::as_str),
                        Some(expected_type),
                        "{name}/{phase}"
                    );
                    assert_eq!(
                        result.is_json(),
                        expected_type.starts_with("application/json")
                    );
                    assert_eq!(
                        result.body.bytes()?.as_ref(),
                        if ignored {
                            b"{\"endpoint\":true}".as_slice()
                        } else {
                            &bytes
                        }
                    );
                    assert!(matches!(
                        result.body,
                        ResponseBody::Empty | ResponseBody::Bytes(_)
                    ));
                } else {
                    assert_eq!(result.is_native(), !explicit);
                    if !explicit {
                        assert_eq!(
                            result.is_json(),
                            ignored || content_type.starts_with("application/json")
                        );
                    }
                    same_body(&result.body, &expected.body);
                    assert_eq!(
                        result.headers.get("authorization").map(String::as_str),
                        Some("queued")
                    );
                    assert_eq!(
                        result.headers.get("content-type").map(String::as_str),
                        Some("application/queued")
                    );
                    if explicit {
                        assert_eq!(
                            result
                                .explicit_response_headers()
                                .unwrap()
                                .get("content-type")
                                .map(String::as_str),
                            Some(content_type)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn materialization_preserves_bun_status_and_body_construction() -> AuthResult<()> {
    for status in [101, 200, 204, 205, 304, 599] {
        for (value, bytes, null_body) in [
            (FieldValue::Undefined, "", true),
            (FieldValue::Null, "null", false),
            ("".into(), "", false),
            (false.into(), "false", false),
            (0.0.into(), "0", false),
        ] {
            let native = AuthResponse::native(status, value.clone());
            same_body(&native.body, &ResponseBody::Native(value));
            assert_eq!(native.native_status(), NativeResponseStatus::Value(status));
            assert!(native.headers.is_empty());
            let response = native.into_http_response()?;
            for response in [response.clone(), response.into_http_response()?] {
                assert_eq!(response.status, status);
                assert!(!response.is_native());
                assert_eq!(
                    response.headers.into_iter().collect::<Vec<_>>(),
                    vec![("content-type".into(), "application/json".into())]
                );
                assert_eq!(matches!(response.body, ResponseBody::Empty), null_body);
                assert_eq!(response.body.bytes()?.as_ref(), bytes.as_bytes());
            }
        }
        assert!(matches!(
            AuthResponse::new(status).into_http_response()?.body,
            ResponseBody::Empty
        ));
        let explicit = AuthResponse::text(status, "").into_http_response()?;
        assert_eq!(explicit.status, status);
        assert!(matches!(explicit.body, ResponseBody::Bytes(ref bytes) if bytes.is_empty()));
        assert_eq!(
            explicit.headers.into_iter().collect::<Vec<_>>(),
            vec![("content-type".into(), "text/plain".into())]
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_response_status_preserves_native_values_and_range_errors() -> AuthResult<()> {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let route = AuthRoute::get("/invalid-response-status", "invalidResponseStatus");
    let dispatcher =
        EndpointDispatcher::new(Arc::new(vec![]), EndpointHooks::default(), [route.clone()]);
    let value: FieldValue = FieldMap::from([("retained".into(), true.into())]).into();
    for status in [0, 100, 102, 199, 600, u16::MAX] {
        let request = AuthRequest::new(HttpMethod::Get, "/invalid-response-status");
        let output = AuthResponse::native(status, value.clone());
        let native = dispatcher
            .native(
                request.clone(),
                route.clone(),
                &context,
                move |_| async move { Ok(output) },
            )
            .await?;
        assert_eq!(native.native_status(), NativeResponseStatus::Value(status));
        same_body(&native.body, &ResponseBody::Native(value.clone()));
        let mut request = request;
        let error = dispatcher
            .run(&mut request, true, &context, None, move |_| async move {
                Ok(native)
            })
            .await
            .unwrap_err();
        let message =
            format!("The status provided ({status}) must be 101 or in the range of [200, 599]");
        assert!(matches!(&error, crate::AuthError::RangeError(actual) if actual == &message));
        assert_eq!(error.to_string(), message);
        assert_eq!(error.instrumentation_message(), message);
        assert!(!error.is_api_error());
        assert_eq!(error.status_code(), 500);
        let response = error.to_http_response()?;
        assert_eq!(response.status, 500);
        assert!(response.headers.is_empty());
        assert!(matches!(response.body, ResponseBody::Empty));
    }
    Ok(())
}

#[test]
fn materialization_preserves_binary_and_utf16_boundaries() -> AuthResult<()> {
    for body in [
        ResponseBody::Binary(Arc::from([1, 2])),
        ResponseBody::Blob(Arc::new(ResponseBlob::new(vec![1, 2], ""))),
    ] {
        assert!(matches!(
            body.field_value(),
            Err(crate::AuthError::TypeError(_))
        ));
        assert!(matches!(body.json(), Err(crate::AuthError::TypeError(_))));
    }
    let value = AuthResponse::json(None, &Utf16String::from_units(vec![0xd800]))?;
    assert_eq!(
        value.body.field_value()?,
        Utf16String::from_units(vec![0xd800]).into()
    );
    assert_eq!(
        value.into_http_response()?.body.bytes()?.as_ref(),
        "�".as_bytes()
    );
    let object: FieldValue = FieldMap::from([
        ("text".into(), Utf16String::from_units(vec![0xd800]).into()),
        ("date".into(), "2030-01-01T00:00:00.000Z".into()),
    ])
    .into();
    let response = AuthResponse::json(None, &object)?.into_http_response()?;
    assert_eq!(response.body.field_value()?, object);
    Ok(())
}
