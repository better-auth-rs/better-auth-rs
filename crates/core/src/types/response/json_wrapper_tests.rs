#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired wrapper contracts assert exact getter order, runtime identity, and HTTP output."
)]

use crate::{
    AuthError, AuthResponse, AuthResult, FieldArray, FieldFunction, FieldMap, FieldObject,
    FieldValue, Headers, ResponseBody, field_value::FieldObjectSource,
};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

fn wrapper(
    body: FieldValue,
    router: FieldValue,
    headers: FieldValue,
    status: FieldValue,
) -> FieldValue {
    FieldMap::from([
        ("_flag".into(), "json".into()),
        ("body".into(), body),
        ("routerResponse".into(), router),
        ("headers".into(), headers),
        ("status".into(), status),
    ])
    .into()
}

fn bare(body: FieldValue) -> FieldValue {
    wrapper(
        body,
        FieldValue::Undefined,
        FieldValue::Undefined,
        FieldValue::Undefined,
    )
}

fn observation(headers: &Headers) -> (Vec<(String, String)>, Vec<String>) {
    let mut ordinary: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.as_str() != "set-cookie")
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    ordinary.sort();
    (ordinary, headers.get_all("set-cookie").cloned().collect())
}

#[test]
fn raw_json_wrappers_encode_the_body_once_and_preserve_native_identity() -> AuthResult<()> {
    for (body, bytes) in [
        (FieldValue::Undefined, None),
        (FieldValue::Null, Some("null")),
        (false.into(), Some("false")),
        (0.0.into(), Some("0")),
        ("".into(), Some(r#""""#)),
        ("text".into(), Some(r#""text""#)),
        (
            bare("nested".into()),
            Some(r#"{"_flag":"json","body":"nested"}"#),
        ),
    ] {
        let value = bare(body);
        let native = AuthResponse::native(None, value.clone());
        assert!(native.body.field_value()?.strict_equals(&value));
        let response = native.into_http_response()?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            matches!(response.body, ResponseBody::Empty),
            bytes.is_none()
        );
        assert_eq!(
            response.body.bytes()?.as_ref(),
            bytes.unwrap_or_default().as_bytes()
        );
    }
    let value = bare("nested".into());
    let mut before = AuthResponse::json_value(None, value);
    before.prepare_before_return(true);
    assert_eq!(
        before.into_http_response()?.body.bytes()?.as_ref(),
        br#"{"_flag":"json","body":"nested"}"#
    );
    let cycle: FieldValue = FieldMap::new().into();
    cycle.as_object().unwrap().set("self", cycle.clone())?;
    let error = AuthResponse::native(None, bare(cycle.clone()))
        .into_http_response()
        .unwrap_err();
    assert!(
        matches!(error, AuthError::TypeError(ref message) if message == "Converting circular structure to JSON")
    );
    let _ = cycle.as_object().unwrap().delete("self")?;
    Ok(())
}

#[test]
fn wrapper_headers_merge_in_upstream_order_and_strip_only_endpoint_headers() -> AuthResult<()> {
    let router: FieldValue = FieldMap::from([
        (
            "headers".into(),
            FieldMap::from([
                ("x-router".into(), "router".into()),
                ("x-shared".into(), "router".into()),
                ("set-cookie".into(), "router=1".into()),
                ("authorization".into(), "router-credential".into()),
            ])
            .into(),
        ),
        ("status".into(), 203.0.into()),
    ])
    .into();
    let headers: FieldValue = vec![
        vec!["x-data".into(), "data".into()].into(),
        vec!["x-shared".into(), "data".into()].into(),
        vec!["set-cookie".into(), "data=1".into()].into(),
        vec!["cookie".into(), "a=1".into()].into(),
        vec!["Cookie".into(), "b=2".into()].into(),
        vec!["x-repeat".into(), " a ".into()].into(),
        vec!["X-Repeat".into(), "b".into()].into(),
    ]
    .into();
    let value = wrapper("body".into(), router, headers, 202.0.into());
    let response = AuthResponse::native(201, value)
        .with_header("x-init", "init")
        .with_header("x-shared", "init")
        .with_header("authorization", "removed")
        .with_header("content-type", "overridden")
        .with_appended_header("set-cookie", "init=1")
        .into_http_response()?;
    assert_eq!(response.status, 202);
    assert_eq!(response.body.bytes()?.as_ref(), br#""body""#);
    assert_eq!(
        observation(&response.headers),
        (
            [
                ("authorization", "router-credential"),
                ("content-type", "application/json"),
                ("cookie", "a=1; b=2"),
                ("x-data", "data"),
                ("x-init", "init"),
                ("x-repeat", "a, b"),
                ("x-router", "router"),
                ("x-shared", "init"),
            ]
            .map(|(name, value)| (name.into(), value.into()))
            .to_vec(),
            vec!["router=1".into(), "data=1".into(), "init=1".into()]
        )
    );
    Ok(())
}

#[test]
fn wrapper_status_preserves_nullish_priority_and_bun_numeric_coercion() -> AuthResult<()> {
    for (data, init, router, expected) in [
        (FieldValue::Undefined, None, FieldValue::Undefined, Ok(200)),
        (FieldValue::Undefined, None, 203.0.into(), Ok(203)),
        (FieldValue::Null, Some(201), 203.0.into(), Ok(201)),
        (202.0.into(), Some(201), 203.0.into(), Ok(202)),
        ("202.9".into(), Some(201), 203.0.into(), Ok(202)),
        ("4294967497".into(), None, FieldValue::Undefined, Ok(201)),
        (
            4_294_967_497.0.into(),
            None,
            FieldValue::Undefined,
            Err(4_294_967_497_i64),
        ),
        (false.into(), Some(201), 203.0.into(), Err(0)),
        (FieldValue::Undefined, None, FieldValue::Null, Err(0)),
        (199.9.into(), None, FieldValue::Undefined, Err(199)),
    ] {
        let router = FieldMap::from([("status".into(), router)]).into();
        let result = AuthResponse::native(
            init,
            wrapper(true.into(), router, FieldValue::Undefined, data),
        )
        .into_http_response();
        match expected {
            Ok(status) => assert_eq!(result?.status, status),
            Err(number) => assert!(matches!(result, Err(AuthError::RangeError(message))
                if message == format!("The status provided ({number}) must be 101 or in the range of [200, 599]"))),
        }
    }
    Ok(())
}

struct Getters {
    label: &'static str,
    fields: FieldMap,
    events: Events,
    failure: Option<&'static str>,
}

impl FieldObjectSource for Getters {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        crate::FieldObject::from(self.fields.clone()).own_keys()
    }
    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .get(name)
            .cloned()
            .map(crate::field_value::FieldPropertyDescriptor::data))
    }
    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let Some(value) = self.fields.get(name) else {
            return Ok(None);
        };
        let event = format!("{}.{}", self.label, name);
        record(&self.events, self.failure, &event)?;
        Ok(Some(value.clone()))
    }
    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("Wrapper fixture is read-only"))
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("Wrapper fixture is read-only"))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.fields
            .keys()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(name, &FieldValue::Undefined)?
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
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

fn record(events: &Events, failure: Option<&str>, event: &str) -> AuthResult<()> {
    events.lock().unwrap().push(event.into());
    if failure == Some(event) {
        Err(AuthError::internal(format!("original {event} error")))
    } else {
        Ok(())
    }
}

fn getters(
    label: &'static str,
    fields: FieldMap,
    events: &Events,
    failure: Option<&'static str>,
) -> FieldValue {
    FieldValue::Object(FieldObject::from_source(Arc::new(Getters {
        label,
        fields,
        events: events.clone(),
        failure,
    })))
}

fn converting(
    method: &str,
    event: &'static str,
    output: FieldValue,
    events: &Events,
    failure: Option<&'static str>,
) -> FieldValue {
    let events = events.clone();
    FieldMap::from([(
        method.into(),
        FieldFunction::contextual(move |_, arguments| {
            if method_name(event) == "toJSON" {
                assert_eq!(arguments.len(), 1);
                assert_eq!(arguments.first().unwrap().as_str(), Some(""));
            } else {
                assert!(arguments.is_empty());
            }
            record(&events, failure, event)?;
            Ok(output.clone())
        })
        .into(),
    )])
    .into()
}

fn method_name(event: &str) -> &str {
    event.rsplit('.').next().unwrap()
}

#[test]
fn wrapper_getters_and_failures_keep_json_before_spread_and_init_conversion() -> AuthResult<()> {
    let expected = [
        "data._flag",
        "data.body",
        "data.routerResponse",
        "router.headers",
        "data.headers",
        "body.toJSON",
        "router.headers",
        "router.status",
        "router.extra",
        "router.statusText",
        "router.method",
        "data.status",
        "router.status",
        "router.statusText",
        "status.valueOf",
        "statusText.toString",
        "method.toString",
    ];
    for failure in std::iter::once(None).chain(expected.into_iter().map(Some)) {
        let events = Events::default();
        let body = converting(
            "toJSON",
            "body.toJSON",
            FieldMap::from([("kept".into(), 1.0.into())]).into(),
            &events,
            failure,
        );
        let router = getters(
            "router",
            FieldMap::from([
                ("headers".into(), FieldMap::new().into()),
                (
                    "status".into(),
                    converting("valueOf", "status.valueOf", 202.0.into(), &events, failure),
                ),
                ("extra".into(), true.into()),
                (
                    "statusText".into(),
                    converting(
                        "toString",
                        "statusText.toString",
                        "Custom\r\n中".into(),
                        &events,
                        failure,
                    ),
                ),
                (
                    "method".into(),
                    converting(
                        "toString",
                        "method.toString",
                        "GET".into(),
                        &events,
                        failure,
                    ),
                ),
            ]),
            &events,
            failure,
        );
        let value = getters(
            "data",
            FieldMap::from([
                ("_flag".into(), "json".into()),
                ("body".into(), body),
                ("routerResponse".into(), router),
                ("headers".into(), FieldMap::new().into()),
                ("status".into(), FieldValue::Undefined),
            ]),
            &events,
            failure,
        );
        let native = AuthResponse::native(None, value.clone());
        assert!(native.body.field_value()?.strict_equals(&value));
        assert!(events.lock().unwrap().is_empty());
        let result = native.into_http_response();
        let count = if let Some(failed) = failure {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == format!("original {failed} error"))
            );
            expected.iter().position(|event| *event == failed).unwrap() + 1
        } else {
            let result = result?;
            assert_eq!(result.status, 202);
            assert_eq!(result.body.bytes()?.as_ref(), br#"{"kept":1}"#);
            expected.len()
        };
        assert_eq!(
            *events.lock().unwrap(),
            expected
                .iter()
                .take(count)
                .map(|event| (*event).to_owned())
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn headers_convert_all_dom_strings_before_validating_names_and_values() -> AuthResult<()> {
    for sequence in [false, true] {
        for failure in [None, Some("later.toString")] {
            let events = Events::default();
            let first = converting(
                "toString",
                "first.toString",
                "value".into(),
                &events,
                failure,
            );
            let later = converting(
                "toString",
                "later.toString",
                "value".into(),
                &events,
                failure,
            );
            let headers: FieldValue = if sequence {
                vec![
                    vec!["bad name".into(), first].into(),
                    vec!["later".into(), later].into(),
                ]
                .into()
            } else {
                FieldMap::from([("bad name".into(), first), ("later".into(), later)]).into()
            };
            let error = AuthResponse::native(
                None,
                wrapper(
                    true.into(),
                    FieldValue::Undefined,
                    headers,
                    FieldValue::Undefined,
                ),
            )
            .into_http_response()
            .unwrap_err();
            if failure.is_some() {
                assert!(
                    matches!(error, AuthError::Internal(ref message) if message == "original later.toString error")
                );
            } else {
                assert!(
                    matches!(error, AuthError::TypeError(ref message) if message == "Invalid header name: 'bad name'")
                );
            }
            assert_eq!(
                *events.lock().unwrap(),
                ["first.toString", "later.toString"]
            );
        }
    }
    for (name, value, message) in [
        (
            "x-bad",
            "one\ntwo",
            "Header 'x-bad' has invalid value: 'one\ntwo'",
        ),
        ("x-bad", "中", "Header 'x-bad' has invalid value: '中'"),
    ] {
        let headers = FieldMap::from([(name.into(), value.into())]).into();
        assert!(
            matches!(AuthResponse::native(None, wrapper(true.into(), FieldValue::Undefined, headers, FieldValue::Undefined)).into_http_response(),
            Err(AuthError::TypeError(actual)) if actual == message)
        );
    }
    Ok(())
}

#[test]
fn header_record_rechecks_deleted_fields_and_keeps_explicit_undefined() -> AuthResult<()> {
    let headers: FieldValue = FieldMap::new().into();
    let fields = headers.as_object().unwrap();
    let first: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let headers = headers.clone();
            move |_, arguments| {
                assert!(arguments.is_empty());
                let _ = headers.as_object().unwrap().delete("removed")?;
                Ok("first".into())
            }
        })
        .into(),
    )])
    .into();
    fields.set("first", first)?;
    fields.set("removed", "never copied".into())?;
    fields.set("explicit", FieldValue::Undefined)?;
    let response = AuthResponse::native(
        None,
        wrapper(
            true.into(),
            FieldValue::Undefined,
            headers.clone(),
            FieldValue::Undefined,
        ),
    )
    .into_http_response()?;
    assert_eq!(
        observation(&response.headers),
        (
            vec![
                ("content-type".into(), "application/json".into()),
                ("explicit".into(), "undefined".into()),
                ("first".into(), "first".into()),
            ],
            Vec::new(),
        )
    );
    let _ = fields.delete("first")?;
    Ok(())
}

#[test]
fn typed_init_headers_validate_before_stripping_on_each_http_path() -> AuthResult<()> {
    for (name, value, message) in [
        ("bad name", "value", "Invalid header name: 'bad name'"),
        (
            "x-invalid",
            "one\ntwo",
            "Header 'x-invalid' has invalid value: 'one\ntwo'",
        ),
        (
            "authorization",
            "one\ntwo",
            "Header 'Authorization' has invalid value: 'one\ntwo'",
        ),
        (
            "AUTHORIZATION",
            "one\ntwo",
            "Header 'Authorization' has invalid value: 'one\ntwo'",
        ),
        (
            "eTaG",
            "one\ntwo",
            "Header 'ETag' has invalid value: 'one\ntwo'",
        ),
        (
            "X-Unknown",
            "one\ntwo",
            "Header 'X-Unknown' has invalid value: 'one\ntwo'",
        ),
    ] {
        for phase in ["native", "wrapper", "before-json", "explicit"] {
            let mut response = match phase {
                "wrapper" => AuthResponse::native(None, bare(true.into())),
                "before-json" => {
                    let mut response = AuthResponse::json_value(None, true.into());
                    response.prepare_before_return(true);
                    response
                }
                "explicit" => AuthResponse::text(207, "explicit").with_header("x-owned", "kept"),
                _ => AuthResponse::native(None, true.into()),
            };
            let mut init = Headers::new();
            let _ = init.insert(name, value);
            response.initialize_endpoint_headers(init);
            let error = response.into_http_response().unwrap_err();
            assert!(
                matches!(&error, AuthError::TypeError(actual) if actual == message),
                "{name}/{phase}"
            );
        }
    }
    Ok(())
}

#[test]
fn init_header_validation_follows_wrapper_headers_and_precedes_body_json() -> AuthResult<()> {
    for stage in ["header", "init", "body"] {
        let events = Events::default();
        let body = converting(
            "toJSON",
            "body.toJSON",
            FieldValue::Null,
            &events,
            Some("body.toJSON"),
        );
        let header = converting(
            "toString",
            "header.toString",
            "value".into(),
            &events,
            (stage == "header").then_some("header.toString"),
        );
        let headers = FieldMap::from([("x-data".into(), header)]).into();
        let mut response = AuthResponse::native(
            None,
            wrapper(body, FieldValue::Undefined, headers, FieldValue::Undefined),
        );
        if stage != "body" {
            response = response.with_header("bad name", "invalid init");
        }
        let error = response.into_http_response().unwrap_err();
        match stage {
            "header" => assert!(
                matches!(error, AuthError::Internal(message) if message == "original header.toString error")
            ),
            "init" => assert!(
                matches!(error, AuthError::TypeError(message) if message == "Invalid header name: 'bad name'")
            ),
            _ => assert!(
                matches!(error, AuthError::Internal(message) if message == "original body.toJSON error")
            ),
        }
        assert_eq!(
            *events.lock().unwrap(),
            if stage == "body" {
                vec!["header.toString", "body.toJSON"]
            } else {
                vec!["header.toString"]
            }
        );
    }
    Ok(())
}

#[test]
fn header_sequences_observe_live_inner_and_outer_lengths() -> AuthResult<()> {
    for mode in ["inner-grow", "inner-shrink", "outer-grow", "outer-shrink"] {
        let array = FieldArray::new();
        let events = Events::default();
        let name: FieldValue = FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual({
                let array = array.clone();
                let events = events.clone();
                move |_, arguments| {
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push("name.toString".into());
                    match mode {
                        "inner-grow" => array.set(array.len()?, "third".into())?,
                        "outer-grow" => array
                            .set(array.len()?, vec!["x-added".into(), "added".into()].into())?,
                        _ => array.set_length(1)?,
                    }
                    Ok("x-first".into())
                }
            })
            .into(),
        )])
        .into();
        let headers = if mode.starts_with("inner") {
            array.set(0, name)?;
            array.set(1, "first".into())?;
            vec![array.clone().into()].into()
        } else {
            let mut pairs = vec![vec![name, "first".into()].into()];
            if mode == "outer-shrink" {
                pairs.push(vec!["x-removed".into(), "never copied".into()].into());
            }
            for (index, pair) in pairs.into_iter().enumerate() {
                array.set(index, pair)?;
            }
            array.clone().into()
        };
        let response = AuthResponse::native(
            None,
            wrapper(
                true.into(),
                FieldValue::Undefined,
                headers,
                FieldValue::Undefined,
            ),
        )
        .into_http_response();
        if mode.starts_with("inner") {
            assert!(
                matches!(response, Err(AuthError::TypeError(message)) if message == "Header sub-sequence must contain exactly two items")
            );
        } else {
            let mut expected = vec![("content-type".into(), "application/json".into())];
            if mode == "outer-grow" {
                expected.push(("x-added".into(), "added".into()));
            }
            expected.push(("x-first".into(), "first".into()));
            assert_eq!(observation(&response?.headers), (expected, Vec::new()));
        }
        assert_eq!(*events.lock().unwrap(), ["name.toString"]);
        array.set_length(0)?;
    }
    Ok(())
}
