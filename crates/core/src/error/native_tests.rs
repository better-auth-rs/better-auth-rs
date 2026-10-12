#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify constructor order, shared identity, and observable error propagation."
)]

use super::*;
use crate::{FieldFunction, FieldObject, field_value::FieldObjectSource};
use std::sync::{Arc, Mutex};

type ReadProperty = dyn Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync;

struct Source {
    keys: Vec<String>,
    read: Box<ReadProperty>,
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.keys.clone())
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(self
            .keys
            .iter()
            .any(|key| key == name)
            .then_some(crate::field_value::FieldPropertyDescriptor { enumerable: true }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        (self.read)(name)
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::type_error("The test source is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::type_error("The test source is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let mut fields = FieldMap::new();
        for name in &self.keys {
            if let Some(value) = self.get(name)? {
                let _ = fields.insert(name.clone(), value);
            }
        }
        Ok(fields)
    }

    fn identity(&self) -> usize {
        self as *const Self as usize
    }
}

fn source(
    keys: &[&str],
    read: impl Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync + 'static,
) -> FieldObject {
    FieldObject::from_source(Arc::new(Source {
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        read: Box::new(read),
    }))
}

fn record(events: &Mutex<Vec<String>>, event: &str) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Test events lock poisoned"))?
        .push(event.into());
    Ok(())
}

fn events(events: &Mutex<Vec<String>>) -> AuthResult<Vec<String>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Test events lock poisoned"))?
        .clone())
}

#[test]
fn callback_error_values_retain_identity_without_reading_properties() -> AuthResult<()> {
    let raw: FieldValue = source(&["name", "message"], |_| {
        Err(AuthError::type_error("No field should be read"))
    })
    .into();
    let value = AuthError::from_thrown(raw.clone()).into_thrown_value()?;
    assert!(value.strict_equals(&raw));
    for raw in [FieldValue::Undefined, FieldValue::Null, 7.into()] {
        assert!(
            AuthError::from_thrown(raw.clone())
                .into_thrown_value()?
                .strict_equals(&raw)
        );
    }
    Ok(())
}

#[test]
fn shared_native_errors_do_not_read_properties_during_transport() -> AuthResult<()> {
    let raw: FieldValue = source(&["name", "message", "statusCode"], |_| {
        Err(AuthError::type_error(
            "Transport must not read error properties",
        ))
    })
    .into();
    let error = AuthError::from_thrown(raw.clone()).into_shared();
    let AuthError::Shared(shared) = &error else {
        return Err(AuthError::internal("Expected a shared error"));
    };
    let second = AuthError::Shared(shared.clone());
    let _ = format!("{second:?} {second}");
    assert!(
        second
            .to_auth_response()?
            .body
            .field_value()?
            .strict_equals(&raw)
    );
    assert!(error.into_thrown_value()?.strict_equals(&raw));
    Ok(())
}

#[test]
fn typed_callback_error_values_keep_messages_hidden_and_api_brands() -> AuthResult<()> {
    for (error, name, message) in [
        (
            AuthError::type_error("bad access"),
            "TypeError",
            "bad access",
        ),
        (
            AuthError::RangeError("bad range".into()),
            "RangeError",
            "bad range",
        ),
        (
            AuthError::internal("original failure"),
            "Error",
            "original failure",
        ),
    ] {
        let value = error.into_thrown_value()?;
        assert_eq!(value.model_property("name")?, FieldValue::from(name));
        assert_eq!(value.model_property("message")?, FieldValue::from(message));
        assert_eq!(value.stringify()?.as_deref(), Some("{}"));
        assert_eq!(
            value.display_utf16()?.as_utf16(),
            format!("{name}: {message}")
                .encode_utf16()
                .collect::<Vec<_>>()
        );
        let object = value
            .as_object()
            .ok_or_else(|| AuthError::internal("runtime errors require object values"))?;
        assert_eq!(object.own_keys()?, ["message"]);
        assert!(object.own_property_descriptor("name")?.is_none());
        assert!(
            object
                .own_property_descriptor("message")?
                .is_some_and(|descriptor| !descriptor.enumerable)
        );
    }
    for (error, class, status) in [
        (
            AuthError::FieldInput {
                code: "BAD_FIELD",
                message: "bad field".into(),
            },
            ApiErrorClass::BetterAuth,
            FieldValue::from("BAD_REQUEST"),
        ),
        (
            AuthError::RequestValidation {
                message: "bad request".into(),
            },
            ApiErrorClass::BetterCall,
            FieldValue::from(400),
        ),
    ] {
        let body = error.body_value()?;
        let value = error.into_thrown_value()?;
        assert!(api_error_instance(&value, class));
        assert_eq!(value.model_property("status")?, status);
        assert_eq!(value.model_property("body")?, body);
    }
    Ok(())
}

#[test]
fn raw_envelope_round_trip_keeps_identity_without_reading_fields() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let raw: FieldValue = source(&["name", "body", "statusCode"], {
        let reads = reads.clone();
        move |name| {
            record(&reads, name)?;
            Err(AuthError::type_error("No field should be read"))
        }
    })
    .into();
    let headers: FieldValue = FieldMap::from([("x-context".into(), "retained".into())]).into();
    let error = AuthError::from_thrown(raw.clone()).capture_native_headers(headers.clone());
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&raw))
    );
    let _ = format!("{error:?} {error}");
    let response = error.to_auth_response().expect("fixture response succeeds");
    assert!(response.body.field_value()?.strict_equals(&raw));
    assert!(
        response
            .captured_headers_value()
            .is_some_and(|value| value.strict_equals(&headers))
    );
    let recovered = AuthError::from_returned_response(response)?;
    assert!(
        recovered
            .raw_value()
            .is_some_and(|value| value.strict_equals(&raw))
    );
    assert!(
        recovered
            .captured_headers_value()
            .is_some_and(|value| value.strict_equals(&headers))
    );
    assert!(events(&reads)?.is_empty());
    Ok(())
}

#[test]
fn structural_classification_repeats_reads_but_instance_brands_short_circuit() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let object = source(&["name"], {
        let reads = reads.clone();
        move |name| {
            record(&reads, name)?;
            let count = events(&reads)?.len();
            Ok(Some(if count == 1 {
                "APIError".into()
            } else {
                "Changed".into()
            }))
        }
    });
    let raw = FieldValue::Object(object);
    assert!(is_api_error_value(&raw)?);
    assert!(!is_api_error_value(&raw)?);
    assert_eq!(events(&reads)?, ["name", "name"]);

    let object = source(&["name"], |_| {
        Err(AuthError::type_error("name getter failed"))
    });
    assert!(object.has_property("name")?);
    let call = brand_api_error_object(object.clone(), ApiErrorClass::BetterCall);
    let auth = brand_api_error_object(object, ApiErrorClass::BetterAuth);
    assert!(is_api_error_value(&call)?);
    assert!(is_api_error_value(&auth)?);
    assert!(!api_error_instance(&call, ApiErrorClass::BetterAuth));
    assert!(api_error_instance(&auth, ApiErrorClass::BetterAuth));
    assert!(api_error_instance(&auth, ApiErrorClass::BetterCall));
    Ok(())
}

#[test]
fn status_reads_preserve_dynamic_values_and_do_not_coerce_objects() -> AuthResult<()> {
    let conversions = Arc::new(Mutex::new(Vec::new()));
    let dynamic: FieldValue = FieldMap::from([(
        "valueOf".into(),
        FieldFunction::contextual({
            let conversions = conversions.clone();
            move |_, _| {
                record(&conversions, "valueOf")?;
                Ok(409.0.into())
            }
        })
        .into(),
    )])
    .into();
    for value in [
        FieldValue::Undefined,
        FieldValue::Null,
        "409".into(),
        (-1.0).into(),
        400.75.into(),
        dynamic.clone(),
    ] {
        let raw: FieldValue = FieldMap::from([("statusCode".into(), value.clone())]).into();
        let error = AuthError::from_thrown(raw.clone());
        assert!(error.status_code()?.field_value().strict_equals(&value));
        let _ = raw
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected raw error object"))?
            .set("statusCode", 201.0.into())?;
        assert_eq!(error.status_code()?, 201);
    }
    assert!(events(&conversions)?.is_empty());
    Ok(())
}

#[test]
fn construction_observes_defaults_then_arguments_then_message_conversion() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let status: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let reads = reads.clone();
            move |_, _| {
                record(&reads, "status.toString")?;
                Ok("BAD_REQUEST".into())
            }
        })
        .into(),
    )])
    .into();
    let message: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let reads = reads.clone();
            move |_, _| {
                record(&reads, "message.toString")?;
                Ok("captured message".into())
            }
        })
        .into(),
    )])
    .into();
    let cause: FieldValue = FieldMap::from([("source".into(), "original cause".into())]).into();
    let body: FieldValue = source(&["message", "cause"], {
        let reads = reads.clone();
        let cause = cause.clone();
        move |name| {
            record(&reads, &format!("body.{name}"))?;
            Ok(match name {
                "message" => Some(message.clone()),
                "cause" => Some(cause.clone()),
                _ => None,
            })
        }
    })
    .into();
    let headers: FieldValue = FieldMap::new().into();
    let error = AuthError::try_api_error(ApiErrorInit {
        status: status.clone(),
        body: body.clone(),
        headers: headers.clone(),
        ..Default::default()
    })?;
    assert_eq!(
        events(&reads)?,
        [
            "status.toString",
            "body.message",
            "body.cause",
            "body.cause",
            "message.toString"
        ]
    );
    assert_eq!(error.status_code()?, 400);
    assert!(error.status_value()?.strict_equals(&status));
    assert!(error.body_value()?.strict_equals(&body));
    assert!(error.headers_value()?.strict_equals(&headers));
    assert_eq!(error.instrumentation_message()?, "captured message");
    let raw = error
        .raw_value()
        .ok_or_else(|| AuthError::internal("Expected constructed error"))?;
    assert!(raw.model_property("cause")?.strict_equals(&cause));
    assert_eq!(events(&reads)?.len(), 5);
    Ok(())
}

#[test]
fn message_is_captured_once_without_serializing_the_body() -> AuthResult<()> {
    let body = FieldObject::from(FieldMap::from([
        ("message".into(), "initial message".into()),
        (
            "toJSON".into(),
            FieldFunction::contextual(|_, _| Err(AuthError::type_error("toJSON must not run")))
                .into(),
        ),
    ]));
    let error = AuthError::try_api_error(ApiErrorInit {
        body: body.clone().into(),
        ..Default::default()
    })?;
    let _ = body.set("message", "changed body".into())?;
    assert_eq!(error.instrumentation_message()?, "initial message");
    assert_eq!(
        error.body_value()?.model_property("message")?,
        "changed body".into()
    );
    Ok(())
}

#[test]
fn response_conversion_propagates_the_original_constructor_failure() -> AuthResult<()> {
    let failure: FieldValue = FieldMap::from([("failure".into(), "identity".into())]).into();
    let body: FieldValue = source(&["message"], {
        let failure = failure.clone();
        move |_| Err(AuthError::from_thrown(failure.clone()))
    })
    .into();
    for error in [
        AuthError::from(crate::AuthResponse::native(Some(400), body.clone())),
        AuthError::from_status("BAD_REQUEST", body),
    ] {
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&failure))
        );
    }
    Ok(())
}

#[test]
fn organization_input_propagates_getter_failures_without_issue_aggregation() -> AuthResult<()> {
    use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};

    let fields = UserConfig {
        additional_fields: Some(
            [
                ("first".into(), UserFieldConfig::default()),
                (
                    "payload".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        ..Default::default()
                    },
                ),
                ("later".into(), UserFieldConfig::default()),
            ]
            .into(),
        ),
    };
    let failure = AuthError::from_code("CONFLICT", "VALIDATION_ERROR", "getter rejected");
    let failure = failure
        .raw_value()
        .cloned()
        .ok_or_else(|| AuthError::internal("Expected native getter failure"))?;
    let reads = Arc::new(Mutex::new(Vec::new()));
    let payload = source(&["value"], {
        let failure = failure.clone();
        let reads = reads.clone();
        move |name| {
            record(&reads, name)?;
            Err(AuthError::from_thrown(failure.clone()))
        }
    });
    let error = fields
        .parse_organization_input(
            &FieldMap::from([
                ("first".into(), false.into()),
                ("payload".into(), payload.into()),
            ]),
            "body",
            false,
        )
        .err()
        .ok_or_else(|| AuthError::internal("Organization schema ignored the getter failure"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&failure))
    );
    assert_eq!(error.status_value()?, FieldValue::from("CONFLICT"));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
    assert_eq!(events(&reads)?, ["value"]);
    let error = AuthError::from_returned_response(
        error.to_auth_response().expect("fixture response succeeds"),
    )?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&failure))
    );

    for request_validation in [false, true] {
        let payload = source(&["value"], move |_| {
            Err(if request_validation {
                AuthError::RequestValidation {
                    message: "field getter rejected".into(),
                }
            } else {
                AuthError::FieldInput {
                    code: "CUSTOM_FIELD_FAILURE",
                    message: "field getter rejected".into(),
                }
            })
        });
        let error = fields
            .parse_organization_input(
                &FieldMap::from([
                    ("first".into(), false.into()),
                    ("payload".into(), payload.into()),
                ]),
                "body",
                false,
            )
            .err()
            .ok_or_else(|| AuthError::internal("Organization schema swallowed a getter error"))?;
        if request_validation {
            assert!(
                matches!(error, AuthError::RequestValidation { ref message } if message == "field getter rejected")
            );
        } else {
            assert!(
                matches!(error, AuthError::FieldInput { code: "CUSTOM_FIELD_FAILURE", ref message } if message == "field getter rejected")
            );
        }
    }
    Ok(())
}

#[test]
fn instrumentation_propagates_top_level_message_getter_and_conversion_failures() -> AuthResult<()> {
    let failure: FieldValue = FieldMap::from([("failure".into(), "message".into())]).into();
    let getter: FieldValue = source(&["message"], {
        let failure = failure.clone();
        move |_| Err(AuthError::from_thrown(failure.clone()))
    })
    .into();
    let conversion: FieldValue = FieldMap::from([(
        "message".into(),
        FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual({
                let failure = failure.clone();
                move |_, _| Err(AuthError::from_thrown(failure.clone()))
            })
            .into(),
        )])
        .into(),
    )])
    .into();
    for value in [getter, conversion] {
        let error = AuthError::from_thrown(value)
            .instrumentation_message()
            .err()
            .ok_or_else(|| AuthError::internal("Message conversion unexpectedly succeeded"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&failure))
        );
    }
    Ok(())
}

#[test]
fn constructed_error_presence_and_enumeration_follow_error_properties() -> AuthResult<()> {
    let error = AuthError::try_api_error(ApiErrorInit {
        body: FieldMap::from([
            ("message".into(), "message".into()),
            ("cause".into(), true.into()),
        ])
        .into(),
        ..Default::default()
    })?;
    let object = error
        .raw_value()
        .and_then(FieldValue::as_object)
        .ok_or_else(|| AuthError::internal("Expected constructed error object"))?;
    assert!(object.has_property("message")?);
    assert!(object.has_property("cause")?);
    assert_eq!(
        object.enumerable_keys()?,
        ["status", "body", "headers", "statusCode", "name"]
    );
    let _ = object.delete("cause")?;
    assert!(!object.has_property("cause")?);
    let _ = object.set("cause", false.into())?;
    assert_eq!(
        object.enumerable_keys()?.last().map(String::as_str),
        Some("cause")
    );
    let _ = object.delete("message")?;
    assert!(object.has_property("message")?);
    assert_eq!(error.message_value()?, "".into());
    Ok(())
}

#[test]
fn better_auth_errors_keep_hidden_properties_and_remain_outside_api_error_brands() -> AuthResult<()>
{
    let native_messages = [
        crate::Utf16String::default(),
        crate::Utf16String::from_units(vec![0xd800]),
        crate::Utf16String::from_units(vec![0xdc00]),
        crate::Utf16String::from_units(vec![0xd83d, 0xde00]),
        crate::Utf16String::from_units(vec![0xdc00, 65, 0xd800]),
    ];
    for (message, error) in std::iter::once((
        crate::Utf16String::from("OAUTH_ACCOUNT_SUBJECT_INVALID"),
        AuthError::better_auth("OAUTH_ACCOUNT_SUBJECT_INVALID"),
    ))
    .chain(native_messages.into_iter().map(|message| {
        let error = AuthError::better_auth_native(message.clone());
        (message, error)
    })) {
        let raw = error
            .raw_value()
            .ok_or_else(|| AuthError::internal("Expected native BetterAuthError"))?;
        let object = raw
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected BetterAuthError object"))?;
        assert_eq!(raw.model_property("name")?, "BetterAuthError".into());
        assert_eq!(error.message_value()?, message.clone().into());
        assert_eq!(raw.model_property("stack")?, "".into());
        for name in ["message", "stack"] {
            assert_eq!(
                object.own_property_descriptor(name)?,
                Some(crate::field_value::FieldPropertyDescriptor { enumerable: false })
            );
        }
        assert_eq!(object.enumerable_keys()?, ["name"]);
        assert_eq!(
            raw.json()?,
            Some(serde_json::json!({"name": "BetterAuthError"}))
        );
        let mut display = "BetterAuthError".encode_utf16().collect::<Vec<_>>();
        if !message.as_utf16().is_empty() {
            display.extend(": ".encode_utf16());
            display.extend_from_slice(message.as_utf16());
        }
        assert_eq!(raw.display_utf16()?.as_utf16(), display);
        assert!(!error.is_api_error()?);
        for class in [ApiErrorClass::BetterCall, ApiErrorClass::BetterAuth] {
            assert!(!error.is_api_error_instance(class));
        }
        let _ = object.set("name", "APIError".into())?;
        assert!(error.is_api_error()?);
        for class in [ApiErrorClass::BetterCall, ApiErrorClass::BetterAuth] {
            assert!(!error.is_api_error_instance(class));
        }
        let raw = raw.clone();
        let error = error.capture_native_headers(FieldMap::new().into());
        assert!(
            error
                .raw_value()
                .is_some_and(|retained| retained.strict_equals(&raw))
        );
    }
    Ok(())
}

#[test]
fn constructor_defaults_distinguish_undefined_from_null_and_explicit_status_code() -> AuthResult<()>
{
    let default = AuthError::try_api_error(ApiErrorInit::default())?;
    assert_eq!(default.status_value()?, "INTERNAL_SERVER_ERROR".into());
    assert_eq!(default.status_code()?, 500);
    assert!(default.body_value()?.is_undefined());
    assert_eq!(default.message_value()?, "".into());

    let null = AuthError::try_api_error(ApiErrorInit {
        status: FieldValue::Null,
        status_code: FieldValue::Null,
        ..Default::default()
    })?;
    assert!(null.status_value()?.is_null());
    assert!(null.status_code()?.field_value().is_null());
    let dynamic: FieldValue = FieldMap::new().into();
    let explicit = AuthError::try_api_error(ApiErrorInit {
        status: source(&["toString"], |_| {
            Err(AuthError::type_error("status must not convert"))
        })
        .into(),
        status_code: dynamic.clone(),
        ..Default::default()
    })?;
    assert!(
        explicit
            .status_code()?
            .field_value()
            .strict_equals(&dynamic)
    );
    let unknown = AuthError::try_api_error(ApiErrorInit {
        status: "UNKNOWN".into(),
        ..Default::default()
    })?;
    assert!(unknown.status_code()?.is_undefined());
    Ok(())
}
