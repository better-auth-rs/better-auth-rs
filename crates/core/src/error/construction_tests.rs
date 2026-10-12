#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::{AuthResponse, FieldMap, FieldValue};

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares native property order and complete HTTP bytes"
)]
fn observe(error: AuthError, status: u16, keys: &[&str], bytes: &[u8]) -> AuthResult<FieldValue> {
    assert_eq!(error.status_code()?, status);
    assert!(error.is_api_error()?);
    let raw_status = error.status_value()?;
    let brands = [ApiErrorClass::BetterCall, ApiErrorClass::BetterAuth]
        .map(|class| error.is_api_error_instance(class));
    let body = error.body_value()?;
    let error = AuthError::from_returned_response(
        error.to_auth_response().expect("fixture response succeeds"),
    )?;
    assert_eq!(error.status_value()?, raw_status);
    assert_eq!(
        [ApiErrorClass::BetterCall, ApiErrorClass::BetterAuth]
            .map(|class| error.is_api_error_instance(class)),
        brands
    );
    let fields = body
        .as_object()
        .map(|body| body.snapshot_fields())
        .transpose()?;
    assert_eq!(
        fields
            .as_ref()
            .map(|fields| fields.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default(),
        keys
    );
    let response = error
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()?;
    assert_eq!(response.status, status);
    assert_eq!(response.body.bytes()?.as_ref(), bytes);
    Ok(body)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The same message must have different bodies for coded and explicit errors"
)]
fn coded_errors_and_explicit_message_bodies_have_distinct_contracts() -> AuthResult<()> {
    for status in [FieldValue::from(400u16), "BAD_REQUEST".into()] {
        let error = AuthError::from_code(status.clone(), "USER_NOT_FOUND", "User not found");
        assert_eq!(error.status_value()?, status);
        let coded = observe(
            error,
            400,
            &["message", "code"],
            br#"{"message":"User not found","code":"USER_NOT_FOUND"}"#,
        )?;
        assert_eq!(
            coded,
            FieldValue::from(FieldMap::from([
                ("message".into(), "User not found".into()),
                ("code".into(), "USER_NOT_FOUND".into()),
            ]))
        );
    }
    let explicit: FieldValue = FieldMap::from([("message".into(), "User not found".into())]).into();
    let observed = observe(
        AuthResponse::native(Some(400), explicit.clone()).into(),
        400,
        &["message"],
        br#"{"message":"User not found"}"#,
    )?;
    assert!(observed.strict_equals(&explicit));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Explicit bodies retain identity, property presence, and mutations before HTTP serialization"
)]
fn explicit_error_body_retains_order_extra_properties_and_identity() -> AuthResult<()> {
    let body: FieldValue = FieldMap::from([
        ("code".into(), "CUSTOM".into()),
        ("message".into(), "initial".into()),
        (
            "details".into(),
            FieldMap::from([("reason".into(), "retained".into())]).into(),
        ),
        ("omitted".into(), FieldValue::Undefined),
    ])
    .into();
    let errors = [
        (
            AuthError::from(AuthResponse::native(Some(409), body.clone())),
            FieldValue::from(409u16),
        ),
        (
            AuthError::from_status(409u16, body.clone()),
            FieldValue::from(409u16),
        ),
        (
            AuthError::from_status("CONFLICT", body.clone()),
            FieldValue::from("CONFLICT"),
        ),
    ];
    let object = body
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected explicit error object"))?;
    object.set("message", "User not found".into())?;
    for (error, status) in errors {
        assert_eq!(error.status_value()?, status);
        assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
        let observed = observe(
            error,
            409,
            &["code", "message", "details", "omitted"],
            br#"{"code":"CUSTOM","message":"User not found","details":{"reason":"retained"}}"#,
        )?;
        assert!(observed.strict_equals(&body));
    }
    assert_eq!(object.get("omitted")?, Some(FieldValue::Undefined));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "An absent body and an explicit null remain distinct for native and HTTP callers"
)]
fn absent_and_null_error_bodies_remain_distinct() -> AuthResult<()> {
    for (absent, null) in [
        (
            AuthResponse::native(Some(401), FieldValue::Undefined).into(),
            AuthResponse::native(Some(401), FieldValue::Null).into(),
        ),
        (
            AuthError::from_status("UNAUTHORIZED", FieldValue::Undefined),
            AuthError::from_status("UNAUTHORIZED", FieldValue::Null),
        ),
    ] {
        assert!(observe(absent, 401, &[], b"")?.is_undefined());
        assert!(observe(null, 401, &[], b"null")?.is_null());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "FieldInput must retain its typed API while response conversion uses native error construction"
)]
fn field_input_retains_its_variant_until_response_conversion() -> AuthResult<()> {
    let error = AuthError::FieldInput {
        code: "CUSTOM_FIELD_FAILURE",
        message: "field rejected".into(),
    };
    assert!(matches!(
        &error,
        AuthError::FieldInput {
            code: "CUSTOM_FIELD_FAILURE",
            ..
        }
    ));
    assert_eq!(
        error.error_payload()?,
        (
            SchemaValue::Typed(400),
            Some("CUSTOM_FIELD_FAILURE".into()),
            "field rejected".into()
        )
    );
    assert_eq!(error.to_string(), "field rejected");
    assert_eq!(error.status_value()?, FieldValue::from("BAD_REQUEST"));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
    let _ = observe(
        error,
        400,
        &["message", "code"],
        br#"{"message":"field rejected","code":"CUSTOM_FIELD_FAILURE"}"#,
    )?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Request schemas must retain Better Call identity and numeric status through conversion"
)]
fn record_and_query_validation_share_native_coded_error_bodies() -> AuthResult<()> {
    let mut request = crate::AuthRequest::new(crate::HttpMethod::Post, "/record");
    request.body = Some(b"42".to_vec());
    let error = crate::endpoint_input::record_body(&request)
        .err()
        .ok_or_else(|| AuthError::internal("Record schema accepted a number"))?;
    assert!(matches!(error, AuthError::RequestValidation { .. }));
    assert_eq!(error.status_value()?, FieldValue::from(400u16));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
    assert!(!error.is_api_error_instance(ApiErrorClass::BetterAuth));
    let _ = observe(error, 400, &["message", "code"],
        br#"{"message":"[body] Invalid input: expected record, received number","code":"VALIDATION_ERROR"}"#)?;
    let error = crate::query::session_query(Some(serde_json::json!(42)))
        .err()
        .ok_or_else(|| AuthError::internal("Query schema accepted a number"))?;
    assert!(matches!(error, AuthError::RequestValidation { .. }));
    assert_eq!(error.status_value()?, FieldValue::from(400u16));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
    assert!(!error.is_api_error_instance(ApiErrorClass::BetterAuth));
    let _ = observe(error, 400, &["message", "code"],
        br#"{"message":"[query] Invalid input: expected object, received number","code":"VALIDATION_ERROR"}"#)?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Organization issues must retain declaration order and the request-schema constructor"
)]
fn organization_issues_retain_request_brand_and_declaration_order() -> AuthResult<()> {
    use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};

    let fields = UserConfig {
        additional_fields: Some(
            [
                ("title".into(), UserFieldConfig::default()),
                (
                    "tags".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::StringArray,
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    let input = FieldMap::from([
        ("title".into(), false.into()),
        ("tags".into(), vec![FieldValue::Null, 3u16.into()].into()),
    ]);
    let error = fields
        .parse_organization_input(&input, "body", false)
        .err()
        .ok_or_else(|| AuthError::internal("Organization schema accepted invalid fields"))?;
    assert!(matches!(error, AuthError::RequestValidation { .. }));
    assert_eq!(error.status_value()?, FieldValue::from(400u16));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
    assert!(!error.is_api_error_instance(ApiErrorClass::BetterAuth));
    let _ = observe(error, 400, &["message", "code"],
        br#"{"message":"[body.title] Invalid input: expected string, received boolean; [body.tags.0] Invalid input: expected string, received null; [body.tags.1] Invalid input: expected string, received number","code":"VALIDATION_ERROR"}"#)?;
    Ok(())
}
