#![expect(
    clippy::panic_in_result_fn,
    reason = "The regression verifies original typed errors, native identity, and independent header ownership."
)]

use std::error::Error;

use crate::{ApiErrorClass, AuthError, AuthResult, FieldMap, FieldValue};

fn copy(error: &AuthError) -> AuthResult<AuthError> {
    match error {
        AuthError::Shared(shared) => Ok(AuthError::Shared(shared.clone())),
        _ => Err(AuthError::internal("Expected a shared error")),
    }
}

#[test]
fn shared_errors_retain_typed_metadata_and_original_source() -> AuthResult<()> {
    let error = AuthError::FieldInput {
        code: "BAD_FIELD",
        message: "field rejected".into(),
    }
    .into_shared();
    let second = copy(&error)?.into_shared();
    assert!(std::ptr::eq(error.original(), second.original()));
    let source = second
        .source()
        .and_then(|source| source.downcast_ref::<AuthError>())
        .ok_or_else(|| AuthError::internal("The original AuthError must remain a typed source"))?;
    assert!(std::ptr::eq(source, error.original()));
    assert!(matches!(
        source,
        AuthError::FieldInput {
            code: "BAD_FIELD",
            ..
        }
    ));
    assert_eq!(second.status_code()?, 400);
    assert_eq!(second.status_value()?, "BAD_REQUEST".into());
    assert!(second.is_api_error_instance(ApiErrorClass::BetterAuth));
    assert_eq!(second.message_value()?, "field rejected".into());
    let response = second.to_auth_response()?.into_http_response()?;
    assert_eq!(response.status, 400);
    assert_eq!(
        response.body.bytes()?.as_ref(),
        br#"{"message":"field rejected","code":"BAD_FIELD"}"#
    );
    Ok(())
}

#[test]
fn shared_header_capture_does_not_mutate_other_owners() -> AuthResult<()> {
    let raw: FieldValue = FieldMap::from([("marker".into(), "original".into())]).into();
    let original_headers: FieldValue = FieldMap::from([("x-original".into(), "one".into())]).into();
    let replacement_headers: FieldValue =
        FieldMap::from([("x-replaced".into(), "two".into())]).into();
    let error = AuthError::from_thrown(raw.clone())
        .capture_native_headers(original_headers.clone())
        .into_shared();
    let second = copy(&error)?.capture_native_headers(replacement_headers.clone());
    assert!(std::ptr::eq(error.original(), second.original()));
    assert!(
        error
            .captured_headers_value()
            .is_some_and(|headers| headers.strict_equals(&original_headers))
    );
    assert!(
        second
            .captured_headers_value()
            .is_some_and(|headers| headers.strict_equals(&replacement_headers))
    );
    let response = second.to_auth_response()?;
    assert!(response.body.field_value()?.strict_equals(&raw));
    assert!(
        response
            .captured_headers_value()
            .is_some_and(|headers| headers.strict_equals(&replacement_headers))
    );
    assert!(error.into_thrown_value()?.strict_equals(&raw));
    Ok(())
}

#[test]
fn shared_runtime_errors_keep_their_native_error_class() -> AuthResult<()> {
    for (source, name) in [
        (AuthError::type_error("source failure"), "TypeError"),
        (AuthError::RangeError("source failure".into()), "RangeError"),
        (AuthError::DataClone, "DataCloneError"),
    ] {
        let error = source.into_shared();
        assert!(!error.is_api_error()?);
        let message = error.message_value()?;
        let raw = error.into_thrown_value()?;
        assert_eq!(raw.model_property("name")?, name.into());
        assert_eq!(raw.model_property("message")?, message);
    }
    Ok(())
}
