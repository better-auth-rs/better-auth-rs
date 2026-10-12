#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::{AuthError, AuthResult, error::ApiErrorClass};

#[derive(Debug, Error)]
#[error("driver source")]
struct DriverSource;

#[test]
fn native_database_error_retains_source_identity_and_mutation() -> AuthResult<()> {
    let context: FieldValue = FieldMap::from([("row".into(), "original".into())]).into();
    let database = DatabaseError::UniqueConstraint(DatabaseErrorCause::from_source(
        "diagnostic constraint",
        DriverSource,
        Some(FieldMap::from([
            ("message".into(), "driver message".into()),
            ("name".into(), "error".into()),
            ("detail".into(), FieldValue::Undefined),
            ("line".into(), "24".into()),
            ("column".into(), "column_name".into()),
            ("context".into(), context.clone()),
        ])),
    ));
    assert!(database.is_unique_constraint());
    assert!(
        database
            .cause()
            .source()
            .is_some_and(|source| source.is::<DriverSource>())
    );
    let error = AuthError::Database(database);
    let diagnostic = "Database error: Unique constraint violation: diagnostic constraint";
    assert_eq!(error.to_string(), diagnostic);
    assert_eq!(error.message_value()?, "driver message".into());
    assert!(!error.is_api_error()?);
    assert!(error.is_error_instance());
    assert!(!error.is_api_error_instance(ApiErrorClass::BetterCall));

    let first = error.callback_value()?;
    assert!(error.callback_value()?.strict_equals(&first));
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&first))
    );
    assert!(first.model_property("context")?.strict_equals(&context));
    assert_eq!(
        first
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["name", "detail", "context"]
    );
    assert!(first.model_property("detail")?.is_undefined());
    assert_eq!(first.model_property("line")?, "24".into());
    assert_eq!(first.model_property("column")?, "column_name".into());
    assert!(!first.has_property("length")?);
    first.set_model_property("message", "callback mutation".into())?;
    first.set_model_property("added", context.clone())?;
    assert_eq!(error.message_value()?, "callback mutation".into());
    assert_eq!(error.instrumentation_message()?, "callback mutation");
    assert_eq!(error.to_string(), diagnostic);

    let thrown = error.into_thrown_value()?;
    assert!(thrown.strict_equals(&first));
    assert!(thrown.model_property("added")?.strict_equals(&context));
    Ok(())
}

#[test]
fn database_error_reads_native_properties_and_keeps_captured_headers() -> AuthResult<()> {
    let error = AuthError::Database(DatabaseError::Query(DatabaseErrorCause::from_source(
        "stable diagnostic",
        DriverSource,
        Some(FieldMap::from([(
            "message".into(),
            "driver message".into(),
        )])),
    )));
    assert!(error.status_value()?.is_undefined());
    assert!(error.status_code()?.field_value().is_undefined());
    assert!(error.body_value()?.is_undefined());
    assert!(error.headers_value()?.is_undefined());

    let captured: FieldValue = FieldMap::from([("x-endpoint".into(), "captured".into())]).into();
    let error = error.capture_native_headers(captured.clone());
    assert!(matches!(&error, AuthError::Database(database)
        if database.cause().source().is_some_and(|source| source.is::<DriverSource>())));
    assert!(
        error
            .captured_headers_value()
            .is_some_and(|headers| headers.strict_equals(&captured))
    );
    let value = error.callback_value()?;
    let body: FieldValue = FieldMap::from([("message".into(), "public replacement".into())]).into();
    let headers: FieldValue = FieldMap::from([("x-driver".into(), "native".into())]).into();
    for (name, field) in [
        ("name", "APIError".into()),
        ("status", "IM_A_TEAPOT".into()),
        ("statusCode", 418.0.into()),
        ("body", body.clone()),
        ("headers", headers.clone()),
    ] {
        value.set_model_property(name, field)?;
    }
    assert!(error.is_api_error()?);
    assert!(!error.is_api_error_instance(ApiErrorClass::BetterCall));
    assert_eq!(error.status_value()?, "IM_A_TEAPOT".into());
    assert_eq!(error.status_code()?.field_value(), 418.0.into());
    assert!(error.body_value()?.strict_equals(&body));
    assert!(error.headers_value()?.strict_equals(&headers));
    assert_eq!(
        error.to_string(),
        "Database error: Query error: stable diagnostic"
    );

    let response = error.to_auth_response()?;
    assert!(response.body.field_value()?.strict_equals(&value));
    assert!(
        response
            .captured_headers_value()
            .is_some_and(|headers| headers.strict_equals(&captured))
    );
    let http = response.into_http_response()?;
    assert_eq!(http.status, 418);
    assert_eq!(
        http.headers.get("x-driver").map(String::as_str),
        Some("native")
    );
    assert_eq!(http.headers.get("x-endpoint"), None);
    assert_eq!(
        http.body.bytes()?.as_ref(),
        br#"{"message":"public replacement"}"#
    );
    Ok(())
}

#[test]
fn ordinary_database_error_has_no_native_status_and_returns_an_empty_http_500() -> AuthResult<()> {
    let error = AuthError::Database(DatabaseError::Query("private database failure".into()));
    assert!(error.status_code()?.field_value().is_undefined());
    let response = error.to_http_response()?;
    assert_eq!(response.status, 500);
    assert_eq!(response.status_text, "Internal Server Error".into());
    assert!(response.body.bytes()?.is_empty());
    Ok(())
}

#[test]
fn error_inheritance_ignores_structural_name_properties() -> AuthResult<()> {
    assert!(AuthError::type_error("typed").is_error_instance());
    assert!(AuthError::from_code("BAD_REQUEST", "CODE", "message").is_error_instance());
    assert!(
        !AuthError::from_thrown(FieldMap::from([("name".into(), "Error".into())]).into())
            .is_error_instance()
    );
    assert!(!AuthError::from_thrown(FieldValue::Null).is_error_instance());
    let native = AuthError::type_error("typed").into_thrown_value()?;
    native.set_model_property("name", "custom name".into())?;
    assert!(AuthError::from_thrown(native).is_error_instance());
    Ok(())
}

#[test]
fn plain_database_error_keeps_legacy_diagnostic_and_one_callback_object() -> AuthResult<()> {
    let error = AuthError::Database(DatabaseError::Query("bad sql".into()));
    let diagnostic = "Database error: Query error: bad sql";
    assert_eq!(error.to_string(), diagnostic);
    let first = error.callback_value()?;
    assert_eq!(first.model_property("name")?, "Error".into());
    assert_eq!(first.model_property("message")?, diagnostic.into());
    assert!(first.enumerable_fields()?.is_empty());
    assert!(error.callback_value()?.strict_equals(&first));
    assert!(error.into_thrown_value()?.strict_equals(&first));
    Ok(())
}
