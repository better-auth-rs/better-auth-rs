#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;

fn shared_carrier(error: &AuthError) -> TestResult<Arc<sqlx::Error>> {
    let AuthError::Shared(source) = error else {
        return Err("Expected a shared materialization error".into());
    };
    Ok(Arc::new(sqlx::Error::Encode(Box::new(AuthError::Shared(
        source.clone(),
    )))))
}

#[test]
fn cloned_materialization_error_retains_native_identity_status_and_headers() -> TestResult {
    let headers: FieldValue = FieldMap::from([("x-native".into(), "original".into())]).into();
    let original = AuthError::from_code("FORBIDDEN", "FORMAT_FAILED", "Cannot format value")
        .capture_native_headers(headers.clone())
        .into_shared();
    let native = original
        .raw_value()
        .cloned()
        .ok_or("Missing native error")?;
    let carrier = shared_carrier(&original)?;
    for source in [
        DbErr::Exec(RuntimeErr::SqlxError(Arc::clone(&carrier))),
        DbErr::Query(RuntimeErr::SqlxError(Arc::clone(&carrier))),
    ] {
        let error = map_db_err(source.clone());
        assert!(std::ptr::eq(error.original(), original.original()));
        assert!(
            error
                .raw_value()
                .ok_or("Missing retained error")?
                .strict_equals(&native)
        );
        assert!(error.is_api_error()?);
        assert_eq!(error.status_value()?, "FORBIDDEN".into());
        assert_eq!(error.status_code()?, 403);
        assert_eq!(error.message_value()?, "Cannot format value".into());
        assert!(
            error
                .captured_headers_value()
                .ok_or("Missing captured headers")?
                .strict_equals(&headers)
        );
        let override_headers: FieldValue =
            FieldMap::from([("x-native".into(), "override".into())]).into();
        let response = error
            .capture_native_headers(override_headers.clone())
            .to_auth_response()?;
        assert!(
            response
                .captured_headers_value()
                .ok_or("Missing response headers")?
                .strict_equals(&override_headers)
        );
        assert!(response.body.field_value()?.strict_equals(&native));
        assert!(
            original
                .captured_headers_value()
                .ok_or("Missing original headers")?
                .strict_equals(&headers)
        );
        let thrown = map_db_err(source).into_thrown_value()?;
        assert!(thrown.strict_equals(&native));
    }
    Ok(())
}

#[test]
fn cloned_materialization_error_retains_original_typed_variant_and_source() -> TestResult {
    let original = AuthError::TypeError("toSqlString is not callable".into()).into_shared();
    let carrier = shared_carrier(&original)?;
    let source = DbErr::Query(RuntimeErr::SqlxError(Arc::clone(&carrier)));
    let error = map_db_err(source.clone());
    assert!(
        matches!(error.original(), AuthError::TypeError(message) if message == "toSqlString is not callable")
    );
    assert!(std::ptr::eq(error.original(), original.original()));
    let typed_source = error
        .source()
        .and_then(|source| source.downcast_ref::<AuthError>())
        .ok_or("Missing original typed source")?;
    assert!(std::ptr::eq(typed_source, original.original()));
    assert!(!error.is_api_error()?);
    assert_eq!(error.status_code()?, 500);
    assert_eq!(error.message_value()?, "toSqlString is not callable".into());
    assert_eq!(
        error.into_thrown_value()?.model_property("name")?,
        "TypeError".into()
    );
    let repeated = map_db_err(source);
    assert!(std::ptr::eq(repeated.original(), original.original()));
    Ok(())
}

#[test]
fn ordinary_sqlx_encoding_errors_retain_database_classification() -> TestResult {
    let source = DbErr::Query(RuntimeErr::SqlxError(Arc::new(sqlx::Error::Encode(
        Box::new(std::io::Error::other("binary parameter failure")),
    ))));
    let error = map_db_err(source.clone());
    assert!(matches!(
        check_source(&error, &source)?,
        DatabaseError::Query(_)
    ));
    assert!(error.to_string().contains("binary parameter failure"));
    Ok(())
}
