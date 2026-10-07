use super::OAuthSignInError;
use better_auth_core::{AuthError, AuthResponse, AuthResult, FieldMap, FieldValue, Utf16String};
use serde_json::json;

// Upstream api/routes/callback.mjs redirects only API errors with a truthy body.code.
#[test]
fn callback_redirects_api_errors_with_codes() -> AuthResult<()> {
    for error in [
        AuthError::FieldInput {
            code: "PROFILE_REJECTED",
            message: "Provider profile rejected".into(),
        },
        AuthError::Upstream {
            status: 422,
            code: "PROFILE_REJECTED",
            message: "Provider profile rejected",
        },
        AuthResponse::json(
            403,
            &json!({"code": "PROFILE_REJECTED", "message": "Provider profile rejected"}),
        )?
        .into(),
    ] {
        assert_eq!(
            OAuthSignInError::from(error).redirect_parts()?,
            (
                "PROFILE_REJECTED".into(),
                Some("Provider profile rejected".into()),
            ),
        );
    }
    Ok(())
}

#[test]
fn callback_converts_truthy_api_error_values_at_the_url_boundary() -> AuthResult<()> {
    for message in [
        FieldValue::Undefined,
        FieldValue::Null,
        FieldValue::Bool(false),
        FieldValue::Number(0.0),
        FieldValue::Number(f64::NAN),
        FieldValue::from(""),
    ] {
        let response = AuthResponse::native(
            422,
            FieldMap::from([
                ("code".into(), FieldValue::Number(429.0)),
                ("message".into(), message),
            ])
            .into(),
        );
        assert_eq!(
            OAuthSignInError::from(AuthError::from(response)).redirect_parts()?,
            ("429".into(), None),
        );
    }
    for (code, message, expected) in [
        (
            FieldValue::Number(f64::INFINITY),
            FieldValue::Number(12.0),
            ("Infinity", Some("12")),
        ),
        (
            FieldValue::from("PROFILE_REJECTED"),
            FieldValue::from(Vec::<FieldValue>::new()),
            ("PROFILE_REJECTED", Some("")),
        ),
        (
            FieldValue::from(Vec::<FieldValue>::new()),
            FieldValue::Null,
            ("", None),
        ),
        (
            FieldValue::Utf16String(Utf16String::from_units(vec![0xd800])),
            FieldValue::Utf16String(Utf16String::from_units(vec![0xdc00])),
            ("\u{fffd}", Some("\u{fffd}")),
        ),
    ] {
        let response = AuthResponse::native(
            422,
            FieldMap::from([("code".into(), code), ("message".into(), message)]).into(),
        );
        for error in [
            OAuthSignInError::from(AuthError::from(response.clone())),
            OAuthSignInError::Endpoint(response),
        ] {
            assert_eq!(
                error.redirect_parts()?,
                (expected.0.into(), expected.1.map(str::to_owned)),
            );
        }
    }
    Ok(())
}

#[test]
fn callback_preserves_errors_without_codes_and_found_redirects() -> AuthResult<()> {
    let internal =
        OAuthSignInError::from(AuthError::internal("database update failed")).redirect_parts();
    assert!(
        matches!(internal, Err(AuthError::Internal(message)) if message == "database update failed")
    );
    let bad_request =
        OAuthSignInError::from(AuthError::bad_request("custom rejection")).redirect_parts();
    assert!(
        matches!(bad_request, Err(AuthError::BadRequest(message)) if message == "custom rejection")
    );

    for response in [
        AuthResponse::json(422, &json!({"message": "custom rejection"}))?,
        AuthResponse::json(422, &json!({"code": "", "message": "custom rejection"}))?,
        AuthResponse::text(422, "custom rejection"),
    ] {
        let response = response.with_header("x-error-detail", "preserved");
        let original_body = response.body.bytes()?.into_owned();
        let error = match OAuthSignInError::from(AuthError::from(response)).redirect_parts() {
            Err(error) => error,
            Ok(_) => {
                return Err(AuthError::internal(
                    "An API error without a code was redirected",
                ));
            }
        };
        let response = error.to_auth_response();
        assert_eq!(response.status, 422);
        assert_eq!(response.body.bytes()?.as_ref(), original_body);
        assert_eq!(
            response.headers.get("x-error-detail").map(String::as_str),
            Some("preserved")
        );
    }

    let error = match OAuthSignInError::from(AuthError::redirect("https://example.test/error"))
        .redirect_parts()
    {
        Err(error) => error,
        Ok(_) => return Err(AuthError::internal("A FOUND redirect was replaced")),
    };
    assert!(error.is_found_redirect());
    let response = error.to_auth_response();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some("https://example.test/error"),
    );
    Ok(())
}
