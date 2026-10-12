#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::OAuthSignInError;
use better_auth_core::{AuthError, AuthResponse, AuthResult, FieldMap, FieldValue, Utf16String};
use serde_json::json;

#[test]
fn callback_reads_description_before_code_coercion_and_preserves_conversion_errors()
-> AuthResult<()> {
    use better_auth_core::{FieldFunction, FieldObject};
    use std::sync::{Arc, Mutex};

    let events = Arc::new(Mutex::new(Vec::new()));
    let message = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let events = events.clone();
            move |_, _| {
                events
                    .lock()
                    .map_err(|_| AuthError::internal("OAuth trace lock poisoned"))?
                    .push("message");
                Ok("original description".into())
            }
        })
        .into(),
    )]);
    let body = FieldObject::from(FieldMap::from([("message".into(), message.into())]));
    let code = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let body = body.clone();
            let events = events.clone();
            move |_, _| {
                events
                    .lock()
                    .map_err(|_| AuthError::internal("OAuth trace lock poisoned"))?
                    .push("code");
                body.set("message", "changed description".into())?;
                Ok("PROFILE_REJECTED".into())
            }
        })
        .into(),
    )]);
    body.set("code", code.into())?;
    let raw: FieldValue = FieldMap::from([
        ("name".into(), "APIError".into()),
        ("body".into(), FieldValue::Object(body.clone())),
    ])
    .into();
    let result = OAuthSignInError::from(AuthError::from_thrown(raw)).redirect_parts();
    let _ = body.delete("code")?;
    assert_eq!(
        result?,
        (
            "PROFILE_REJECTED".into(),
            Some("original description".into())
        )
    );
    assert_eq!(body.get("message")?, Some("changed description".into()));
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("OAuth trace lock poisoned"))?,
        ["code", "message"]
    );

    let thrown: FieldValue = FieldMap::from([("reason".into(), "coercion failure".into())]).into();
    let code: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let thrown = thrown.clone();
            move |_, _| Err(AuthError::from_thrown(thrown.clone()))
        })
        .into(),
    )])
    .into();
    let raw = FieldMap::from([
        ("name".into(), "APIError".into()),
        (
            "body".into(),
            FieldMap::from([("code".into(), code)]).into(),
        ),
    ])
    .into();
    let result = OAuthSignInError::from(AuthError::from_thrown(raw)).redirect_parts();
    assert!(
        matches!(result, Err(error) if error.raw_value().is_some_and(|value| value.strict_equals(&thrown)))
    );
    Ok(())
}

#[test]
fn oauth_database_catches_preserve_structural_api_errors_before_the_fallback() {
    let raw: FieldValue = FieldMap::from([
        ("name".into(), "APIError".into()),
        ("body".into(), json!({"code":"DATABASE_REJECTED"}).into()),
    ])
    .into();
    let mut calls = 0;
    let result = super::api_error_or(AuthError::from_thrown(raw.clone()), |_| {
        calls += 1;
        Ok(OAuthSignInError::Generic("fallback".into()))
    });
    assert_eq!(calls, 0);
    assert!(
        matches!(result, OAuthSignInError::Auth(error) if error.raw_value().is_some_and(|value| value.strict_equals(&raw)))
    );
    let result = super::api_error_or(AuthError::internal("database failed"), |error| {
        calls += 1;
        Ok(OAuthSignInError::Auth(error))
    });
    assert_eq!(calls, 1);
    assert!(
        matches!(result, OAuthSignInError::Auth(AuthError::Internal(message)) if message == "database failed")
    );
}

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
            OAuthSignInError::Auth(AuthError::from_returned_response(
                AuthError::from(response)
                    .to_auth_response()
                    .expect("fixture response succeeds"),
            )?),
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
        let response = error.to_auth_response().expect("fixture response succeeds");
        assert_eq!(
            response.api_error_status()?,
            better_auth_core::SchemaValue::Typed(422)
        );
        assert_eq!(
            better_auth_core::ResponseBody::Native(response.api_error_body()?)
                .bytes()?
                .as_ref(),
            original_body
        );
        assert_eq!(
            response
                .api_error_headers()?
                .get("x-error-detail")
                .map(String::as_str),
            Some("preserved")
        );
    }

    let error = match OAuthSignInError::from(AuthError::redirect("https://example.test/error"))
        .redirect_parts()
    {
        Err(error) => error,
        Ok(_) => return Err(AuthError::internal("A FOUND redirect was replaced")),
    };
    assert!(error.is_found_redirect().unwrap());
    let response = error.to_auth_response().expect("fixture response succeeds");
    assert_eq!(
        response.api_error_status()?,
        better_auth_core::SchemaValue::Typed(302)
    );
    assert_eq!(
        response
            .api_error_headers()?
            .get("location")
            .map(String::as_str),
        Some("https://example.test/error"),
    );
    Ok(())
}
