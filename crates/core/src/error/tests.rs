#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;

#[test]
fn endpoint_error_preserves_body_headers_and_redacts_diagnostics() {
    let body = serde_json::json!({"code":"RATE_LIMITED", "message":"Rate limit exceeded.", "details":{"tryAgainIn":1234}});
    let mut response = crate::types::AuthResponse::json(429, &body).unwrap();
    response.headers.append("Set-Cookie", "sensitive=first");
    response.headers.append("Set-Cookie", "sensitive=second");
    let error = AuthError::from(response);
    assert_eq!(error.status_code().unwrap(), 429);
    assert!(!format!("{error:?} {error}").contains("sensitive"));
    assert!(!format!("{error:?} {error}").contains("tryAgainIn"));
    let response = error
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
        body
    );
    assert_eq!(
        response.headers.get_all("set-cookie").collect::<Vec<_>>(),
        ["sensitive=first", "sensitive=second"]
    );
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn endpoint_error_into_axum_preserves_json_and_repeated_headers() {
    use axum::response::IntoResponse;
    for router_failure in [false, true] {
        let mut response = crate::types::AuthResponse::json(
            429,
            &serde_json::json!({"details":{"tryAgainIn":1234}}),
        )
        .unwrap();
        response.headers.append("Set-Cookie", "first=1");
        response.headers.append("Set-Cookie", "second=2");
        let error = AuthError::from(response);
        let output = if router_failure {
            finish_axum_response(crate::api_error::HttpFailure::Source(error).into_response())
        } else {
            error.into_response()
        };
        assert_eq!(output.status(), 429);
        assert_eq!(output.headers().get_all("set-cookie").iter().count(), 2);
        assert_eq!(output.headers()["content-type"], "application/json");
        let body = axum::body::to_bytes(output.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["details"]["tryAgainIn"],
            1234
        );
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn database_errors_are_sanitized_at_both_axum_error_boundaries() {
    use axum::response::IntoResponse;

    for router_failure in [false, true] {
        for properties in [
            None,
            Some(FieldMap::from([
                ("message".into(), "private query".into()),
                ("name".into(), "error".into()),
                ("detail".into(), "private row".into()),
                ("schema".into(), "private schema".into()),
                ("table".into(), "private table".into()),
            ])),
        ] {
            let cause = DatabaseErrorCause::from_source(
                "private diagnostic",
                std::io::Error::other("private source"),
                properties,
            );
            let error = AuthError::Database(DatabaseError::Query(cause));
            let response = if router_failure {
                finish_axum_response(crate::api_error::HttpFailure::Source(error).into_response())
            } else {
                error.into_response()
            };
            assert_eq!(
                response.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("The sanitized database error body must be readable");
            assert!(body.is_empty());
        }
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn api_errors_are_materialized_once_at_both_axum_error_boundaries() {
    use axum::response::IntoResponse;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    for router_failure in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let error = AuthError::try_api_error(ApiErrorInit {
            status: "TOO_MANY_REQUESTS".into(),
            body: FieldMap::from([(
                "toJSON".into(),
                crate::FieldFunction::contextual(move |_, _| {
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Ok(FieldMap::from([("retryAfter".into(), 7.0.into())]).into())
                })
                .into(),
            )])
            .into(),
            headers: FieldMap::from([("retry-after".into(), "7".into())]).into(),
            ..Default::default()
        })
        .expect("The native API error must construct");
        let response = if router_failure {
            finish_axum_response(crate::api_error::HttpFailure::Source(error).into_response())
        } else {
            error.into_response()
        };
        assert_eq!(response.status(), 429);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("The API error body must be readable");
        assert_eq!(body.as_ref(), br#"{"retryAfter":7}"#);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

// ── status_code ─────────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn bad_request_is_400() {
    assert_eq!(AuthError::bad_request("oops").status_code().unwrap(), 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn invalid_request_is_400() {
    assert_eq!(
        AuthError::InvalidRequest("x".into()).status_code().unwrap(),
        400
    );
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn validation_is_400() {
    assert_eq!(AuthError::validation("x").status_code().unwrap(), 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn invalid_credentials_is_401() {
    assert_eq!(AuthError::InvalidCredentials.status_code().unwrap(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unauthenticated_is_401() {
    assert_eq!(AuthError::Unauthenticated.status_code().unwrap(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn session_not_found_is_401() {
    assert_eq!(AuthError::SessionNotFound.status_code().unwrap(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn forbidden_is_403() {
    assert_eq!(AuthError::forbidden("nope").status_code().unwrap(), 403);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unauthorized_is_403() {
    assert_eq!(AuthError::Unauthorized.status_code().unwrap(), 403);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn not_found_is_404() {
    assert_eq!(AuthError::not_found("gone").status_code().unwrap(), 404);
    assert_eq!(AuthError::UserNotFound.status_code().unwrap(), 404);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn conflict_is_409() {
    assert_eq!(AuthError::conflict("dup").status_code().unwrap(), 409);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unprocessable_entity_is_422() {
    assert_eq!(
        AuthError::UnprocessableEntity("x".into())
            .status_code()
            .unwrap(),
        422
    );
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn rate_limited_is_429() {
    assert_eq!(AuthError::RateLimited.status_code().unwrap(), 429);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn not_implemented_is_501() {
    assert_eq!(
        AuthError::not_implemented("todo").status_code().unwrap(),
        501
    );
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn internal_errors_are_500() {
    assert_eq!(AuthError::config("bad").status_code().unwrap(), 500);
    assert_eq!(AuthError::internal("fail").status_code().unwrap(), 500);
    assert_eq!(AuthError::plugin("p", "m").status_code().unwrap(), 500);
    assert_eq!(
        AuthError::PasswordHash("h".into()).status_code().unwrap(),
        500
    );
    assert_eq!(
        AuthError::Database(DatabaseError::Connection("c".into()))
            .to_http_response()
            .unwrap()
            .status,
        500
    );
}

// ── code_from_message ───────────────────────────────────────────────

// Upstream reference: BASE_ERROR_CODES in @better-auth/core — a message
// upstream defines a constant for carries that constant.
#[test]
fn code_from_message_returns_the_upstream_constant() {
    assert_eq!(
        AuthError::code_from_message("User not found").as_deref(),
        Some("USER_NOT_FOUND")
    );
}

// Upstream reference: packages/core/src/error/index.ts :: `APIError.from`
// attaches a code, while `new APIError(status, { message })` does not — so
// a message outside every upstream table has no code on the wire.
#[test]
fn code_from_message_is_none_for_unknown_messages() {
    assert_eq!(AuthError::code_from_message("invalid email!"), None);
    assert_eq!(AuthError::code_from_message("Email is the same"), None);
    assert_eq!(AuthError::code_from_message(""), None);
}

// Upstream reference: plugin tables built with `defineErrorCodes` are part
// of the same vocabulary, not just the base set.
#[test]
fn code_from_message_covers_plugin_tables() {
    assert_eq!(
        AuthError::code_from_message("Username is already taken. Please try another.").as_deref(),
        Some("USERNAME_IS_ALREADY_TAKEN")
    );
}

// Upstream reference: BASE_ERROR_CODES in @better-auth/core ::
// packages/core/src/error/codes.ts — codes are explicit constants since
// better-auth 1.5, so these must not be re-derived from the message.
#[test]
fn base_error_codes_are_not_derived_from_the_message() {
    for (message, expected) in [
        ("Invalid callbackURL", "INVALID_CALLBACK_URL"),
        ("Invalid redirectURL", "INVALID_REDIRECT_URL"),
        ("Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
        (
            "Invalid newUserCallbackURL",
            "INVALID_NEW_USER_CALLBACK_URL",
        ),
        ("Email is already verified", "EMAIL_ALREADY_VERIFIED"),
        (
            "Verification email isn't enabled",
            "VERIFICATION_EMAIL_NOT_ENABLED",
        ),
        (
            "Session expired. Re-authenticate to perform this action.",
            "SESSION_EXPIRED",
        ),
        (
            "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
            "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
        ),
    ] {
        assert_eq!(
            AuthError::code_from_message(message).as_deref(),
            Some(expected),
            "message {message:?} must carry the upstream constant"
        );
    }
}

// ── error_payload ───────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn error_payload_for_client_error() {
    // Not an upstream message, so it goes out without a code.
    let (status, code, message) = AuthError::bad_request("Missing field")
        .error_payload()
        .unwrap();
    assert_eq!(status, 400);
    assert_eq!(code, None);
    assert_eq!(message, "Missing field");

    let (status, code, message) = AuthError::bad_request("Field is required")
        .error_payload()
        .unwrap();
    assert_eq!(status, 400);
    assert_eq!(code.as_deref(), Some("MISSING_FIELD"));
    assert_eq!(message, "Field is required");
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn error_payload_for_internal_error_hides_details() {
    let (status, _code, message) = AuthError::internal("secret detail")
        .error_payload()
        .unwrap();
    assert_eq!(status, 500);
    assert_eq!(message, "Internal server error");
}

// ── to_auth_response ────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn to_auth_response_returns_correct_status() {
    let resp = AuthError::bad_request("oops")
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()
        .unwrap();
    assert_eq!(resp.status, 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn to_auth_response_body_contains_code_and_message() {
    let resp = AuthError::UserNotFound
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()
        .unwrap();
    assert_eq!(resp.status, 404);
    let body: serde_json::Value = serde_json::from_slice(&resp.body.bytes().unwrap())
        .expect("response body should be valid JSON");
    assert_eq!(body["code"], "USER_NOT_FOUND");
    assert_eq!(body["message"], "User not found");
}

// ── constructor helpers ──────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn constructor_helpers_produce_correct_variants() {
    // Each helper should produce the expected Display output
    assert_eq!(AuthError::bad_request("x").to_string(), "x");
    assert_eq!(AuthError::forbidden("x").to_string(), "x");
    assert_eq!(AuthError::not_found("x").to_string(), "x");
    assert_eq!(AuthError::conflict("x").to_string(), "x");
    assert_eq!(AuthError::not_implemented("x").to_string(), "x");
    assert_eq!(AuthError::config("x").to_string(), "Configuration error: x");
    assert_eq!(
        AuthError::internal("x").to_string(),
        "Internal server error: x"
    );
    assert_eq!(
        AuthError::validation("x").to_string(),
        "Validation error: x"
    );
    assert_eq!(
        AuthError::plugin("p", "m").to_string(),
        "Plugin error: p - m"
    );
}

// ── DatabaseError ───────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn database_error_display() {
    let e = DatabaseError::Connection("timeout".into());
    assert_eq!(e.to_string(), "Connection error: timeout");
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn database_error_converts_to_auth_error() {
    let db_err = DatabaseError::Query("bad sql".into());
    let auth_err: AuthError = db_err.into();
    assert!(auth_err.status_code().unwrap().is_undefined());
    assert_eq!(auth_err.to_http_response().unwrap().status, 500);
}

// ── validation_error_response ───────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn validation_error_response_serializes_field_errors() {
    let mut errors = validator::ValidationErrors::new();
    let mut error = validator::ValidationError::new("email");
    error.message = Some("Email is invalid".into());
    errors.add("email", error);

    let resp = validation_error_response(&errors);
    assert_eq!(resp.status, 400);
    let body: serde_json::Value = serde_json::from_slice(&resp.body.bytes().unwrap())
        .expect("response body should be valid JSON");
    assert_eq!(body["code"], "VALIDATION_ERROR");
    assert_eq!(body["message"], "[body.email] Email is invalid");
}

#[test]
fn request_validation_uses_native_errors_and_preserves_http_bodies() -> AuthResult<()> {
    #[derive(Debug, serde::Deserialize, validator::Validate)]
    struct Body {
        #[validate(length(min = 3, message = "Name is too short"))]
        name: String,
    }
    let mut request = crate::types::AuthRequest::new(crate::types::HttpMethod::Post, "/validate");
    request.body = Some(br#"{"name":"valid"}"#.to_vec());
    assert_eq!(validate_request_body::<Body>(&request)?.name, "valid");

    request.body = Some(br#"{"name":"x"}"#.to_vec());
    let error = validate_request_body::<Body>(&request).unwrap_err();
    assert!(error.is_api_error()?);
    let response = error
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()?;
    assert_eq!(response.status, 400);
    assert_eq!(
        response.body.bytes()?.as_ref(),
        br#"{"code":"VALIDATION_ERROR","message":"[body.name] Name is too short"}"#
    );

    request.body = Some(b"{".to_vec());
    let message = format!(
        "Invalid JSON: {}",
        request.body_as_json::<Body>().unwrap_err()
    );
    let error = validate_request_body::<Body>(&request).unwrap_err();
    assert!(error.is_api_error()?);
    let response = error
        .to_auth_response()
        .expect("fixture response succeeds")
        .into_http_response()?;
    assert_eq!(response.status, 400);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes()?)?,
        serde_json::json!({"message": message})
    );
    Ok(())
}

// ── Display for fixed-message variants ──────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn fixed_message_variants_display() {
    assert_eq!(
        AuthError::InvalidCredentials.to_string(),
        "Invalid email or password"
    );
    assert_eq!(AuthError::Unauthenticated.to_string(), "Unauthorized");
    assert_eq!(
        AuthError::SessionNotFound.to_string(),
        "Session not found or expired"
    );
    assert_eq!(
        AuthError::Unauthorized.to_string(),
        "Insufficient permissions"
    );
    assert_eq!(AuthError::UserNotFound.to_string(), "User not found");
    assert_eq!(AuthError::RateLimited.to_string(), "Too many requests");
}
