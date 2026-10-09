#![expect(
    clippy::expect_used,
    reason = "The regression contract fails immediately on invalid JWT boundaries or incomplete fixture setup"
)]

use super::*;
use crate::plugins::{email_verification::EmailVerificationPlugin, test_helpers};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, HttpMethod};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;

const SECRET: &str = "email-verification-payload-contract-secret-at-least-32-characters";

fn signed(payload: &str, secret: &str) -> String {
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(payload),
    );
    let mut signer = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts the fixture key length");
    signer.update(message.as_bytes());
    format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes())
    )
}

fn malformed_payloads() -> Vec<Value> {
    vec![
        json!({"iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": 7, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "owner@verify-payload.test", "updateTo": 7, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "not-an-email", "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "owner@verify-payload.test", "updateTo": null, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "owner@verify-payload.test", "requestType": null, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "owner@verify-payload.test", "requestType": false, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
    ]
}

#[test]
fn optional_dates_use_jose_types_order_and_fractional_boundaries() -> AuthResult<()> {
    let now =
        DateTime::from_timestamp(2_000_000_000, 900_000_000).expect("Fixture clock fits Chrono");
    for extra in [
        json!({}),
        json!({"iat": -0.5}),
        json!({"iat": 4_102_444_800.5}),
        json!({"nbf": 2_000_000_000.0}),
        json!({"nbf": -0.5, "exp": 2_000_000_000.25}),
        json!({"aud": "unrestricted", "iss": false, "sub": [7]}),
    ] {
        let mut payload = json!({"email":"owner@verify-payload.test"});
        payload
            .as_object_mut()
            .expect("Fixture object")
            .extend(extra.as_object().expect("Fixture extra fields").clone());
        let token = signed(&serde_json::to_string(&payload)?, SECRET);
        let claims = decode_email_verification_token_at(SECRET, &token, now)?;
        assert_eq!(claims.email, "owner@verify-payload.test");
        assert_eq!(claims.iat, payload.get("iat").and_then(Value::as_f64));
        assert_eq!(claims.exp, payload.get("exp").and_then(Value::as_f64));
    }
    for field in ["iat", "nbf", "exp"] {
        for invalid in [
            Value::Null,
            json!("2000000000"),
            json!(true),
            json!([]),
            json!({}),
        ] {
            let mut payload = json!({"email":"owner@verify-payload.test"});
            let _ = payload
                .as_object_mut()
                .expect("Fixture object")
                .insert(field.into(), invalid);
            let token = signed(&serde_json::to_string(&payload)?, SECRET);
            assert!(matches!(
                decode_email_verification_token_at(SECRET, &token, now),
                Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidClaimFormat(field.into())
            ));
        }
    }
    for (payload, expected) in [
        (
            json!({"email":"invalid", "iat":null, "exp":0}),
            ErrorKind::InvalidClaimFormat("iat".into()),
        ),
        (
            json!({"email":"invalid", "nbf":2_000_000_000.25, "exp":0}),
            ErrorKind::ImmatureSignature,
        ),
        (
            json!({"email":"invalid", "nbf":null, "exp":0}),
            ErrorKind::InvalidClaimFormat("nbf".into()),
        ),
        (
            json!({"email":"invalid", "exp":2_000_000_000.0, "updateTo":null}),
            ErrorKind::ExpiredSignature,
        ),
    ] {
        let token = signed(&serde_json::to_string(&payload)?, SECRET);
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &token, now),
            Err(AuthError::Jwt(error)) if error.kind() == &expected
        ));
    }
    Ok(())
}

#[test]
fn native_payload_preserves_duplicate_claims_overflow_and_utf16_values() -> AuthResult<()> {
    let now = DateTime::from_timestamp(2_000_000_000, 0).expect("Fixture clock fits Chrono");
    let token = signed(
        r#"{"email":"invalid","email":"owner@verify-payload.test","iat":null,"iat":1e400,"nbf":1e400,"nbf":-1e400,"exp":0,"exp":1e400,"aud":"ignored","aud":null,"iss":false,"sub":[],"\ud800":"ignored","extra":{"\ud800":1e400},"updateTo":"NEW\ud800@EXAMPLE.TEST","requestType":"\udc00"}"#,
        SECRET,
    );
    let claims = decode_email_verification_token_at(SECRET, &token, now)?;
    assert_eq!(claims.email, "owner@verify-payload.test");
    assert_eq!(claims.iat, Some(f64::INFINITY));
    assert_eq!(claims.exp, Some(f64::INFINITY));
    assert_eq!(
        claims.update_to,
        Some(better_auth_core::FieldValue::parse_json(
            r#""NEW\ud800@EXAMPLE.TEST""#
        )?)
    );
    assert_eq!(
        claims.request_type,
        Some(better_auth_core::FieldValue::parse_json(r#""\udc00""#)?)
    );
    for (payload, expired) in [
        (
            r#"{"email":"owner@verify-payload.test","exp":1e400,"exp":-1e400}"#,
            true,
        ),
        (
            r#"{"email":"owner@verify-payload.test","nbf":-1e400,"nbf":1e400,"exp":-1e400}"#,
            false,
        ),
    ] {
        let token = signed(payload, SECRET);
        let expected = if expired {
            ErrorKind::ExpiredSignature
        } else {
            ErrorKind::ImmatureSignature
        };
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &token, now),
            Err(AuthError::Jwt(error)) if error.kind() == &expected
        ));
    }
    for payload in [
        r#"{"email":"\ud800"}"#,
        r#"{"email":"owner@verify-payload.test","updateTo":{"\ud800":0}}"#,
    ] {
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &signed(payload, SECRET), now),
            Err(AuthError::Serialization(_))
        ));
    }
    Ok(())
}

#[test]
fn jwt_guards_precede_business_payload_parsing() -> AuthResult<()> {
    let now = DateTime::from_timestamp(2_000_000_000, 0).expect("Fixture clock fits Chrono");
    for mut payload in malformed_payloads() {
        let token = signed(&serde_json::to_string(&payload)?, SECRET);
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &token, now),
            Err(AuthError::Serialization(_))
        ));
        assert!(matches!(
            decode_email_verification_token_at("wrong-secret", &token, now),
            Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidSignature
        ));
        let _ = payload
            .as_object_mut()
            .expect("Fixture payload is an object")
            .insert("exp".into(), json!(now.timestamp()));
        let expired = signed(&serde_json::to_string(&payload)?, SECRET);
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &expired, now),
            Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::ExpiredSignature
        ));
    }
    assert!(matches!(
        decode_email_verification_token_at(SECRET, &signed("{", SECRET), now),
        Err(AuthError::Jwt(_))
    ));
    Ok(())
}

#[tokio::test]
async fn business_payload_errors_remain_server_errors_with_callback_urls() -> AuthResult<()> {
    let ctx = test_helpers::create_test_context().await;
    let plugin = EmailVerificationPlugin::new();
    let secret = ctx.config.signing_secret();
    let mut cases = malformed_payloads()
        .into_iter()
        .map(|payload| Ok((signed(&serde_json::to_string(&payload)?, secret), true)))
        .collect::<AuthResult<Vec<_>>>()?;
    cases.push((signed("{", secret), false));
    cases.push((
        signed(
            r#"{"email":"owner@verify-payload.test","iat":1700000000,"exp":4102444800}"#,
            "wrong-secret",
        ),
        false,
    ));
    for (token, business_error) in cases {
        for callback in [None, Some("/verified?source=mail#done")] {
            let mut query = HashMap::from([("token".to_owned(), token.clone())]);
            if let Some(callback) = callback {
                let _ = query.insert("callbackURL".to_owned(), callback.to_owned());
            }
            let request = test_helpers::create_auth_request(
                HttpMethod::Get,
                "/verify-email",
                None,
                None,
                query,
            );
            let result = plugin.handle_verify_email(&request, &ctx).await;
            if business_error {
                assert!(matches!(&result, Err(AuthError::Serialization(_))));
            }
            let response = result.or_else(AuthError::to_http_response)?;
            assert!(response.headers.get_all("set-cookie").next().is_none());
            if business_error {
                assert_eq!(response.status, 500);
                assert!(response.body.bytes()?.is_empty());
                assert!(response.headers.get("location").is_none());
            } else if callback.is_some() {
                assert_eq!(response.status, 302);
                assert_eq!(
                    response.headers.get("location").map(String::as_str),
                    Some("/verified?source=mail&error=INVALID_TOKEN#done")
                );
            } else {
                assert_eq!(response.status, 401);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                    json!({"code": "INVALID_TOKEN", "message": "Invalid token"})
                );
            }
        }
    }
    eprintln!(
        "Email malformed payload boundary: source-backed regression; upstream capture remains unpaired until CI produces a golden fixture"
    );
    Ok(())
}
