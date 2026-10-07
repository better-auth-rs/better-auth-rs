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

fn malformed_payloads() -> [Value; 3] {
    [
        json!({"iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": 7, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
        json!({"email": "owner@verify-payload.test", "updateTo": 7, "iat": 1_700_000_000, "exp": 4_102_444_800_u64}),
    ]
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
            let response = result.unwrap_or_else(AuthError::to_http_response);
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
