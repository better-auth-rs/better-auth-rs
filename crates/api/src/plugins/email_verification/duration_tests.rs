#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "The paired JWT contract fails immediately on incomplete captured claims or expiration observations"
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::AuthError;
use jsonwebtoken::Algorithm;
use serde_json::{Value, json};

const SECRET: &str = "email-verification-duration-contract-secret-at-least-32-characters";
const EMAIL: &str = "owner@email-verification-duration.test";

fn fixture() -> AuthResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/email-verification-duration-1.7.6.json"
    ))?)
}

fn date(value: &Value) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(value.as_i64().expect("Captured millisecond clock"))
        .expect("Captured clock fits Chrono")
}

#[test]
fn email_verification_numeric_dates_match_all_pinned_jwts_and_expiry_boundaries() -> AuthResult<()>
{
    let fixture = fixture()?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .expect("Captured duration cases");
    assert_eq!(cases.len(), 14);
    let scenarios = fixture["scenarios"]
        .as_array()
        .expect("Captured duration scenarios");
    assert_eq!(scenarios.len(), 7);
    for (backend, cases) in ["memory", "sqlite"].into_iter().zip(cases.chunks_exact(7)) {
        for (case, scenario) in cases.iter().zip(scenarios) {
            assert_eq!(case["backend"], backend);
            assert_eq!(&case["scenario"], scenario);
            let lifetime = Duration::milliseconds(
                (scenario["expiresIn"].as_f64().expect("Captured lifetime") * 1000.0) as i64,
            );
            let token = create_email_verification_token_at(
                SECRET,
                EMAIL,
                None,
                lifetime,
                None,
                date(&case["issuedAt"]),
            )?;
            assert_eq!(
                token,
                case["jwt"]["token"].as_str().expect("Captured compact JWT"),
                "{backend} {} JWT bytes",
                scenario["name"]
            );
            let parts = token.split('.').collect::<Vec<_>>();
            assert_eq!(parts.len(), 3);
            for (part, expected) in [
                (parts[0], &case["jwt"]["protectedHeader"]),
                (parts[1], &case["jwt"]["claims"]),
            ] {
                let bytes = URL_SAFE_NO_PAD
                    .decode(part)
                    .expect("JWT uses base64url encoding");
                assert_eq!(&serde_json::from_slice::<Value>(&bytes)?, expected);
            }
            let read_at = date(&case["readAt"]);
            let result = decode_email_verification_token_at(SECRET, &token, read_at);
            let accepted = scenario["accepted"]
                .as_bool()
                .expect("Captured acceptance result");
            assert_eq!(
                result.is_ok(),
                accepted,
                "{backend} {}: {result:?}",
                scenario["name"]
            );
            if accepted {
                assert_eq!(
                    serde_json::to_value(result.expect("Accepted verification claims"))?,
                    case["jwt"]["claims"]
                );
            } else {
                assert!(
                    matches!(result, Err(AuthError::Jwt(ref error)) if error.kind() == &ErrorKind::ExpiredSignature),
                    "{backend} {} must expire at the captured integer clock: {result:?}",
                    scenario["name"]
                );
            }
            let signed = decode_email_verification_token_at(
                SECRET,
                &token,
                date(&case["issuedAt"]) - Duration::seconds(1),
            )?;
            assert_eq!(serde_json::to_value(signed)?, case["jwt"]["claims"]);
            assert_eq!(case["jwt"]["signatureVerified"], true);
        }
    }
    eprintln!(
        "Email verification duration boundary: JWT bytes, claims, signature validation, and fixed-time expiration are paired; captured HTTP, callbacks, cookies, and storage snapshots remain unpaired at the fixed clock"
    );
    Ok(())
}

#[test]
fn fractional_expiration_keeps_signature_algorithm_and_present_claim_guards() -> AuthResult<()> {
    let fixture = fixture()?;
    let case = &fixture["cases"][0];
    let token = case["jwt"]["token"]
        .as_str()
        .expect("Captured fractional token");
    let now = date(&case["issuedAt"]);
    assert!(matches!(
        decode_email_verification_token_at("wrong-signing-secret", token, now),
        Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidSignature
    ));
    let invalid_algorithm = encode(
        &Header::new(Algorithm::HS384),
        &case["jwt"]["claims"],
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )?;
    assert!(matches!(
        decode_email_verification_token_at(SECRET, &invalid_algorithm, now),
        Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidAlgorithm
    ));
    for field in ["email", "iat", "exp"] {
        let mut claims = case["jwt"]["claims"]
            .as_object()
            .expect("Captured claims")
            .clone();
        let _ = claims.remove(field);
        let missing = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )?;
        let decoded = decode_email_verification_token_at(SECRET, &missing, now);
        if field == "email" {
            assert!(matches!(decoded, Err(AuthError::Serialization(_))));
        } else {
            assert_eq!(serde_json::to_value(decoded?)?, Value::Object(claims));
        }
    }
    for expiration in [Value::Null, json!("2000000001.5")] {
        let mut claims = case["jwt"]["claims"].clone();
        claims["exp"] = expiration;
        let malformed = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )?;
        assert!(decode_email_verification_token_at(SECRET, &malformed, now).is_err());
    }
    Ok(())
}
