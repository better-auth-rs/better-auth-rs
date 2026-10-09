#![expect(
    clippy::expect_used,
    reason = "The paired JWT contract fails immediately when captured cases or signed claims are incomplete"
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::AuthError;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};

const SECRET: &str = "email-verification-claims-contract-secret-at-least-32-characters";
const ISSUED_AT: i64 = 2_000_000_000_123;
const CALLBACK: &str = "/verified?source=mail#done";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capture {
    version: String,
    issued_at: i64,
    scenarios: Vec<Scenario>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scenario {
    name: String,
    payload: String,
    result: Option<String>,
    error: Option<String>,
    invalid_field: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    backend: String,
    scenario: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    issued_at: i64,
    jwt: CapturedJwt,
    observations: Vec<Observation>,
    follow_up_tokens: Vec<CapturedJwt>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapturedJwt {
    token: String,
    protected_header: Box<RawValue>,
    payload: String,
    claims: Box<RawValue>,
    signature_verified: bool,
}

#[derive(Deserialize)]
struct Observation {
    phase: String,
    response: Response,
}

#[derive(Deserialize)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn fixture() -> AuthResult<Capture> {
    // RawValue preserves unknown UTF-16 keys that FieldMap and serde_json::Value cannot read.
    Ok(serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/email-verification-claims-1.7.6.json"
    ))?)
}

#[derive(Debug, PartialEq)]
enum ObservedClaims {
    Scalar(FieldValue),
    Array(Vec<Self>),
    Object(BTreeMap<Vec<u8>, Self>),
}

fn observe_claims(raw: &RawValue) -> AuthResult<ObservedClaims> {
    Ok(match raw.get().as_bytes().first() {
        Some(b'{') => {
            let fields: VerificationPayload = serde_json::from_str(raw.get())?;
            ObservedClaims::Object(
                fields
                    .0
                    .into_iter()
                    .map(|(key, value)| Ok((key, observe_claims(&value)?)))
                    .collect::<AuthResult<_>>()?,
            )
        }
        Some(b'[') => ObservedClaims::Array(
            serde_json::from_str::<Vec<&RawValue>>(raw.get())?
                .into_iter()
                .map(observe_claims)
                .collect::<AuthResult<_>>()?,
        ),
        _ => {
            let value = FieldValue::parse_json(raw.get())?;
            if let Some(number) = value.as_f64().filter(|number| !number.is_finite()) {
                let label = if number.is_nan() {
                    "NaN"
                } else if number.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                };
                ObservedClaims::Object(BTreeMap::from([
                    (b"type".to_vec(), ObservedClaims::Scalar("number".into())),
                    (b"value".to_vec(), ObservedClaims::Scalar(label.into())),
                ]))
            } else {
                ObservedClaims::Scalar(value)
            }
        }
    })
}

fn verify_capture(jwt: &CapturedJwt) -> AuthResult<()> {
    assert!(jwt.signature_verified);
    let bytes = crate::plugins::jwt::verify_hs256_raw(&jwt.token, SECRET)?;
    assert_eq!(bytes, jwt.payload.as_bytes());
    let header = jwt.token.split('.').next().expect("Compact JWT header");
    let header = URL_SAFE_NO_PAD
        .decode(header)
        .expect("Captured JWT uses base64url");
    assert_eq!(header, br#"{"alg":"HS256"}"#);
    assert_eq!(
        FieldValue::parse_json(std::str::from_utf8(&header).expect("ASCII JWT header"))?,
        FieldValue::parse_json(jwt.protected_header.get())?
    );
    assert_eq!(
        observe_claims(serde_json::from_str(&jwt.payload)?)?,
        observe_claims(&jwt.claims)?
    );
    Ok(())
}

fn captured_number(fields: &VerificationPayload, name: &str) -> AuthResult<Option<f64>> {
    fields
        .field(name)?
        .map(|value| {
            if let Some(number) = value.as_f64() {
                return Ok(number);
            }
            let tag = value
                .as_object()
                .expect("Captured nonfinite number tag")
                .snapshot_fields()?;
            assert_eq!(tag.get("type").and_then(FieldValue::as_str), Some("number"));
            match tag.get("value").and_then(FieldValue::as_str) {
                Some("Infinity") => Ok(f64::INFINITY),
                Some("-Infinity") => Ok(f64::NEG_INFINITY),
                _ => Err(AuthError::internal("Unexpected captured numeric date")),
            }
        })
        .transpose()
}

fn compare_decoded(claims: &EmailVerificationClaims, jwt: &CapturedJwt) -> AuthResult<()> {
    let fields: VerificationPayload = serde_json::from_str(jwt.claims.get())?;
    assert_eq!(
        Some(FieldValue::from(claims.email.clone())),
        fields.field("email")?
    );
    assert_eq!(claims.update_to, fields.field("updateTo")?);
    assert_eq!(claims.request_type, fields.field("requestType")?);
    assert_eq!(claims.iat, captured_number(&fields, "iat")?);
    assert_eq!(claims.exp, captured_number(&fields, "exp")?);
    Ok(())
}

fn captured_response<'a>(case: &'a Case, phase: &str) -> &'a Response {
    &case
        .observations
        .iter()
        .find(|observation| observation.phase == phase)
        .expect("Captured request phase")
        .response
}

fn assert_reference_error(case: &Case, code: &str) -> AuthResult<()> {
    let response = captured_response(case, "verify");
    if case.callback_url.is_some() {
        assert_eq!(response.status, 302);
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(name, _)| name == "location")
                .map(|(_, value)| value.as_str()),
            Some(format!("/verified?source=mail&error={code}#done").as_str())
        );
    } else {
        assert_eq!(response.status, 401);
        let body = FieldValue::parse_json(&response.body)?;
        assert_eq!(
            body.as_object()
                .expect("Captured API error")
                .get("code")?
                .as_ref()
                .and_then(FieldValue::as_str),
            Some(code)
        );
    }
    Ok(())
}

#[test]
fn all_captured_claims_keep_signed_bytes_native_values_and_validation_order() -> AuthResult<()> {
    let capture = fixture()?;
    assert_eq!(capture.version, "1.7.6");
    assert_eq!(capture.issued_at, ISSUED_AT);
    assert_eq!(capture.scenarios.len(), 15);
    assert_eq!(capture.cases.len(), 60);
    let scenarios = capture
        .scenarios
        .iter()
        .map(|scenario| (scenario.name.as_str(), scenario))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(scenarios.len(), 15);
    let mut cases = BTreeSet::new();
    for case in &capture.cases {
        assert!(matches!(case.backend.as_str(), "memory" | "sqlite"));
        assert!(case.callback_url.is_none() || case.callback_url.as_deref() == Some(CALLBACK));
        assert!(cases.insert((&case.backend, &case.scenario, &case.callback_url)));
        assert_eq!(case.issued_at, ISSUED_AT);
        let scenario = scenarios
            .get(case.scenario.as_str())
            .expect("Captured scenario belongs to the complete matrix");
        assert_eq!(case.jwt.payload, scenario.payload);
        verify_capture(&case.jwt)?;
        let now = DateTime::from_timestamp_millis(case.issued_at).expect("Captured clock");
        let decoded = decode_email_verification_token_at(SECRET, &case.jwt.token, now);
        if let Some(code) = scenario.error.as_deref() {
            assert_reference_error(case, code)?;
            match code {
                "INVALID_TOKEN" => assert!(
                    matches!(&decoded, Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::ImmatureSignature),
                    "{}: {decoded:?}",
                    case.scenario
                ),
                "TOKEN_EXPIRED" => assert!(
                    matches!(&decoded, Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::ExpiredSignature),
                    "{}: {decoded:?}",
                    case.scenario
                ),
                "INVALID_USER" => compare_decoded(&decoded?, &case.jwt)?,
                _ => return Err(AuthError::internal("Unexpected captured JWT error")),
            }
        } else if scenario.invalid_field.is_some() {
            assert_eq!(captured_response(case, "verify").status, 500);
            assert!(
                matches!(&decoded, Err(AuthError::Serialization(_))),
                "{}: {decoded:?}",
                case.scenario
            );
        } else {
            assert_eq!(
                captured_response(case, "verify").status,
                if case.callback_url.is_some() {
                    302
                } else {
                    200
                }
            );
            compare_decoded(&decoded?, &case.jwt)?;
        }
    }
    assert_eq!(cases.len(), 60);
    Ok(())
}

#[test]
fn native_follow_up_tokens_match_captured_bytes_and_keep_expiration_before_business_validation()
-> AuthResult<()> {
    let capture = fixture()?;
    let mut rebuilt = 0;
    for case in &capture.cases {
        let scenario = capture
            .scenarios
            .iter()
            .find(|scenario| scenario.name == case.scenario)
            .expect("Captured follow-up scenario");
        let confirmation = scenario.result.as_deref() == Some("confirmation");
        let legacy = scenario.result.as_deref() == Some("legacy");
        assert_eq!(
            case.follow_up_tokens.len(),
            usize::from(confirmation || legacy)
        );
        let Some(jwt) = case.follow_up_tokens.first() else {
            continue;
        };
        let now = DateTime::from_timestamp_millis(case.issued_at).expect("Captured clock");
        let input = decode_email_verification_token_at(SECRET, &case.jwt.token, now)?;
        let update_to = input
            .update_to
            .expect("Captured native updateTo")
            .display_utf16()?;
        let email = if confirmation {
            input.email.into()
        } else {
            update_to.clone()
        };
        let token = create_native_token_at(
            SECRET,
            &email,
            confirmation.then_some(&update_to),
            Duration::hours(1),
            confirmation.then_some("change-email-verification"),
            now,
        )?;
        assert_eq!(token, jwt.token, "{} {}", case.backend, case.scenario);
        verify_capture(jwt)?;
        let fields: VerificationPayload = serde_json::from_str(jwt.claims.get())?;
        assert_eq!(
            captured_number(&fields, "iat")?,
            Some(now.timestamp() as f64)
        );
        assert_eq!(
            captured_number(&fields, "exp")?,
            Some(now.timestamp() as f64 + 3600.0)
        );
        let expires =
            DateTime::from_timestamp(now.timestamp() + 3600, 0).expect("Captured expiration clock");
        for read_at in [now, expires - Duration::milliseconds(1)] {
            let decoded = decode_email_verification_token_at(SECRET, &token, read_at);
            if legacy {
                assert!(matches!(decoded, Err(AuthError::Serialization(_))));
            } else {
                compare_decoded(&decoded?, jwt)?;
            }
        }
        if legacy {
            assert_eq!(captured_response(case, "follow-up").status, 500);
        }
        assert!(matches!(
            decode_email_verification_token_at(SECRET, &token, expires),
            Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::ExpiredSignature
        ));
        rebuilt += 1;
    }
    assert_eq!(rebuilt, 8);
    Ok(())
}
