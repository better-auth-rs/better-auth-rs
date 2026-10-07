use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use totp_rs::Algorithm;

#[derive(Deserialize)]
struct Fixture {
    secret: String,
    issuer: String,
    account: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    options: Options,
    timestamp_millis: i64,
    server: Code,
    helper: Helper,
}

#[derive(Deserialize)]
struct Options {
    period: Option<f64>,
    digits: usize,
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

#[derive(Deserialize)]
struct Helper {
    code: String,
    uri: String,
}

#[test]
fn fractional_period_generation_and_uri_match_pinned_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/totp-period-1.7.6.json"
    ))?;
    for case in fixture.cases {
        let totp = Totp::new(
            TOTP::new(
                Algorithm::SHA1,
                case.options.digits,
                1,
                1,
                fixture.secret.as_bytes().to_vec(),
                Some(fixture.issuer.clone()),
                fixture.account.clone(),
            )?,
            case.options.period.unwrap_or(DEFAULT_TOTP_PERIOD_SECS),
        );
        let code = totp.generate_at(case.timestamp_millis)?;
        assert_eq!(code, case.server.code, "{} native generator", case.name);
        assert_eq!(code, case.helper.code, "{} OTP helper", case.name);
        assert_eq!(totp.get_url()?, case.helper.uri, "{} full URI", case.name);
    }
    Ok(())
}

#[test]
fn nan_period_preserves_the_uri_and_defaults_only_for_server_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/totp-period-nan-1.7.6.json"
    ))?;
    let timestamp = fixture["timestampMillis"].as_i64().expect("capture clock");
    for case in fixture["cases"].as_array().expect("captured cases") {
        let raw = Totp::new(
            TOTP::new(
                Algorithm::SHA1,
                case["options"]["digits"].as_u64().expect("digit count") as usize,
                1,
                1,
                fixture["secret"]
                    .as_str()
                    .expect("secret")
                    .as_bytes()
                    .to_vec(),
                Some(fixture["issuer"].as_str().expect("issuer").to_owned()),
                fixture["account"].as_str().expect("account").to_owned(),
            )?,
            f64::NAN,
        );
        assert_eq!(raw.get_url()?, case["helper"]["uri"]["value"]);
        let code = case["server"]["generation"]["outcome"]["value"]["code"]
            .as_str()
            .expect("captured server code");
        assert!(raw.generate_at(timestamp).is_err());
        assert!(raw.check_at(code, timestamp).is_err());
        let server = raw.with_default_period();
        assert_eq!(server.generate_at(timestamp)?, code);
        assert!(server.check_at(code, timestamp)?);
        assert!(!server.check_at("not-a-totp", timestamp)?);
        let uri: Value = serde_json::from_str(
            case["server"]["uri"]["outcome"]["value"]["body"]
                .as_str()
                .expect("captured HTTP body"),
        )?;
        assert_eq!(server.get_url()?, uri["totpURI"]);
    }
    Ok(())
}

#[tokio::test]
async fn nan_period_enrollment_uri_encodes_the_persisted_secret() -> AuthResult<()> {
    use super::super::{
        EnableRequest, EnrollmentMethod, TwoFactorConfig, decrypt_value, enable_core,
    };
    use better_auth_core::{AuthRequest, HttpMethod};
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/totp-period-nan-1.7.6.json"
    ))?;
    for case in fixture["cases"].as_array().expect("captured cases") {
        let (ctx, user, session) = super::super::tests::create_test_context_with_credential_user(
            fixture["account"].as_str().expect("account"),
            false,
        )
        .await;
        let config = TwoFactorConfig {
            totp_period: f64::NAN,
            totp_digits: case["options"]["digits"].as_u64().expect("digits") as usize,
            ..Default::default()
        };
        let (response, cookies) = enable_core(
            &AuthRequest::new(HttpMethod::Post, "/two-factor/enable"),
            &EnableRequest {
                password: Some("password123".into()),
                issuer: Some(fixture["issuer"].as_str().expect("issuer").to_owned()),
                method: EnrollmentMethod::Totp,
            },
            &user,
            &session,
            &config,
            &ctx,
        )
        .await?;
        assert!(cookies.is_empty());
        let factor = ctx
            .database
            .get_two_factor_by_user_id(user.id.typed()?)
            .await?
            .expect("stored factor");
        let secret = decrypt_value(ctx.config.encryption_secret(), &factor.secret)?;
        assert_eq!(secret.len(), 32);
        assert!(secret.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(factor.verified, Some(false));
        let uri = response.totp_uri.expect("TOTP enrollment URI");
        let parsed = url::Url::parse(&uri).expect("valid enrollment URI");
        let encoded = parsed
            .query_pairs()
            .find(|(key, _)| key == "secret")
            .expect("URI secret")
            .1
            .into_owned();
        assert_eq!(
            totp_rs::Secret::Encoded(encoded.clone())
                .to_bytes()
                .expect("valid Base32"),
            secret.as_bytes()
        );
        let expected: Value = serde_json::from_str(
            case["enrollment"]["enable"]["outcome"]["value"]["body"]
                .as_str()
                .expect("captured body"),
        )?;
        assert_eq!(
            uri.replace(&encoded, "<enrollment-secret-base32>"),
            expected["totpURI"]
        );
        let codes: Value = serde_json::from_str(&decrypt_value(
            ctx.config.encryption_secret(),
            &factor.backup_codes,
        )?)?;
        assert_eq!(codes, serde_json::to_value(response.backup_codes)?);
    }
    Ok(())
}

fn counter_fixture_number(value: &Value) -> f64 {
    if let Some(number) = value.as_f64() {
        return number;
    }
    assert_eq!(value["type"], "number");
    match value["value"].as_str().expect("non-finite Number") {
        "Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        value => panic!("unexpected captured Number: {value}"),
    }
}

fn assert_captured_counter(actual: f64, captured: &Value, label: &str) {
    assert_eq!(
        actual,
        counter_fixture_number(&captured["rawNumber"]),
        "{label} raw Number"
    );
    assert_eq!(
        actual == 0.0 && actual.is_sign_negative(),
        captured["negativeZero"]
            .as_bool()
            .expect("negative-zero flag"),
        "{label} negative zero"
    );
}

fn assert_counter_outcome<T: Serialize>(actual: &AuthResult<T>, captured: &Value, label: &str) {
    match actual {
        Ok(value) => assert_eq!(
            json!({ "kind": "returned", "value": value }),
            *captured,
            "{label}"
        ),
        Err(AuthError::Config(message)) => {
            assert_eq!(message, "Not an integer", "{label} Rust Config payload");
            // Bun's error class and own source properties remain observations; Rust exposes the Config payload.
            assert_eq!(
                *captured,
                json!({
                    "kind": "thrown",
                    "error": {
                        "name": "RangeError",
                        "message": "Not an integer",
                        "keys": ["message", "originalLine", "originalColumn", "line", "column", "sourceURL"],
                        "properties": {
                            "message": "Not an integer",
                            "originalLine": 23,
                            "originalColumn": 46,
                            "line": 26,
                            "column": 40,
                            "sourceURL": "/home/runner/work/better-auth-rs/better-auth-rs/compat-tests/reference-server/node_modules/@better-auth/utils/dist/otp.mjs"
                        }
                    }
                }),
                "{label} upstream error observation"
            );
        }
        Err(error) => panic!("{label}: unexpected Rust error: {error:?}"),
    }
}

#[test]
fn counter_boundaries_and_verification_windows_match_pinned_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/totp-counter-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["utilsVersion"], "0.4.2");
    let cases = fixture["cases"].as_array().expect("captured cases");
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let timestamp = case["timestampMillis"].as_i64().expect("capture clock");
        let totp = Totp::new(
            TOTP::new(
                Algorithm::SHA1,
                case["options"]["digits"].as_u64().expect("digit count") as usize,
                1,
                1,
                fixture["secret"]
                    .as_str()
                    .expect("secret")
                    .as_bytes()
                    .to_vec(),
                Some(fixture["issuer"].as_str().expect("issuer").to_owned()),
                fixture["account"].as_str().expect("account").to_owned(),
            )?,
            counter_fixture_number(&case["options"]["period"]),
        );
        assert_eq!(
            (totp.period * 1000.0).to_bits(),
            counter_fixture_number(&case["milliseconds"]).to_bits(),
            "{name} milliseconds"
        );
        let counter = totp.counter(timestamp);
        assert_captured_counter(counter, &case["counter"], name);
        assert_counter_outcome(
            &totp
                .generate_at(timestamp)
                .map(|code| json!({ "code": code })),
            &case["server"],
            &format!("{name} native generation"),
        );
        assert_counter_outcome(
            &totp.generate_at(timestamp),
            &case["helper"]["generation"],
            &format!("{name} helper generation"),
        );
        assert_counter_outcome(
            &totp.get_url(),
            &case["helper"]["uri"],
            &format!("{name} full URI"),
        );
        let neighbors = case["helper"]["neighbors"]
            .as_array()
            .expect("Number neighbors");
        assert_eq!(neighbors.len(), 5, "{name} Number neighbor inventory");
        for (offset, neighbor) in (-2..=2).zip(neighbors) {
            assert_eq!(neighbor["offset"], offset, "{name} neighbor offset");
            let label = format!("{name} neighbor {offset}");
            let raw_counter = counter + f64::from(offset);
            assert_captured_counter(raw_counter, &neighbor["counter"], &label);
            let generated = Totp::hotp_counter(raw_counter).map(|value| totp.inner.generate(value));
            assert_counter_outcome(&generated, &neighbor["hotp"], &label);
            match generated {
                Ok(token) => {
                    assert_eq!(token, neighbor["token"], "{label} token");
                    assert_counter_outcome(
                        &totp.check_at(&token, timestamp),
                        &neighbor["verification"],
                        &label,
                    );
                }
                Err(_) => {
                    assert_eq!(neighbor["token"], json!({ "type": "undefined" }), "{label}");
                    assert_eq!(
                        neighbor["verification"],
                        json!({ "kind": "not-run", "reason": "HOTP generation threw before producing a token" }),
                        "{label} unavailable token"
                    );
                }
            }
        }
        let bigint_neighbors = case["helper"]["bigintNeighbors"]
            .as_array()
            .expect("BigInt neighbors");
        let expected_counters: &[&str] = match name {
            "counter-two-to-53" => &["9007199254740993"],
            "counter-two-to-64" => &["18446744073709551615"],
            _ => &[],
        };
        assert_eq!(bigint_neighbors.len(), expected_counters.len(), "{name}");
        for (neighbor, expected) in bigint_neighbors.iter().zip(expected_counters) {
            let decimal = neighbor["decimalCounter"]
                .as_str()
                .expect("decimal counter");
            assert_eq!(decimal, *expected, "{name} exact integer counter");
            let token = totp.inner.generate(decimal.parse::<u64>()?);
            let label = format!("{name} BigInt neighbor {decimal}");
            assert_counter_outcome(&Ok(&token), &neighbor["hotp"], &label);
            assert_eq!(token, neighbor["token"], "{label} token");
            assert_eq!(
                neighbor["verification"],
                json!({ "kind": "returned", "value": false }),
                "{label} upstream rejection"
            );
            assert_counter_outcome(
                &totp.check_at(&token, timestamp),
                &neighbor["verification"],
                &label,
            );
        }
        let malformed = &case["helper"]["malformed"];
        let token = malformed["token"].as_str().expect("malformed token");
        assert_counter_outcome(
            &totp.check_at(token, timestamp),
            &malformed["verification"],
            &format!("{name} malformed token"),
        );
    }
    Ok(())
}
