use super::*;
use serde::Deserialize;
use serde_json::Value;
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
