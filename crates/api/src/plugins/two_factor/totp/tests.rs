use super::*;
use serde::Deserialize;
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
        )?;
        let code = totp.generate_at(case.timestamp_millis)?;
        assert_eq!(code, case.server.code, "{} native generator", case.name);
        assert_eq!(code, case.helper.code, "{} OTP helper", case.name);
        assert_eq!(totp.get_url()?, case.helper.uri, "{} full URI", case.name);
    }
    Ok(())
}
