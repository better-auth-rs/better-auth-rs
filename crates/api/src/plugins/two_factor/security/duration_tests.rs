use super::*;

#[test]
fn lockout_date_matches_pinned_numeric_configuration() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/account-lockout-duration-1.7.6.json"
    )))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let config = AccountLockout {
            duration_seconds: case["configured"]
                .as_f64()
                .unwrap_or(AccountLockout::default().duration_seconds),
            ..Default::default()
        };
        let now = chrono::DateTime::from_timestamp_millis(case["anchorMillis"].as_i64().unwrap())
            .unwrap();
        let expected = chrono::DateTime::parse_from_rfc3339(
            case["events"][1]["set"]["lockedUntil"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            config.locked_until(now).unwrap(),
            expected.with_timezone(&Utc),
            "{}",
            case["name"]
        );
    }
}
