#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Read the captured ordinary serializer contract and report assertion failures"
)]

use super::*;
use crate::CookieAttributes;
use serde_json::Value;

#[test]
fn explicit_expiration_validates_original_milliseconds_after_max_age() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/cookie-expires-1.7.6.json"
    )))
    .unwrap();
    let now = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    for (name, case) in fixture["serializers"].as_object().unwrap() {
        let attributes = CookieAttributes {
            expires: case["input"]["expires"]
                .as_str()
                .map(|value| value.parse().unwrap()),
            max_age: case["input"]["maxAge"].as_f64(),
            ..Default::default()
        };
        match validate_lifetime(&attributes, now) {
            Ok(()) => assert_eq!(case["result"]["ok"], true, "{name}"),
            Err(AuthError::Internal(message)) => {
                assert_eq!(case["result"]["ok"], false, "{name}");
                assert_eq!(case["result"]["error"]["message"], message, "{name}");
            }
            Err(error) => return Err(error),
        }
    }
    let mut config = AuthConfig::new("ordinary-template-expiration-secret-32-characters");
    config.advanced.default_cookie_attributes.expires =
        Some(chrono::Utc::now() + chrono::Duration::days(401));
    let template = session_cookie_template(&config).unwrap();
    assert!(template.expires_datetime().is_some());
    assert!(matches!(
        create_clear_session_cookie(&config),
        Err(AuthError::Internal(_))
    ));
    Ok(())
}
