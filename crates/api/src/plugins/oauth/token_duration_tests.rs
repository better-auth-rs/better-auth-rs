use super::super::generic::GenericOAuthConfig;
use super::super::providers::OAuthProvider;
use super::super::resolved::ResolvedGenericOAuth;
use super::*;
use serde::Deserialize;
use serde_json::json;

const NOW: i64 = 2_000_000_000_123;

fn provider(fallback: Option<f64>) -> ResolvedProvider {
    ResolvedProvider {
        config: OAuthProvider::google("duration-client", "duration-client-secret"),
        generic: Some(ResolvedGenericOAuth {
            config: GenericOAuthConfig {
                access_token_expires_in: fallback,
                ..Default::default()
            },
            issuer: None,
            is_oidc: false,
            verifier: None,
        }),
    }
}

#[test]
fn oauth_expiry_adds_submilliseconds_before_timeclip() -> AuthResult<()> {
    // The positive clock matches the pinned capture; negative clocks check TimeClip's truncation direction.
    for (now, seconds, expected) in [
        (NOW, -0.0005, NOW - 1),
        (NOW, 0.0005, NOW),
        (NOW, 1.5, NOW + 1500),
        (NOW, 0.0, NOW),
        (-NOW, 0.0005, -NOW + 1),
        (-NOW, -0.0005, -NOW),
    ] {
        let now = DateTime::from_timestamp_millis(now)
            .ok_or_else(|| AuthError::internal("OAuth test clock is out of range"))?;
        assert_eq!(expiry_from(now, seconds)?.milliseconds(), expected as f64);
    }
    Ok(())
}

#[derive(Deserialize)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    backend: String,
    scenario: Scenario,
    now: i64,
    helpers: Vec<Helper>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    #[serde(rename = "fallbackDuration")]
    fallback: Option<Value>,
}

#[derive(Deserialize)]
struct Helper {
    operation: String,
    outcome: Value,
    events: Vec<Value>,
}

fn observed_tokens(tokens: OAuthTokenSet, exchange: bool) -> AuthResult<Value> {
    let mut observed = serde_json::Map::from_iter([
        ("tokenType".into(), json!(tokens.token_type)),
        ("accessToken".into(), json!(tokens.access_token)),
        ("refreshToken".into(), json!(tokens.refresh_token)),
        ("idToken".into(), json!(tokens.id_token)),
        ("scopes".into(), json!(tokens.scopes)),
    ]);
    for (name, value) in [
        ("accessTokenExpiresAt", tokens.access_token_expires_at),
        ("refreshTokenExpiresAt", tokens.refresh_token_expires_at),
    ] {
        if let Some(date) = value {
            let _ = observed.insert(
                name.into(),
                json!({"type": "date", "value": FieldValue::Date(date).json()?}),
            );
        } else if exchange {
            let _ = observed.insert(name.into(), json!({"type": "undefined"}));
        }
    }
    if let Some(raw) = tokens.raw {
        let _ = observed.insert("raw".into(), raw);
    }
    Ok(Value::Object(observed))
}

#[test]
fn oauth_duration_helpers_match_all_captured_token_fields() -> AuthResult<()> {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/oauth-token-duration-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 4);
    for case in fixture.cases {
        let now = DateTime::from_timestamp_millis(case.now)
            .ok_or_else(|| AuthError::internal("Captured OAuth clock is out of range"))?;
        let fallback = match case.scenario.fallback {
            None => None,
            Some(value) if value == json!({"type": "number", "value": "NaN"}) => Some(f64::NAN),
            Some(value) => return Err(AuthError::internal(format!("Unknown fallback: {value}"))),
        };
        assert_eq!(case.helpers.len(), 2);
        for helper in case.helpers {
            let exchange = match helper.operation.as_str() {
                "exchange" => true,
                "refresh" => false,
                operation => {
                    return Err(AuthError::internal(format!("Unknown grant: {operation}")));
                }
            };
            let response = helper
                .events
                .iter()
                .find(|event| event.get("kind").and_then(Value::as_str) == Some("token.http"))
                .and_then(|event| event.get("response"))
                .and_then(|response| response.get("body"))
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::internal("Missing captured OAuth token response"))?;
            let mut tokens =
                parse_token_response_with_clock(serde_json::from_str(response)?, || now)?;
            if !exchange {
                tokens.raw = None;
            }
            let tokens = apply_default_expiry(tokens, &provider(fallback))?;
            assert_eq!(
                json!({"kind": "returned", "value": observed_tokens(tokens, exchange)?}),
                helper.outcome,
                "{}/{}/{}",
                case.backend,
                case.scenario.name,
                helper.operation,
            );
        }
    }
    Ok(())
}

#[test]
fn oauth_falsy_fallback_omits_expiry_without_replacing_supplied_dates() -> AuthResult<()> {
    let supplied = FieldDate::from_milliseconds(NOW as f64);
    for fallback in [None, Some(0.0), Some(-0.0), Some(f64::NAN)] {
        let tokens = apply_default_expiry(
            OAuthTokenSet {
                access_token: Some("duration-access".into()),
                refresh_token_expires_at: Some(supplied.clone()),
                ..Default::default()
            },
            &provider(fallback),
        )?;
        assert!(tokens.access_token_expires_at.is_none());
        assert_eq!(tokens.access_token.as_deref(), Some("duration-access"));
        assert!(
            tokens
                .refresh_token_expires_at
                .is_some_and(|date| date.same_object(&supplied))
        );
    }
    for fallback in [f64::NAN, f64::INFINITY, -0.0005, 300.0] {
        let tokens = apply_default_expiry(
            OAuthTokenSet {
                access_token_expires_at: Some(supplied.clone()),
                ..Default::default()
            },
            &provider(Some(fallback)),
        )?;
        assert!(
            tokens
                .access_token_expires_at
                .is_some_and(|date| date.same_object(&supplied))
        );
    }
    let error = apply_default_expiry(OAuthTokenSet::default(), &provider(Some(f64::INFINITY)))
        .err()
        .ok_or_else(|| AuthError::internal("Expected the existing lifetime validation error"))?;
    assert!(
        matches!(error, AuthError::Internal(message) if message == "Invalid OAuth token lifetime")
    );
    Ok(())
}
