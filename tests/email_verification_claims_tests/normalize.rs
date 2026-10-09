use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct Anchors {
    pub(super) tokens: Vec<(String, String)>,
    replacements: Vec<(String, String)>,
}

fn millis(value: &Value) -> TestResult<i64> {
    let value = if value.get("type").and_then(Value::as_str) == Some("date") {
        &value["value"]
    } else {
        value
    };
    Ok(value
        .as_str()
        .ok_or("Expected Date observation or stored timestamp")?
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp_millis())
}

fn iso(millis: i64) -> TestResult<String> {
    Ok(
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
            .ok_or("Timestamp exceeds Chrono")?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

fn hook<'a>(events: &'a [Value], model: &str, operation: &str, phase: &str) -> Option<&'a Value> {
    events
        .iter()
        .find(|event| {
            event["kind"] == "hook"
                && event["model"] == model
                && event["operation"] == operation
                && event["phase"] == phase
        })
        .map(|event| &event["data"])
}

impl Anchors {
    fn date(&mut self, actual: i64, captured: i64) -> TestResult {
        self.replacements.push((iso(actual)?, iso(captured)?));
        Ok(())
    }

    pub(super) fn validate(
        &mut self,
        observation: &Value,
        case: &Case,
        start: i64,
        end: i64,
    ) -> TestResult {
        assert!(start <= end);
        let events = observation["events"]
            .as_array()
            .ok_or("Missing recorded events")?;
        if let Some(updated) = hook(events, "user", "update", "after") {
            let updated_at = millis(&updated["updatedAt"])?;
            assert!(
                (start..=end).contains(&updated_at),
                "The User mutation must use the request clock"
            );
            assert_eq!(
                millis(&observation["after"]["user"][0]["updatedAt"])?,
                updated_at
            );
            self.date(updated_at, ISSUED_AT)?;
        }
        if let Some(issued) = hook(events, "session", "create", "before") {
            let stored = &observation["after"]["session"][0];
            let completed =
                hook(events, "session", "create", "after").ok_or("Missing created Session hook")?;
            let token = issued["token"]
                .as_str()
                .ok_or("Missing issued Session token")?;
            assert_eq!(token.len(), 32);
            assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            assert_eq!(stored["token"], token);
            assert_eq!(completed["token"], token);
            assert_eq!(stored["userId"], "claims-owner");
            assert_eq!(completed["userId"], stored["userId"]);
            let created = millis(&issued["createdAt"])?;
            let updated = millis(&issued["updatedAt"])?;
            let expiry = millis(&issued["expiresAt"])?;
            assert!((start..=end).contains(&created));
            assert!((created..=end).contains(&updated));
            assert!((start..=created).contains(&(expiry - 3_600_000)));
            for (name, value, captured) in [
                ("createdAt", created, ISSUED_AT),
                ("updatedAt", updated, ISSUED_AT),
                ("expiresAt", expiry, ISSUED_AT + 3_600_000),
            ] {
                assert_eq!(millis(&stored[name])?, value);
                assert_eq!(millis(&completed[name])?, value);
                self.date(value, captured)?;
            }
            let cookies = observation["response"]["cookies"]
                .as_array()
                .ok_or("Missing response cookies")?;
            assert_eq!(cookies.len(), 1);
            let cookie = cookies[0]
                .as_str()
                .ok_or("Missing Session cookie")?
                .split(';')
                .next()
                .ok_or("Missing cookie pair")?;
            let (name, signed) = cookie.split_once('=').ok_or("Malformed cookie pair")?;
            assert_eq!(name, "better-auth.session_token");
            assert_eq!(
                better_auth_core::utils::cookie_utils::verify_cookie_value(signed, SECRET)
                    .as_deref(),
                Some(token)
            );
            self.replacements.push((
                cookie.into(),
                "better-auth.session_token=<verified-signed-session-token>".into(),
            ));
            self.replacements
                .push((token.into(), "<session-token>".into()));
        }
        for event in events.iter().filter(|event| event["kind"] == "sender") {
            let actual = event["data"]["token"]
                .as_str()
                .ok_or("Missing delivered token")?;
            let captured = case
                .follow_up_tokens
                .get(self.tokens.len())
                .ok_or("Unexpected delivered token")?;
            self.verify_token(actual, captured, start, end)?;
            let url: url::Url = event["data"]["url"]
                .as_str()
                .ok_or("Missing delivery URL")?
                .parse()?;
            assert_eq!(
                url.query_pairs()
                    .find(|(name, _)| name == "token")
                    .map(|(_, value)| value.into_owned())
                    .as_deref(),
                Some(actual)
            );
            self.tokens.push((actual.into(), captured.token.clone()));
        }
        Ok(())
    }

    fn verify_token(
        &self,
        token: &str,
        captured: &CapturedToken,
        start: i64,
        end: i64,
    ) -> TestResult {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let verified = jsonwebtoken::decode::<HashMap<String, Box<RawValue>>>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(SECRET.as_bytes()),
            &validation,
        )?;
        let iat: i64 = serde_json::from_str(
            verified
                .claims
                .get("iat")
                .ok_or("Missing signed iat")?
                .get(),
        )?;
        let exp: i64 = serde_json::from_str(
            verified
                .claims
                .get("exp")
                .ok_or("Missing signed exp")?
                .get(),
        )?;
        assert!((start.div_euclid(1000)..=end.div_euclid(1000)).contains(&iat));
        assert_eq!(exp - iat, 3600);
        let claims = values::capture(captured.claims.get())?;
        assert_eq!(claims["iat"], ISSUED_AT.div_euclid(1000));
        assert_eq!(claims["exp"], ISSUED_AT.div_euclid(1000) + 3600);
        let parts = token.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[0])?, br#"{"alg":"HS256"}"#);
        let expected = captured
            .payload
            .replace(
                &format!("\"iat\":{}", ISSUED_AT.div_euclid(1000)),
                &format!("\"iat\":{iat}"),
            )
            .replace(
                &format!("\"exp\":{}", ISSUED_AT.div_euclid(1000) + 3600),
                &format!("\"exp\":{exp}"),
            );
        assert_eq!(
            String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1])?)?,
            expected,
            "Only verified NumericDate anchors may differ from the captured JWT bytes"
        );
        Ok(())
    }

    pub(super) fn apply(&self, value: &mut Value) {
        match value {
            Value::String(text) => {
                for (actual, captured) in self.tokens.iter().chain(&self.replacements) {
                    *text = text.replace(actual, captured);
                }
            }
            Value::Array(values) => values.iter_mut().for_each(|value| self.apply(value)),
            Value::Object(fields) => fields.values_mut().for_each(|value| self.apply(value)),
            _ => {}
        }
    }
}

pub(super) fn paired(actual: &mut Value, expected: &mut Value, sqlite: bool) -> TestResult {
    let status = expected["response"]["status"]
        .as_u64()
        .ok_or("Missing captured HTTP status")?;
    let status_text = expected["response"]
        .as_object_mut()
        .ok_or("Missing captured HTTP response")?
        .remove("statusText")
        .ok_or("Missing upstream statusText")?;
    assert_eq!(
        status_text,
        match status {
            302 => json!("FOUND"),
            401 => json!("UNAUTHORIZED"),
            500 => json!("Internal Server Error"),
            _ => json!(""),
        }
    );
    for observation in [&mut *actual, &mut *expected] {
        let text = observation["response"]["body"]
            .as_str()
            .ok_or("Missing complete HTTP body")?;
        observation["response"]["body"] = values::body(text)?;
    }
    if !sqlite {
        for phase in ["before", "after"] {
            let verification = expected[phase]
                .as_object_mut()
                .ok_or("Missing captured tables")?
                .remove("verification")
                .ok_or("Missing verification table")?;
            assert_eq!(verification, json!([]));
        }
        assert!(
            actual["events"]
                .as_array()
                .ok_or("Missing recorded operations")?
                .iter()
                .all(|event| event.get("model").and_then(Value::as_str) != Some("verification")),
            "No verification operation may escape the paired event sequence"
        );
    }
    Ok(())
}

pub(super) fn remove_native_errors(observation: &mut Value) -> TestResult {
    for event in observation["events"]
        .as_array_mut()
        .ok_or("Missing recorded events")?
    {
        if matches!(event["kind"].as_str(), Some("api-error" | "console.error")) {
            *event = json!({"kind":event["kind"]});
        }
    }
    Ok(())
}
