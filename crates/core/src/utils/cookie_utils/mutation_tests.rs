use super::*;
use crate::{CookieAttributes, SameSite};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Capture {
    versions: Value,
    serializers: Vec<Serializer>,
}

#[derive(Deserialize)]
struct Serializer {
    scenario: String,
    mode: String,
    name: String,
    input: Vec<(String, Value)>,
    writes: Vec<Write>,
}

#[derive(Deserialize)]
struct Write {
    before: Vec<(String, Value)>,
    header: String,
    after: Vec<(String, Value)>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attributes {
    secure: Option<bool>,
    same_site: Option<String>,
    path: Option<String>,
    http_only: Option<bool>,
    domain: Option<String>,
    partitioned: Option<bool>,
    max_age: Option<f64>,
}

impl Attributes {
    fn captured(entries: &[(String, Value)]) -> AuthResult<Self> {
        let values = entries
            .iter()
            .map(|(name, value)| {
                let value = if *value == json!({ "type": "undefined" }) {
                    Value::Null
                } else {
                    value.clone()
                };
                (name.clone(), value)
            })
            .collect();
        Ok(serde_json::from_value(Value::Object(values))?)
    }

    fn observed(value: &CookieAttributes) -> Self {
        Self {
            secure: value.secure,
            same_site: value.same_site.as_ref().map(|value| {
                match value {
                    SameSite::Strict => "strict",
                    SameSite::Lax => "lax",
                    SameSite::None => "none",
                }
                .into()
            }),
            path: value.path.clone(),
            http_only: value.http_only,
            domain: value.domain.clone(),
            partitioned: value.partitioned,
            max_age: value.max_age,
        }
    }

    fn into_cookie(self) -> AuthResult<CookieAttributes> {
        let same_site = match self.same_site.as_deref() {
            Some("strict") => Some(SameSite::Strict),
            Some("lax") => Some(SameSite::Lax),
            Some("none") => Some(SameSite::None),
            None => None,
            Some(value) => return Err(AuthError::internal(format!("Unknown SameSite: {value}"))),
        };
        Ok(CookieAttributes {
            secure: self.secure,
            same_site,
            path: self.path,
            http_only: self.http_only,
            domain: self.domain,
            partitioned: self.partitioned,
            max_age: self.max_age,
            ..Default::default()
        })
    }
}

#[test]
fn cookie_writer_mutations_match_pinned_serializers_without_mutating_callers() -> AuthResult<()> {
    let capture: Capture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/cookie-attribute-mutation-1.7.6.json"
    )))?;
    assert_eq!(
        capture.versions,
        json!({ "better-auth": "1.7.6", "@better-auth/core": "1.7.6", "better-call": "1.4.0" })
    );
    assert_eq!(capture.serializers.len(), 12);
    for case in capture.serializers {
        let original = ResolvedCookie {
            name: case.name,
            attributes: Attributes::captured(&case.input)?.into_cookie()?,
        };
        let encoded = match case.mode.as_str() {
            "plain" => encode_cookie_value("ordinary-output-only"),
            "signed" => sign_cookie_value(
                "ordinary-output-only",
                "ordinary-cookie-attribute-mutation-secret-at-least-32-characters",
            ),
            mode => {
                return Err(AuthError::internal(format!(
                    "Unknown serializer mode: {mode}"
                )));
            }
        };
        assert_eq!(case.writes.len(), 2);
        let first = case
            .writes
            .first()
            .ok_or_else(|| AuthError::internal("Missing first serializer write"))?;
        for _ in 0..2 {
            assert_eq!(render_cookie(&encoded, &original)?, first.header);
            assert_eq!(
                Attributes::observed(&original.attributes),
                Attributes::captured(&case.input)?
            );
        }
        let mut writer = original;
        for expected in case.writes {
            assert_eq!(
                Attributes::observed(&writer.attributes),
                Attributes::captured(&expected.before)?,
                "{}/{} before",
                case.scenario,
                case.mode
            );
            assert_eq!(
                render_cookie_mut(&encoded, &mut writer)?,
                expected.header,
                "{}/{} header",
                case.scenario,
                case.mode
            );
            assert_eq!(
                Attributes::observed(&writer.attributes),
                Attributes::captured(&expected.after)?,
                "{}/{} after",
                case.scenario,
                case.mode
            );
        }
    }
    // Rust attributes have no JavaScript property order or own-undefined distinction.
    // The mutable writer pairs values and wire bytes; the public wrapper preserves its borrowed input.
    Ok(())
}
