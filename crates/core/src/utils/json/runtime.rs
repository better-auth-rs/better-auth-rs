use crate::{AuthError, AuthResult, FieldDate, FieldMap, FieldValue, Utf16String};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::sync::OnceLock;

pub(crate) fn parse_field_json(text: &str) -> AuthResult<FieldValue> {
    let value: &RawValue = serde_json::from_str(text)?;
    let text = value.get();
    match text.as_bytes().first() {
        Some(b'"') => Ok(serde_json::from_str::<Utf16String>(text)?.into()),
        Some(b'[') => serde_json::from_str::<Vec<&RawValue>>(text)?
            .into_iter()
            .map(|value| parse_field_json(value.get()))
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
        Some(b'{') => serde_json::from_str::<indexmap::IndexMap<String, &RawValue>>(text)?
            .into_iter()
            .map(|(key, value)| Ok((key, parse_field_json(value.get())?)))
            .collect::<AuthResult<FieldMap>>()
            .map(Into::into),
        Some(b'n') => Ok(FieldValue::Null),
        Some(b't') => Ok(FieldValue::Bool(true)),
        Some(b'f') => Ok(FieldValue::Bool(false)),
        _ => text
            .parse::<f64>()
            .map(FieldValue::Number)
            .map_err(|error| AuthError::internal(format!("Invalid JSON number: {error}"))),
    }
}

fn utf16_json_source(text: &Utf16String) -> AuthResult<String> {
    let mut source = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for unit in char::decode_utf16(text.as_utf16().iter().copied()) {
        match unit {
            Ok(character) => {
                source.push(character);
                if escaped {
                    escaped = false;
                } else if quoted && character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = !quoted;
                }
            }
            Err(error) => {
                // JSON source permits unpaired surrogates only in unescaped string content.
                if !quoted || escaped {
                    return Err(AuthError::internal("Invalid JSON source"));
                }
                use std::fmt::Write as _;
                write!(source, "\\u{:04x}", error.unpaired_surrogate())
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
    }
    Ok(source)
}

/// Apply JSON.parse string conversion while preserving unpaired UTF-16 string values.
/// Object names containing unpaired surrogates remain unsupported by FieldMap.
pub fn parse_native_json(value: &FieldValue) -> AuthResult<FieldValue> {
    match value {
        FieldValue::String(text) => FieldValue::parse_json(text),
        _ => FieldValue::parse_json(&utf16_json_source(&value.display_utf16()?)?),
    }
}

/// Decode permissions and legacy metadata with upstream safeJSONParse behavior.
pub fn safe_parse_field(value: &FieldValue) -> AuthResult<FieldValue> {
    let parsed = match value {
        FieldValue::Undefined | FieldValue::Null => return Ok(FieldValue::Null),
        FieldValue::String(_) | FieldValue::Utf16String(_) => parse_native_json(value),
        value => Ok(value.clone()),
    };
    match parsed {
        Ok(value) => revive(value, &|text| {
            super::parse_json_date(text).map(FieldDate::from)
        }),
        Err(error) => {
            crate::observability::logger::current().error(
                "Error parsing JSON",
                &[crate::observability::LogArgument::Error(&error)],
            );
            Ok(FieldValue::Null)
        }
    }
}

fn revive(
    value: FieldValue,
    parse_date: &impl Fn(&str) -> Option<FieldDate>,
) -> AuthResult<FieldValue> {
    revive_with_active(value, parse_date, &mut std::collections::HashSet::new())
}

fn revive_with_active(
    value: FieldValue,
    parse_date: &impl Fn(&str) -> Option<FieldDate>,
    active: &mut std::collections::HashSet<crate::field_value::ObjectIdentity>,
) -> AuthResult<FieldValue> {
    Ok(match value {
        FieldValue::String(text) => parse_date(&text).map_or_else(|| text.into(), Into::into),
        FieldValue::Array(values) => values
            .iter()
            .cloned()
            .map(|value| revive_with_active(value, parse_date, active))
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        FieldValue::Object(values) => {
            let identity = values.identity();
            if !active.insert(identity) {
                return Err(AuthError::internal(
                    "JSON date revival of cyclic field objects is not supported",
                ));
            }
            let fields = values
                .snapshot_fields()?
                .into_iter()
                .map(|(key, value)| Ok((key, revive_with_active(value, parse_date, active)?)))
                .collect::<AuthResult<FieldMap>>()?;
            let _ = active.remove(&identity);
            fields.into()
        }
        value => value,
    })
}

#[expect(
    clippy::expect_used,
    reason = "The expressions reproduce constant upstream JSON parser patterns"
)]
fn patterns() -> &'static [regex::Regex; 3] {
    static PATTERNS: OnceLock<[regex::Regex; 3]> = OnceLock::new();
    PATTERNS.get_or_init(|| [
        regex::Regex::new(r#"^\s*["\[{]|^\s*-?[0-9]{1,16}(\.[0-9]{1,17})?([Ee][+-]?[0-9]+)?\s*$"#).expect("JSON signature"),
        regex::Regex::new(r#""(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:|"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:"#).expect("JSON pollution keys"),
        regex::Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,7}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$").expect("client ISO date"),
    ])
}

/// Decode the strict client parser used by the API key metadata schema.
pub fn parse_client_json(value: FieldValue) -> AuthResult<FieldValue> {
    let text = match &value {
        FieldValue::String(text) => Cow::Borrowed(text.as_str()),
        FieldValue::Utf16String(text) => Cow::Owned(
            utf16_json_source(text)
                .map_err(|_| AuthError::internal("[better-json] Invalid JSON"))?,
        ),
        _ => return Ok(value),
    };
    let text =
        text.trim_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}');
    let special = match text.to_ascii_lowercase().as_str() {
        "true" => Some(FieldValue::Bool(true)),
        "false" => Some(FieldValue::Bool(false)),
        "null" => Some(FieldValue::Null),
        "undefined" => Some(FieldValue::Undefined),
        "nan" => Some(f64::NAN.into()),
        "infinity" => Some(f64::INFINITY.into()),
        "-infinity" => Some(f64::NEG_INFINITY.into()),
        _ => None,
    };
    if let Some(value) = special {
        return Ok(value);
    }
    let [signature, pollution, _] = patterns();
    if !signature.is_match(text) {
        return Err(AuthError::internal("[better-json] Invalid JSON"));
    }
    if pollution.is_match(text) {
        return Err(AuthError::internal(
            "[better-json] Potential prototype pollution attempt detected",
        ));
    }
    revive(FieldValue::parse_json(text)?, &client_date)
}

fn client_date(text: &str) -> Option<FieldDate> {
    let [_, _, pattern] = patterns();
    let captures = pattern.captures(text)?;
    let number = |index| captures.get(index)?.as_str().parse::<i64>().ok();
    let year = number(1)?;
    let year = if (0..=99).contains(&year) {
        1900 + year
    } else {
        year
    };
    let fraction = captures.get(7).map_or(0, |value| {
        value
            .as_str()
            .bytes()
            .chain(std::iter::repeat(b'0'))
            .take(value.as_str().len().max(3))
            .fold(0_i64, |acc, digit| acc * 10 + i64::from(digit - b'0'))
    });
    let mut milliseconds = (number(4)? * 3600 + number(5)? * 60 + number(6)?) * 1000 + fraction;
    if let Some(sign) = captures.get(8) {
        milliseconds +=
            (number(9)? * 60 + number(10)?) * 60_000 * if sign.as_str() == "+" { -1 } else { 1 };
    }
    crate::utils::date::normalize_components(year, number(2)? - 1, number(3)?, milliseconds)
        .map(FieldDate::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_json_source_preserves_utf16_values_and_parser_policies() -> AuthResult<()> {
        let text: FieldValue = Utf16String::from_units(
            r#"{"units":[""#
                .encode_utf16()
                .chain([0xd800, 0xd83d, 0xde00, 0xdc00])
                .chain(
                    r#"","\udfff"],"date":"2026-01-02T03:04:05Z","number":1e400}"#.encode_utf16(),
                )
                .collect(),
        )
        .into();
        let expected_units: FieldValue = vec![
            Utf16String::from_units(vec![0xd800, 0xd83d, 0xde00, 0xdc00]).into(),
            Utf16String::from_units(vec![0xdfff]).into(),
        ]
        .into();
        for (parsed, revived) in [
            (parse_native_json(&text)?, false),
            (safe_parse_field(&text)?, true),
            (parse_client_json(text.clone())?, true),
        ] {
            let fields = parsed
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected parsed object"))?
                .snapshot_fields()?;
            assert_eq!(fields.get("units"), Some(&expected_units));
            assert!(
                matches!(fields.get("number"), Some(FieldValue::Number(number)) if number.is_infinite())
            );
            assert_eq!(
                matches!(fields.get("date"), Some(FieldValue::Date(_))),
                revived
            );
            if !revived {
                assert_eq!(fields.get("date"), Some(&"2026-01-02T03:04:05Z".into()));
            }
        }
        for (units, expected) in [
            (vec![34, 92, 92, 0xd800, 34], vec![92, 0xd800]),
            (vec![34, 92, 34, 0xd800, 34], vec![34, 0xd800]),
        ] {
            assert_eq!(
                parse_native_json(&Utf16String::from_units(units).into())?,
                Utf16String::from_units(expected).into()
            );
        }
        assert_eq!(parse_native_json(&FieldValue::Null)?, FieldValue::Null);
        assert_eq!(parse_native_json(&true.into())?, true.into());
        assert_eq!(parse_native_json(&17.0.into())?, 17.0.into());
        Ok(())
    }

    #[test]
    fn native_json_source_rejects_invalid_escapes_and_preserves_pollution_checks() {
        for units in [
            vec![34, 92, 0xd800, 34],
            vec![0xd800],
            vec![34, 92, 117, 0xd800, 34],
            vec![34, 0xd800, 34, 34],
            vec![34, 0xd800, 10, 34],
        ] {
            let text = Utf16String::from_units(units).into();
            assert!(parse_native_json(&text).is_err());
            assert_eq!(safe_parse_field(&text).unwrap(), FieldValue::Null);
            assert!(parse_client_json(text).is_err());
        }
        let text: FieldValue = Utf16String::from_units(
            r#"{"constructor":""#
                .encode_utf16()
                .chain([0xd800])
                .chain(r#""}"#.encode_utf16())
                .collect(),
        )
        .into();
        assert!(parse_native_json(&text).is_ok());
        assert!(matches!(
            parse_client_json(text),
            Err(AuthError::Internal(message))
                if message == "[better-json] Potential prototype pollution attempt detected"
        ));
    }

    #[test]
    fn strict_metadata_and_safe_permissions_keep_distinct_parse_policies() -> AuthResult<()> {
        assert!(parse_client_json("not JSON".into()).is_err());
        assert_eq!(safe_parse_field(&"not JSON".into())?, FieldValue::Null);
        assert!(parse_client_json("undefined".into())?.is_undefined());
        assert!(
            matches!(parse_client_json("NaN".into())?, FieldValue::Number(value) if value.is_nan())
        );
        assert!(parse_client_json(r#"{"\u005f\u005fproto__": 1}"#.into()).is_err());
        assert!(parse_client_json(r#"{"constructor": 1}"#.into()).is_err());
        let object = FieldValue::from(FieldMap::from([(
            "a".into(),
            "2026-01-02T03:04:05Z".into(),
        )]));
        assert!(parse_client_json(object.clone())?.strict_equals(&object));
        assert!(matches!(
            safe_parse_field(&object)?.model_property("a")?,
            FieldValue::Date(_)
        ));
        Ok(())
    }

    #[test]
    fn metadata_reviver_retains_upstream_date_overflow_and_utf16() -> AuthResult<()> {
        let text = r#"{"date":"0020-02-31T01:00:00.1234+01:00","start":"\ud83d","number":1e400}"#;
        let raw = FieldValue::parse_json(text)?;
        let parsed = parse_client_json(text.into())?;
        let fields = parsed
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected metadata object"))?
            .snapshot_fields()?;
        assert_eq!(
            fields
                .get("date")
                .and_then(FieldValue::as_date)
                .map(FieldDate::milliseconds),
            crate::utils::date::normalize_components(1920, 1, 31, 1234)
                .map(|date| date.timestamp_millis() as f64)
        );
        assert!(
            matches!(fields.get("start"), Some(FieldValue::Utf16String(value)) if value.as_utf16() == [0xd83d])
        );
        assert!(
            matches!(fields.get("number"), Some(FieldValue::Number(value)) if value.is_infinite())
        );
        assert_eq!(
            raw.model_property("date")?.as_str(),
            Some("0020-02-31T01:00:00.1234+01:00")
        );
        Ok(())
    }
}
