//! JSON decoding shared by schema fields and OAuth state inputs.

use serde_json::Value;

mod runtime;
pub(crate) use runtime::parse_field_json;
pub use runtime::{parse_client_json, safe_parse_field};

mod stringify;
pub use stringify::{array_index, stringify};

/// Parse upstream JSON values and revive ISO date strings. Invalid JSON produces null.
pub fn safe_json_parse(text: &str) -> Value {
    let mut value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            // The upstream adapter logs invalid JSON and returns null.
            crate::observability::logger::current().error(
                "Error parsing JSON",
                &[crate::observability::LogArgument::Error(&error)],
            );
            return Value::Null;
        }
    };
    fn revive_dates(value: &mut Value) {
        match value {
            Value::Object(fields) => fields.values_mut().for_each(revive_dates),
            Value::Array(values) => values.iter_mut().for_each(revive_dates),
            Value::String(text) => {
                if let Some(date) = parse_json_date(text) {
                    *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            _ => {}
        }
    }
    revive_dates(&mut value);
    value
}

/// Revive the ISO date strings accepted by the upstream JSON decoder.
pub fn parse_json_date(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    fn digits(text: &str) -> Option<i64> {
        text.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| text.parse().ok())
            .flatten()
    }
    let text = text.strip_suffix('Z')?;
    let (whole, fraction) = text
        .split_once('.')
        .map_or((text, None), |(whole, fraction)| (whole, Some(fraction)));
    if whole.len() != 19
        || whole.get(4..5)? != "-"
        || whole.get(7..8)? != "-"
        || whole.get(10..11)? != "T"
        || whole.get(13..14)? != ":"
        || whole.get(16..17)? != ":"
    {
        return None;
    }
    if fraction.is_some_and(|fraction| {
        fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return None;
    }
    let year = digits(whole.get(..4)?)?;
    let month = digits(whole.get(5..7)?)?;
    let day = digits(whole.get(8..10)?)?;
    let hour = digits(whole.get(11..13)?)?;
    let minute = digits(whole.get(14..16)?)?;
    let second = digits(whole.get(17..19)?)?;
    // safeJSONParse uses new Date(string): only the day may overflow its month.
    // Midnight 24:00 is valid only when every fractional digit is zero.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 24
        || minute > 59
        || second > 59
        || (hour == 24
            && (minute != 0
                || second != 0
                || fraction.is_some_and(|fraction| fraction.bytes().any(|byte| byte != b'0'))))
    {
        return None;
    }
    let millis = fraction.map_or(0, |fraction| {
        fraction
            .bytes()
            .take(3)
            .chain(std::iter::repeat(b'0'))
            .take(3)
            .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'))
    });
    crate::utils::date::normalize_components(
        year,
        month - 1,
        day,
        (hour * 60 + minute) * 60_000 + second * 1_000 + millis,
    )
}
