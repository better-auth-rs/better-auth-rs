use better_auth_core::{AuthResult, SchemaValue, user_fields::is_truthy};
use serde_json::Value;

pub(super) fn metadata(
    value: SchemaValue<Option<Value>>,
    create: bool,
) -> AuthResult<SchemaValue<Option<Value>>> {
    let raw = match value {
        SchemaValue::Typed(Some(value)) => Value::String(value.to_string()),
        SchemaValue::Dynamic(value) => value,
        SchemaValue::InvalidDate => Value::Null,
        SchemaValue::Typed(None) | SchemaValue::Undefined => return Ok(SchemaValue::Undefined),
    };
    if !is_truthy(&raw) || (create && !raw.is_string()) {
        return Ok(SchemaValue::Undefined);
    }
    let parsed = if create {
        raw.as_str().map(parse_json).transpose()?
    } else {
        parse_metadata(raw)?
    };
    Ok(parsed.map(SchemaValue::Dynamic).unwrap_or_default())
}

fn parse_metadata(value: Value) -> AuthResult<Option<Value>> {
    let Value::String(text) = value else {
        return Ok(Some(value));
    };
    let trimmed = text.trim();
    let mut parsed = match trimmed.to_ascii_lowercase().as_str() {
        "undefined" => return Ok(None),
        "nan" | "infinity" | "-infinity" | "null" => Value::Null,
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => parse_json(trimmed)?,
    };
    fn normalize(value: &mut Value) -> AuthResult<()> {
        match value {
            Value::Object(fields) => {
                if fields.contains_key("__proto__") || fields.contains_key("constructor") {
                    tracing::error!("Organization JSON contains a prototype pollution key");
                    return Err(better_auth_core::AuthResponse::new(500).into());
                }
                for value in fields.values_mut() {
                    normalize(value)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    normalize(value)?;
                }
            }
            Value::String(value) => {
                if let Some(date) = metadata_date(value) {
                    *value = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            _ => {}
        }
        Ok(())
    }
    normalize(&mut parsed)?;
    Ok(Some(parsed))
}

fn metadata_date(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    fn digits(text: &str, width: usize) -> Option<i64> {
        (text.len() == width && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    }
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let mut year = digits(date.next()?, 4)?;
    let month = digits(date.next()?, 2)? - 1;
    let day = digits(date.next()?, 2)?;
    if date.next().is_some() {
        return None;
    }
    let (time, offset) = if let Some(time) = time.strip_suffix('Z') {
        (time, 0)
    } else {
        let index = time.rfind(['+', '-'])?;
        let (offset_hour, offset_minute) = time.get(index + 1..)?.split_once(':')?;
        let minutes = digits(offset_hour, 2)? * 60 + digits(offset_minute, 2)?;
        (
            time.get(..index)?,
            if time.as_bytes().get(index) == Some(&b'+') {
                minutes
            } else {
                -minutes
            },
        )
    };
    let mut time = time.split(':');
    let hour = digits(time.next()?, 2)?;
    let minute = digits(time.next()?, 2)?;
    let seconds = time.next()?;
    if time.next().is_some() {
        return None;
    }
    let (second, millis) = if let Some((seconds, fraction)) = seconds.split_once('.') {
        if !(1..=7).contains(&fraction.len()) {
            return None;
        }
        let scale = match fraction.len() {
            1 => 100,
            2 => 10,
            _ => 1,
        };
        (
            digits(seconds, 2)?,
            digits(fraction, fraction.len())? * scale,
        )
    } else {
        (digits(seconds, 2)?, 0)
    };
    // The upstream parser passes the padded fraction as milliseconds to Date.UTC.
    // Date.UTC also normalizes overflowing components and maps years 0–99 to 1900–1999.
    if year < 100 {
        year += 1900;
    }
    let millis = (hour * 60 + minute - offset) * 60_000 + second * 1_000 + millis;
    better_auth_core::utils::date::normalize_components(year, month, day, millis)
}

pub(super) fn permission(value: &SchemaValue<Value>) -> AuthResult<Value> {
    match value {
        SchemaValue::Typed(value) => Ok(value.clone()),
        value => parse_json(&value.display_string()?),
    }
}

pub(super) fn parse_json(text: &str) -> AuthResult<Value> {
    serde_json::from_str(text).map_err(|error| {
        tracing::error!(%error, "Organization JSON decoding failed");
        better_auth_core::AuthResponse::new(500).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_dates_follow_the_upstream_component_parser() {
        let parsed = parse_metadata(json!(r#"{"fraction":"2026-01-02T03:04:05.1234Z","overflow":"2026-02-30T25:00:00+02:00","year":"0099-01-01T00:00:00Z","untouched":"2026-01-02T03:04:05.12345678Z"}"#)).unwrap();
        assert_eq!(
            parsed,
            Some(
                json!({"fraction":"2026-01-02T03:04:06.234Z","overflow":"2026-03-02T23:00:00.000Z","year":"1999-01-01T00:00:00.000Z","untouched":"2026-01-02T03:04:05.12345678Z"})
            )
        );
    }
}
