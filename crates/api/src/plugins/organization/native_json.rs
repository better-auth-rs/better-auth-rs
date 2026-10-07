use better_auth_core::{AuthResult, SchemaValue};
use serde_json::Value;

pub(super) fn metadata(
    value: SchemaValue<Option<better_auth_core::FieldValue>>,
    create: bool,
) -> AuthResult<SchemaValue<Option<better_auth_core::FieldValue>>> {
    use better_auth_core::FieldValue;
    let raw = value.into_field_value();
    if !raw.is_truthy() || (create && !raw.is_string()) {
        return Ok(SchemaValue::Undefined);
    }
    let parsed = if create {
        raw.as_str()
            .map(|text| FieldValue::from_json(parse_json(text)?))
            .transpose()?
    } else {
        parse_metadata(raw)?
    };
    Ok(parsed.map(SchemaValue::Dynamic).unwrap_or_default())
}

fn parse_metadata(
    value: better_auth_core::FieldValue,
) -> AuthResult<Option<better_auth_core::FieldValue>> {
    use better_auth_core::FieldValue;
    let FieldValue::String(text) = value else {
        return Ok(Some(value));
    };
    let trimmed = text.trim();
    let parsed = match trimmed.to_ascii_lowercase().as_str() {
        "undefined" => return Ok(None),
        "nan" => FieldValue::Number(f64::NAN),
        "infinity" => FieldValue::Number(f64::INFINITY),
        "-infinity" => FieldValue::Number(f64::NEG_INFINITY),
        "null" => FieldValue::Null,
        "true" => FieldValue::Bool(true),
        "false" => FieldValue::Bool(false),
        _ => FieldValue::from_json(parse_json(trimmed)?)?,
    };
    fn revive(value: FieldValue) -> AuthResult<FieldValue> {
        Ok(match value {
            FieldValue::Object(fields) => {
                if fields.contains_key("__proto__") || fields.contains_key("constructor") {
                    better_auth_core::observability::logger::current()
                        .error("Organization JSON contains a prototype pollution key", &[]);
                    return Err(better_auth_core::AuthResponse::new(500).into());
                }
                fields
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), revive(value.clone())?)))
                    .collect::<AuthResult<better_auth_core::FieldMap>>()?
                    .into()
            }
            FieldValue::Array(values) => values
                .iter()
                .cloned()
                .map(revive)
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
            FieldValue::String(value) => match metadata_date(&value) {
                Some(date) => date.into(),
                None => FieldValue::String(value),
            },
            value => value,
        })
    }
    Ok(Some(revive(parsed)?))
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

pub(super) fn permission(
    value: &SchemaValue<better_auth_core::FieldValue>,
) -> AuthResult<better_auth_core::FieldValue> {
    better_auth_core::FieldValue::from_json(parse_json(&value.display_string()?)?)
}

pub(super) fn parse_json(text: &str) -> AuthResult<Value> {
    serde_json::from_str(text).map_err(|error| {
        better_auth_core::observability::logger::current().error(
            "Organization JSON decoding failed",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
        better_auth_core::AuthResponse::new(500).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_dates_follow_the_upstream_component_parser() {
        let parsed = parse_metadata(better_auth_core::FieldValue::from_json(json!(r#"{"fraction":"2026-01-02T03:04:05.1234Z","overflow":"2026-02-30T25:00:00+02:00","year":"0099-01-01T00:00:00Z","untouched":"2026-01-02T03:04:05.12345678Z"}"#)).unwrap()).unwrap();
        let fields = parsed.as_ref().unwrap().as_object().unwrap();
        assert!(fields["fraction"].as_date().is_some());
        assert!(fields["overflow"].as_date().is_some());
        assert!(fields["year"].as_date().is_some());
        assert!(fields["untouched"].as_str().is_some());
        assert_eq!(
            parsed.map(|value| value.json().unwrap().unwrap()),
            Some(
                json!({"fraction":"2026-01-02T03:04:06.234Z","overflow":"2026-03-02T23:00:00.000Z","year":"1999-01-01T00:00:00.000Z","untouched":"2026-01-02T03:04:05.12345678Z"})
            )
        );
    }

    #[test]
    fn metadata_parser_preserves_nonfinite_values_until_serialization() -> AuthResult<()> {
        for (text, expected) in [
            ("NaN", f64::NAN),
            ("Infinity", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
        ] {
            let parsed = parse_metadata(text.into())?.unwrap();
            let number = parsed.as_f64().unwrap();
            assert!(number == expected || number.is_nan() && expected.is_nan());
            assert_eq!(parsed.json()?, Some(Value::Null));
        }
        Ok(())
    }
}
