//! Format native parameters at mysql2's text-command boundary.

use better_auth_core::{AuthError, AuthResult, FieldObject, FieldValue, Utf16String};
use chrono::{Datelike, Timelike};

mod scan;

/// Retain UTF-16 values until the connection encodes the complete SQL command.
pub(super) fn format(sql: &str, values: &[FieldValue]) -> AuthResult<Utf16String> {
    let mut output = Vec::new();
    let mut chunk = 0;
    let mut cursor = 0;
    let mut set = None;
    for value in values {
        let Some((start, end)) = scan::placeholder(sql, cursor) else {
            break;
        };
        append(&mut output, sql_range(sql, chunk..start)?);
        if end - start == 2 {
            identifier(value, &mut output)?;
        } else {
            let object = if let FieldValue::Object(object) = value {
                // sql-escaper probes toSqlString again during escape; getters can observe both reads.
                if !has_sql_string(value)? && scan::assignment(sql, chunk, start, &mut set) {
                    Some(object)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(object) = object {
                object_assignments(object, &mut output)?;
            } else {
                escape(value, &mut output)?;
            }
        }
        cursor = end;
        chunk = end;
    }
    append(&mut output, sql_range(sql, chunk..sql.len())?);
    Ok(Utf16String::from_units(output))
}

fn sql_range(sql: &str, range: std::ops::Range<usize>) -> AuthResult<&str> {
    sql.get(range)
        .ok_or_else(|| AuthError::internal("MySQL formatter produced an invalid SQL text range"))
}

fn append(output: &mut Vec<u16>, value: &str) {
    output.extend(value.encode_utf16());
}

fn quoted(value: &Utf16String, output: &mut Vec<u16>) {
    output.push(u16::from(b'\''));
    for unit in value.as_utf16() {
        let escape = match *unit {
            0 => Some("\\0"),
            8 => Some("\\b"),
            9 => Some("\\t"),
            10 => Some("\\n"),
            13 => Some("\\r"),
            26 => Some("\\Z"),
            34 => Some("\\\""),
            39 => Some("\\'"),
            92 => Some("\\\\"),
            _ => None,
        };
        if let Some(escape) = escape {
            append(output, escape);
        } else {
            output.push(*unit);
        }
    }
    output.push(u16::from(b'\''));
}

fn has_sql_string(value: &FieldValue) -> AuthResult<bool> {
    Ok(matches!(value, FieldValue::Object(_))
        && value.has_property("toSqlString")?
        && matches!(
            value.model_property("toSqlString")?,
            FieldValue::Function(_)
        ))
}

fn escape(value: &FieldValue, output: &mut Vec<u16>) -> AuthResult<()> {
    match value {
        FieldValue::Undefined | FieldValue::Null => append(output, "NULL"),
        FieldValue::Bool(value) => append(output, if *value { "true" } else { "false" }),
        FieldValue::Number(value) => {
            append(
                output,
                &better_auth_core::schema_value::number_string(*value),
            );
        }
        FieldValue::Date(date) => match date.to_datetime()? {
            None => append(output, "NULL"),
            Some(date) => {
                let date = date.with_timezone(&chrono::Local);
                let year = date.year();
                // sql-escaper pads the signed year with comparisons, including years below zero.
                let prefix = if year < 10 {
                    "000"
                } else if year < 100 {
                    "00"
                } else if year < 1000 {
                    "0"
                } else {
                    ""
                };
                quoted(
                    &format!(
                        "{prefix}{year}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                        date.month(),
                        date.day(),
                        date.hour(),
                        date.minute(),
                        date.second(),
                        date.nanosecond() / 1_000_000,
                    )
                    .into(),
                    output,
                );
            }
        },
        FieldValue::Array(values) => {
            for (index, value) in values.iter()?.enumerate() {
                let value = value?;
                if index != 0 {
                    append(output, ", ");
                }
                let nested = matches!(value, FieldValue::Array(_));
                if nested {
                    output.push(u16::from(b'('));
                }
                escape(&value, output)?;
                if nested {
                    output.push(u16::from(b')'));
                }
            }
        }
        FieldValue::Object(_) if has_sql_string(value)? => {
            let FieldValue::Function(function) = value.model_property("toSqlString")? else {
                return Err(AuthError::type_error("value.toSqlString is not a function"));
            };
            let rendered = function.call_with(value, &[])?.display_utf16()?;
            output.extend_from_slice(rendered.as_utf16());
        }
        value => quoted(&value.display_utf16()?, output),
    }
    Ok(())
}

fn identifier(value: &FieldValue, output: &mut Vec<u16>) -> AuthResult<()> {
    if let FieldValue::Array(values) = value {
        for (index, value) in values.iter()?.enumerate() {
            if index != 0 {
                append(output, ", ");
            }
            identifier(&value?, output)?;
        }
        return Ok(());
    }
    let text = value.display_utf16()?;
    let json_path = text.as_utf16().windows(2).any(|units| units == [45, 62]);
    output.push(u16::from(b'`'));
    for unit in text.as_utf16() {
        match *unit {
            96 => append(output, "``"),
            46 if !json_path => append(output, "`.`"),
            unit => output.push(unit),
        }
    }
    output.push(u16::from(b'`'));
    Ok(())
}

fn object_assignments(object: &FieldObject, output: &mut Vec<u16>) -> AuthResult<()> {
    let mut separator = false;
    for key in object.own_keys()? {
        // Keys are captured before reads; getters retain the live source and can mutate later values.
        if !object
            .own_property_descriptor(&key)?
            .is_some_and(|descriptor| descriptor.enumerable)
            || object.own_property_descriptor(&key)?.is_none()
        {
            continue;
        }
        let value = object.get(&key)?.unwrap_or_default();
        if matches!(value, FieldValue::Function(_)) {
            continue;
        }
        if separator {
            append(output, ", ");
        }
        identifier(&key.into(), output)?;
        append(output, " = ");
        escape(&value, output)?;
        separator = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
