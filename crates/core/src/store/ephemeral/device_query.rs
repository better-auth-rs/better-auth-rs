use crate::{
    AuthError, AuthResult, DeviceCode, DeviceCodeWhere, FieldValue as Value, WhereMode,
    WhereOperator,
};
use std::{borrow::Cow, cmp::Ordering};

pub(super) fn matches(row: &DeviceCode, query: &DeviceCodeWhere) -> AuthResult<bool> {
    let native = match query.field.as_str() {
        "scope" => Some(&row.scope),
        "clientId" => Some(&row.client_id),
        _ => None,
    };
    let actual = if let Some(native) = native {
        Some(Cow::Owned(native.field_value()))
    } else {
        row.additional_fields.get(&query.field).map(Cow::Borrowed)
    };
    let actual = actual.as_deref();
    let insensitive = query.mode == WhereMode::Insensitive
        && (query.value.is_string()
            || query
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    match query.operator {
        WhereOperator::Eq if query.value.is_null() => {
            Ok(actual.is_none_or(|value| value.is_null() || value.is_undefined()))
        }
        WhereOperator::Eq => Ok(strict_equals(actual, &query.value, insensitive)),
        WhereOperator::Ne => Ok(!strict_equals(actual, &query.value, insensitive)),
        WhereOperator::In | WhereOperator::NotIn => {
            let values = query
                .value
                .as_array()
                .ok_or_else(|| AuthError::internal("Value must be an array"))?;
            let present = values
                .iter()
                .any(|value| includes(actual, value, insensitive));
            Ok(if query.operator == WhereOperator::In {
                present
            } else {
                !present
            })
        }
        WhereOperator::Lt | WhereOperator::Lte | WhereOperator::Gt | WhereOperator::Gte => {
            if query.value.is_null() {
                return Ok(false);
            }
            let ordering = compare(actual, &query.value)?;
            Ok(match query.operator {
                WhereOperator::Lt => ordering == Some(Ordering::Less),
                WhereOperator::Lte => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
                WhereOperator::Gt => ordering == Some(Ordering::Greater),
                _ => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
            })
        }
        WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
            pattern(actual, &query.value, query.operator, insensitive)
        }
    }
}

fn strict_equals(actual: Option<&Value>, expected: &Value, insensitive: bool) -> bool {
    if insensitive {
        return actual
            .and_then(crate::query::field_string_units)
            .zip(crate::query::field_string_units(expected))
            .is_some_and(|(actual, expected)| lowercase(&actual) == lowercase(&expected));
    }
    actual.unwrap_or(&Value::Undefined).strict_equals(expected)
}

fn includes(actual: Option<&Value>, expected: &Value, insensitive: bool) -> bool {
    if insensitive {
        strict_equals(actual, expected, true)
    } else {
        actual
            .unwrap_or(&Value::Undefined)
            .same_value_zero(expected)
    }
}

fn compare(actual: Option<&Value>, expected: &Value) -> AuthResult<Option<Ordering>> {
    let Some(actual) = actual else {
        return Ok(None);
    };
    crate::query::field_compare(actual, expected)
}

fn pattern(
    actual: Option<&Value>,
    expected: &Value,
    operator: WhereOperator,
    insensitive: bool,
) -> AuthResult<bool> {
    if insensitive {
        let Some((actual, expected)) = actual
            .and_then(crate::query::field_string_units)
            .zip(crate::query::field_string_units(expected))
        else {
            return Ok(false);
        };
        return Ok(string_pattern(
            &lowercase(&actual),
            &lowercase(&expected),
            operator,
        ));
    }
    if operator == WhereOperator::Contains {
        match actual {
            None | Some(Value::Undefined | Value::Null) => return Ok(false),
            Some(Value::Array(values)) => {
                return Ok(values.iter().any(|value| value.same_value_zero(expected)));
            }
            _ => {}
        }
    }
    if let Some(actual) = actual.and_then(crate::query::field_string_units) {
        return Ok(string_pattern(
            &actual,
            expected.display_utf16()?.as_utf16(),
            operator,
        ));
    }
    let method = match operator {
        WhereOperator::Contains => "includes",
        WhereOperator::StartsWith => "startsWith",
        _ => "endsWith",
    };
    let message = match actual {
        None | Some(Value::Undefined) => {
            format!("undefined is not an object (evaluating 'record[field].{method}')")
        }
        Some(Value::Null) => {
            format!("null is not an object (evaluating 'record[field].{method}')")
        }
        _ => format!("record[field].{method} is not a function"),
    };
    Err(AuthError::internal(message))
}

fn string_pattern(actual: &[u16], expected: &[u16], operator: WhereOperator) -> bool {
    match operator {
        WhereOperator::Contains => {
            expected.is_empty() || actual.windows(expected.len()).any(|part| part == expected)
        }
        WhereOperator::StartsWith => actual.starts_with(expected),
        _ => actual.ends_with(expected),
    }
}

fn lowercase(units: &[u16]) -> Vec<u16> {
    let mut output = Vec::new();
    let mut text = String::new();
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok(character) => text.push(character),
            Err(error) => {
                output.extend(text.to_lowercase().encode_utf16());
                text.clear();
                output.push(error.unpaired_surrogate());
            }
        }
    }
    output.extend(text.to_lowercase().encode_utf16());
    output
}
