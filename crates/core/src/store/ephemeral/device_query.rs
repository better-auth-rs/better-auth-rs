use crate::{
    AuthError, AuthResult, DeviceCode, DeviceCodeWhere, SchemaValue, WhereMode, WhereOperator,
};
use serde_json::Value;
use std::{borrow::Cow, cmp::Ordering};

pub(super) fn matches(row: &DeviceCode, query: &DeviceCodeWhere) -> AuthResult<bool> {
    let native = match query.field.as_str() {
        "scope" => Some(&row.scope),
        "clientId" => Some(&row.client_id),
        _ => None,
    };
    let actual = if let Some(native) = native {
        if matches!(native, SchemaValue::InvalidDate) {
            return Err(AuthError::config(
                "DeviceCode Where cannot compare an invalid Date represented as a native string field",
            ));
        }
        native.json()?.map(Cow::Owned)
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
        WhereOperator::Eq if query.value.is_null() => Ok(actual.is_none_or(Value::is_null)),
        WhereOperator::Eq => Ok(strict_equals(actual, &query.value, insensitive)),
        WhereOperator::Ne => Ok(!strict_equals(actual, &query.value, insensitive)),
        WhereOperator::In | WhereOperator::NotIn => {
            let values = query
                .value
                .as_array()
                .ok_or_else(|| AuthError::internal("Value must be an array"))?;
            let present = values
                .iter()
                .any(|value| strict_equals(actual, value, insensitive));
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
    match (actual, expected) {
        (Some(Value::String(actual)), Value::String(expected)) if insensitive => {
            actual.to_lowercase() == expected.to_lowercase()
        }
        (Some(Value::Number(actual)), Value::Number(expected)) => {
            actual.as_f64() == expected.as_f64()
        }
        (Some(actual), expected) => actual == expected,
        _ => false,
    }
}

fn compare(actual: Option<&Value>, expected: &Value) -> AuthResult<Option<Ordering>> {
    let Some(actual) = actual else {
        return Ok(None);
    };
    let actual = match actual {
        Value::Array(_) | Value::Object(_) => Cow::Owned(Value::String(
            SchemaValue::<Value>::Dynamic(actual.clone()).display_string()?,
        )),
        actual => Cow::Borrowed(actual),
    };
    if let (Value::String(actual), Value::String(expected)) = (actual.as_ref(), expected) {
        return Ok(Some(actual.encode_utf16().cmp(expected.encode_utf16())));
    }
    Ok(crate::query::number(&actual)?.partial_cmp(&crate::query::number(expected)?))
}

fn pattern(
    actual: Option<&Value>,
    expected: &Value,
    operator: WhereOperator,
    insensitive: bool,
) -> AuthResult<bool> {
    if insensitive {
        let (Some(Value::String(actual)), Value::String(expected)) = (actual, expected) else {
            return Ok(false);
        };
        return Ok(string_pattern(
            &actual.to_lowercase(),
            &expected.to_lowercase(),
            operator,
        ));
    }
    if operator == WhereOperator::Contains {
        match actual {
            None | Some(Value::Null) => return Ok(false),
            Some(Value::Array(values)) => {
                return Ok(values
                    .iter()
                    .any(|value| strict_equals(Some(value), expected, false)));
            }
            _ => {}
        }
    }
    if let Some(Value::String(actual)) = actual {
        return Ok(string_pattern(
            actual,
            &SchemaValue::<Value>::Dynamic(expected.clone()).display_string()?,
            operator,
        ));
    }
    let method = match operator {
        WhereOperator::Contains => "includes",
        WhereOperator::StartsWith => "startsWith",
        _ => "endsWith",
    };
    let message = match actual {
        None => format!("undefined is not an object (evaluating 'record[field].{method}')"),
        Some(Value::Null) => {
            format!("null is not an object (evaluating 'record[field].{method}')")
        }
        _ => format!("record[field].{method} is not a function"),
    };
    Err(AuthError::internal(message))
}

fn string_pattern(actual: &str, expected: &str, operator: WhereOperator) -> bool {
    match operator {
        WhereOperator::Contains => actual.contains(expected),
        WhereOperator::StartsWith => actual.starts_with(expected),
        _ => actual.ends_with(expected),
    }
}
