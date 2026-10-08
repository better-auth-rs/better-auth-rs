//! Raw query collection and validated endpoint scope.

use serde::Deserialize;
use std::future::Future;

use serde_json::{Map, Value, json};

use crate::{AuthResponse, AuthResult, FieldValue};

/// Decode HTTP query pairs without discarding repeated values or literal bracketed names.
pub fn parse_url_query(query: &str) -> Value {
    let mut result = Map::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = Value::String(value.into_owned());
        match result.entry(name.into_owned()) {
            serde_json::map::Entry::Vacant(entry) => {
                let _ = entry.insert(value);
            }
            serde_json::map::Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(values) => values.push(value),
                previous => {
                    let first = std::mem::replace(previous, Value::Null);
                    *previous = Value::Array(vec![first, value]);
                }
            },
        }
    }
    Value::Object(result)
}

/// Run only the endpoint handler and its nested callbacks with validated query input.
/// The outer dispatch context retains raw input for before and after hooks.
pub fn with_validated_query<T>(
    query: Option<Value>,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let future = Box::pin(future);
    async move {
        if let Some(mut context) = crate::hooks::current_request_hook_context() {
            context.query = query;
            crate::hooks::with_request_hook_context_value(context, future).await
        } else {
            future.await
        }
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Object(_) => "object",
    }
}

fn invalid_type(location: &str, expected: &str, value: &Value) -> AuthResponse {
    AuthResponse::text(400, json!({
        "code": "VALIDATION_ERROR",
        "message": format!("[{location}] Invalid input: expected {expected}, received {}", type_name(value)),
    }).to_string()).with_header("content-type", "application/json")
}

pub(crate) fn string_field<'a>(
    query: Option<&'a Value>,
    name: &str,
) -> Result<Option<&'a str>, AuthResponse> {
    let Some(query) = query else {
        return Ok(None);
    };
    let object = query
        .as_object()
        .ok_or_else(|| invalid_type("query", "object", query))?;
    object
        .get(name)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_type(&format!("query.{name}"), "string", value))
        })
        .transpose()
}

/// Validate the shared get-session query schema, including JavaScript boolean coercion.
pub fn session_query(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(query) = query else {
        return Ok(None);
    };
    let object = query
        .as_object()
        .ok_or_else(|| invalid_type("query", "object", &query))?;
    let mut validated = Map::new();
    for name in ["disableCookieCache", "disableRefresh"] {
        if let Some(value) = object.get(name) {
            let _ = validated.insert(
                name.into(),
                Value::Bool(FieldValue::from_json(value.clone())?.is_truthy()),
            );
        }
    }
    Ok(Some(Value::Object(validated)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthRequest, HttpMethod};

    #[test]
    fn repeated_query_values_keep_order_empty_values_and_literal_names() {
        assert_eq!(
            parse_url_query("value=a+b&value=a%2Bb&value=&value%5B%5D=one&value%5B%5D=two"),
            json!({
                "value": ["a b", "a+b", ""], "value[]": ["one", "two"],
            })
        );
        assert_eq!(parse_url_query(""), json!({}));
        assert_eq!(
            session_query(Some(parse_url_query(
                "disableCookieCache=&disableCookieCache="
            )))
            .unwrap(),
            Some(json!({"disableCookieCache":true}))
        );
        assert_eq!(
            session_query(Some(json!({"disableCookieCache":false,"ignored":true}))).unwrap(),
            Some(json!({"disableCookieCache":false}))
        );
        assert_eq!(session_query(None).unwrap(), None);
        assert!(session_query(Some(Value::Null)).is_err());
    }

    #[tokio::test]
    async fn handler_projection_restores_raw_query_after_success_and_error() {
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        request.query = Some(parse_url_query("disableCookieCache=false&unknown=keep"));
        let raw = request.query.clone();
        crate::with_request_hook_context(&request, async {
            for fail in [false, true] {
                let result: AuthResult<()> =
                    with_validated_query(Some(json!({"disableCookieCache":true})), async {
                        let context = crate::hooks::current_request_hook_context().unwrap();
                        assert_eq!(context.query, Some(json!({"disableCookieCache":true})));
                        assert_eq!(context.request.query, raw);
                        if fail {
                            Err(crate::AuthError::bad_request("endpoint failed"))
                        } else {
                            Ok(())
                        }
                    })
                    .await;
                assert_eq!(result.is_err(), fail);
                assert_eq!(
                    crate::hooks::current_request_hook_context().unwrap().query,
                    raw
                );
            }
            Ok(())
        })
        .await
        .unwrap();
    }
}

/// Apply ECMAScript `Number` conversion to a JSON endpoint value.
pub fn number(value: &Value) -> AuthResult<f64> {
    field_number(&FieldValue::from_json(value.clone())?)
}

/// Apply ECMAScript `Number` conversion without erasing Date or non-finite values.
pub fn field_number(value: &FieldValue) -> AuthResult<f64> {
    match value {
        FieldValue::Undefined => Ok(f64::NAN),
        FieldValue::Null => Ok(0.0),
        FieldValue::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
        FieldValue::Number(value) => Ok(*value),
        FieldValue::Date(value) => Ok(value.milliseconds()),
        value => {
            let Ok(text) = value.display_utf16()?.to_utf8() else {
                return Ok(f64::NAN);
            };
            if text
                .trim_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}')
                .is_empty()
            {
                return Ok(0.0);
            }
            Ok(crate::organization_fields::numeric_filter(&text).unwrap_or(f64::NAN))
        }
    }
}

/// Match Memory adapter equality, where a null filter also selects missing fields.
pub fn field_matches_equality(actual: &FieldValue, expected: &FieldValue) -> bool {
    if expected.is_null() {
        actual.is_null() || actual.is_undefined()
    } else {
        actual.strict_equals(expected)
    }
}

/// Apply the Date constructor while preserving invalid dates and runtime conversion failures.
pub fn field_date(value: &FieldValue) -> AuthResult<crate::FieldDate> {
    let primitive = match value {
        FieldValue::Date(date) => {
            return Ok(crate::FieldDate::from_milliseconds(date.milliseconds()));
        }
        FieldValue::Array(_) | FieldValue::Object(_) => FieldValue::from(value.display_utf16()?),
        value => value.clone(),
    };
    Ok(match primitive {
        FieldValue::String(text) => crate::utils::date::parse_adapter_date(&text)
            .map(crate::FieldDate::from)
            .unwrap_or_else(crate::FieldDate::invalid),
        FieldValue::Utf16String(_) => crate::FieldDate::invalid(),
        value => crate::FieldDate::from_milliseconds(field_number(&value)?),
    })
}

/// Apply JavaScript addition, including string concatenation after primitive conversion.
pub fn field_add(left: &FieldValue, right: &FieldValue) -> AuthResult<FieldValue> {
    let primitive = |value: &FieldValue| -> AuthResult<FieldValue> {
        match value {
            FieldValue::Date(_) | FieldValue::Array(_) | FieldValue::Object(_) => {
                Ok(value.display_utf16()?.into())
            }
            value => Ok(value.clone()),
        }
    };
    let left = primitive(left)?;
    let right = primitive(right)?;
    if field_string_units(&left).is_some() || field_string_units(&right).is_some() {
        let mut units = left.display_utf16()?.as_utf16().to_vec();
        units.extend_from_slice(right.display_utf16()?.as_utf16());
        Ok(crate::Utf16String::from_units(units).into())
    } else {
        Ok((field_number(&left)? + field_number(&right)?).into())
    }
}

/// Read JavaScript string code units without replacing unpaired surrogates.
pub fn field_string_units(value: &FieldValue) -> Option<std::borrow::Cow<'_, [u16]>> {
    match value {
        FieldValue::String(value) => Some(value.encode_utf16().collect::<Vec<_>>().into()),
        FieldValue::Utf16String(value) => Some(value.as_utf16().into()),
        _ => None,
    }
}

/// Apply JavaScript relational conversion. An unordered number comparison returns `None`.
pub fn field_compare(
    left: &FieldValue,
    right: &FieldValue,
) -> AuthResult<Option<std::cmp::Ordering>> {
    let primitive = |value: &FieldValue| -> AuthResult<FieldValue> {
        Ok(match value {
            FieldValue::Date(value) => FieldValue::Number(value.milliseconds()),
            FieldValue::Array(_) | FieldValue::Object(_) => {
                FieldValue::from(value.display_utf16()?)
            }
            value => value.clone(),
        })
    };
    let left = primitive(left)?;
    let right = primitive(right)?;
    if let (Some(left), Some(right)) = (field_string_units(&left), field_string_units(&right)) {
        return Ok(Some(left.cmp(&right)));
    }
    Ok(field_number(&left)?.partial_cmp(&field_number(&right)?))
}

/// Parse the integer prefix used by Organization's `membersLimit` schema.
pub fn parse_integer(value: &str) -> f64 {
    let value = value
        .trim_start_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}');
    let (negative, value) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let (radix, value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((10, value), |value| (16, value));
    let mut digits = value.chars().map_while(|ch| ch.to_digit(radix));
    let Some(first) = digits.next() else {
        return f64::NAN;
    };
    let value = digits.fold(f64::from(first), |value, digit| {
        value * f64::from(radix) + f64::from(digit)
    });
    if negative { -value } else { value }
}

/// Convert a JSON string/number after the route's union validation and adapter defaulting.
pub fn optional_nonzero_number<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<f64>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    value
        .as_ref()
        .map(number)
        .transpose()
        .map(|value| value.filter(|value| *value != 0.0 && !value.is_nan()))
        .map_err(serde::de::Error::custom)
}

/// Use the memory adapter's sequential `slice(offset)` and `slice(0, limit)` semantics.
pub fn paginate_memory<T>(items: Vec<T>, limit: Option<f64>, offset: Option<f64>) -> Vec<T> {
    fn index(value: f64, length: usize) -> usize {
        if value.is_nan() {
            return 0;
        }
        let length_float = length as f64;
        let value = value.trunc();
        if value < 0.0 {
            (length_float + value).clamp(0.0, length_float) as usize
        } else {
            value.min(length_float) as usize
        }
    }
    let start = offset.map_or(0, |offset| index(offset, items.len()));
    let count = items.len() - start;
    let count = limit.map_or(count, |limit| index(limit, count));
    items.into_iter().skip(start).take(count).collect()
}

#[cfg(test)]
mod field_tests {
    use super::*;
    use crate::{FieldDate, Utf16String};
    use std::cmp::Ordering;

    #[test]
    fn runtime_relational_conversion_preserves_dates_nonfinite_numbers_and_utf16() -> AuthResult<()>
    {
        let date = FieldValue::Date(FieldDate::from_milliseconds(42.0));
        assert_eq!(
            field_compare(&date, &FieldValue::Number(43.0))?,
            Some(Ordering::Less)
        );
        assert_eq!(field_compare(&FieldDate::invalid().into(), &date)?, None);
        assert_eq!(
            field_compare(&FieldValue::Number(f64::NAN), &FieldValue::Null)?,
            None
        );
        let high_surrogate = FieldValue::from(Utf16String::from_units(vec![0xd800]));
        assert!(field_number(&high_surrogate)?.is_nan());
        let array = FieldValue::from(vec![high_surrogate.clone()]);
        assert!(field_number(&array)?.is_nan());
        assert_eq!(
            field_compare(&array, &high_surrogate)?,
            Some(Ordering::Equal)
        );
        assert_eq!(
            field_compare(&high_surrogate, &FieldValue::from("\u{e000}"))?,
            Some(Ordering::Less)
        );
        Ok(())
    }
}

#[cfg(test)]
mod dynamic_value_tests {
    use super::*;

    #[test]
    fn memory_null_query_selects_missing_without_coercing_other_values() {
        assert!(field_matches_equality(
            &FieldValue::Undefined,
            &FieldValue::Null
        ));
        assert!(!field_matches_equality(
            &FieldValue::Null,
            &FieldValue::Undefined
        ));
        assert!(!field_matches_equality(&0.0.into(), &false.into()));
        assert!(!field_matches_equality(&"1".into(), &1.0.into()));
        let object = FieldValue::from(crate::FieldMap::new());
        assert!(field_matches_equality(&object, &object));
        assert!(!field_matches_equality(
            &object,
            &crate::FieldMap::new().into()
        ));
    }

    #[test]
    fn arithmetic_keeps_addition_and_numeric_decrement_distinct() -> AuthResult<()> {
        let value = FieldValue::from("2");
        assert_eq!(field_add(&value, &1.0.into())?, FieldValue::from("21"));
        assert_eq!(field_number(&value)? - 1.0, 1.0);
        assert_eq!(field_add(&FieldValue::Null, &1.0.into())?, 1.0.into());
        assert!(
            matches!(field_add(&FieldValue::Undefined, &1.0.into())?, FieldValue::Number(value) if value.is_nan())
        );
        assert_eq!(
            field_add(&Vec::<FieldValue>::new().into(), &1.0.into())?,
            "1".into()
        );
        assert!(
            field_add(
                &crate::FieldMap::from([("toString".into(), false.into())]).into(),
                &1.0.into()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn date_constructor_preserves_nan_and_applies_array_primitive_conversion() -> AuthResult<()> {
        assert!(field_date(&FieldValue::Undefined)?.milliseconds().is_nan());
        assert_eq!(field_date(&FieldValue::Null)?.milliseconds(), 0.0);
        assert_eq!(field_date(&true.into())?.milliseconds(), 1.0);
        assert_eq!(
            field_date(&vec![FieldValue::from("2026-01-02T03:04:05Z")].into())?.milliseconds(),
            1_767_323_045_000.0
        );
        let date = crate::FieldDate::from_milliseconds(123.0);
        let converted = field_date(&date.clone().into())?;
        assert_eq!(converted, date);
        assert!(!converted.same_object(&date));
        Ok(())
    }
}
