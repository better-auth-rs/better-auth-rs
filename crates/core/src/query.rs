//! Raw query collection and validated endpoint scope.

use serde::Deserialize;
use std::future::Future;

use serde_json::{Map, Value, json};

use crate::{AuthResponse, AuthResult};

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
                Value::Bool(crate::user_fields::is_truthy(value)),
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
        })
        .await;
    }
}

/// Apply ECMAScript `Number` conversion to a JSON endpoint value.
pub fn number(value: &Value) -> AuthResult<f64> {
    match value {
        Value::Null => Ok(0.0),
        Value::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
        Value::Number(value) => value.as_f64().ok_or_else(|| {
            crate::AuthError::internal("JSON number exceeds JavaScript number range")
        }),
        value => {
            let text = crate::SchemaValue::<Value>::Dynamic(value.clone()).display_string()?;
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
