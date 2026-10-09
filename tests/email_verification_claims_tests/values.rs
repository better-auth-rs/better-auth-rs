use better_auth_core::{AuthResult, FieldValue};
use serde_json::{Value, json};

#[expect(
    dead_code,
    reason = "The shared module also exposes fixture revival, which this capture does not require"
)]
#[path = "../support/device_where_values.rs"]
mod shared;

pub(super) fn observe(value: &FieldValue) -> AuthResult<Value> {
    match value {
        FieldValue::Utf16String(value) => Ok(match value.to_utf8() {
            Ok(value) => Value::String(value),
            Err(_) => json!({ "type": "utf16", "units": value.as_utf16() }),
        }),
        FieldValue::Array(values) => Ok(Value::Array(
            values.iter().map(observe).collect::<AuthResult<_>>()?,
        )),
        FieldValue::Object(fields) => Ok(Value::Object(
            fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), observe(value)?)))
                .collect::<AuthResult<_>>()?,
        )),
        value => shared::observe(value),
    }
}

pub(super) fn capture(text: &str) -> AuthResult<Value> {
    observe(&FieldValue::parse_json(text)?)
}

pub(super) fn body(text: &str) -> AuthResult<Value> {
    if text.is_empty() {
        Ok(Value::Null)
    } else {
        capture(text)
    }
}
