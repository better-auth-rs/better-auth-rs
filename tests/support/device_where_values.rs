use better_auth_core::{AuthError, AuthResult, FieldDate, FieldMap, FieldValue};
use serde_json::{Value, json};

pub(super) fn observe(value: &FieldValue) -> AuthResult<Value> {
    Ok(match value {
        FieldValue::Undefined => json!({"type":"undefined"}),
        FieldValue::Date(date) => json!({
            "type":"date",
            "value": if date.milliseconds().is_nan() {
                Value::String("Invalid Date".into())
            } else {
                value.json()?.ok_or_else(|| AuthError::internal("A Date observation must have a JSON value"))?
            },
        }),
        FieldValue::Number(number) if !number.is_finite() => json!({
            "type":"number",
            "value": if number.is_nan() { "NaN" } else if number.is_sign_positive() { "Infinity" } else { "-Infinity" },
        }),
        FieldValue::Array(values) => {
            Value::Array(values.iter().map(observe).collect::<AuthResult<_>>()?)
        }
        FieldValue::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), observe(value)?)))
                .collect::<AuthResult<_>>()?,
        ),
        value => value
            .json()?
            .ok_or_else(|| AuthError::internal("A scalar observation must have a JSON value"))?,
    })
}

pub(super) fn revive(value: &Value) -> AuthResult<FieldValue> {
    Ok(match value {
        Value::Object(fields)
            if fields.get("type").and_then(Value::as_str) == Some("undefined") =>
        {
            if fields.len() != 1 {
                return Err(AuthError::internal(
                    "An undefined fixture tag must contain only its type",
                ));
            }
            FieldValue::Undefined
        }
        Value::Object(fields) if fields.get("type").and_then(Value::as_str) == Some("date") => {
            if fields.len() != 2 {
                return Err(AuthError::internal(
                    "A Date fixture tag must contain its type and value",
                ));
            }
            let text = fields.get("value").and_then(Value::as_str).ok_or_else(|| {
                AuthError::internal("A Date fixture tag must contain a string value")
            })?;
            let date = if text == "Invalid Date" {
                FieldDate::invalid()
            } else {
                text.parse::<chrono::DateTime<chrono::Utc>>()
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid captured Date: {error}"))
                    })?
                    .into()
            };
            FieldValue::Date(date)
        }
        Value::Object(fields) if fields.get("type").and_then(Value::as_str) == Some("number") => {
            if fields.len() != 2 {
                return Err(AuthError::internal(
                    "A number fixture tag must contain its type and value",
                ));
            }
            FieldValue::Number(match fields.get("value").and_then(Value::as_str) {
                Some("NaN") => f64::NAN,
                Some("Infinity") => f64::INFINITY,
                Some("-Infinity") => f64::NEG_INFINITY,
                _ => {
                    return Err(AuthError::internal(
                        "A number fixture tag must contain a non-finite number",
                    ));
                }
            })
        }
        Value::Array(values) => {
            FieldValue::from(values.iter().map(revive).collect::<AuthResult<Vec<_>>>()?)
        }
        Value::Object(fields) => FieldValue::from(
            fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), revive(value)?)))
                .collect::<AuthResult<FieldMap>>()?,
        ),
        value => FieldValue::from_json(value.clone())?,
    })
}
