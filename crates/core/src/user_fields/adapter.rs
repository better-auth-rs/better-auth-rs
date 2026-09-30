use super::{UserConfig, UserFieldConfig, UserFieldType};
use crate::AuthResult;
use serde_json::{Map, Value};

impl UserConfig {
    /// Apply storage policies before converting JSON for the selected adapter.
    pub fn storage_fields_for_adapter(
        &self,
        input: Map<String, Value>,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut fields = self.storage_fields(input, create)?;
        if !supports_native_json {
            for (name, field) in &self.additional_fields {
                let storage_name = field.field_name.as_ref().unwrap_or(name);
                if matches!(field.field_type, UserFieldType::Json)
                    && let Some(value) = fields.get_mut(storage_name)
                    && (value.is_null()
                        || (!native_json_field(storage_name)
                            && (value.is_object() || value.is_array())))
                {
                    *value = Value::String(value.to_string());
                }
            }
        }
        Ok(fields)
    }
}

impl UserFieldConfig {
    /// Run the output policy on adapter storage values, then decode text-backed JSON.
    pub fn adapter_output(
        &self,
        mut value: Option<Value>,
        supports_native_json: bool,
    ) -> AuthResult<Option<Value>> {
        let text_json = !supports_native_json && matches!(self.field_type, UserFieldType::Json);
        if text_json {
            value = value.map(|value| match value {
                Value::Object(_) | Value::Array(_) => Value::String(value.to_string()),
                value => value,
            });
        }
        if let Some(transform) = &self.output_transform {
            value = transform(value)?;
        }
        Ok(value.map(|value| match value {
            Value::String(text) if text_json => parse_json(&text),
            value => value,
        }))
    }
}

fn parse_json(text: &str) -> Value {
    let mut value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            // The upstream adapter logs invalid JSON and returns null.
            tracing::error!(%error, "Error parsing JSON");
            return Value::Null;
        }
    };
    fn revive_dates(value: &mut Value) {
        match value {
            Value::Object(fields) => fields.values_mut().for_each(revive_dates),
            Value::Array(values) => values.iter_mut().for_each(revive_dates),
            Value::String(text) => {
                if let Some(date) = json_date(text) {
                    *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            _ => {}
        }
    }
    revive_dates(&mut value);
    value
}

fn json_date(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
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
