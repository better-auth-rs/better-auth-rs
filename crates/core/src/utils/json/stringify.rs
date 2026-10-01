use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::{Value, value::RawValue};

/// Read an ECMAScript array-index property name. Leading zeroes and 2^32 - 1 are ordinary keys.
pub fn array_index(key: &str) -> Option<u32> {
    key.parse::<u32>()
        .ok()
        .filter(|index| *index != u32::MAX && index.to_string() == key)
}

/// Serialize JSON values with JavaScript property ordering and number formatting.
pub fn stringify(value: &Value) -> serde_json::Result<String> {
    serde_json::to_string(&JavaScriptJson(value))
}

struct JavaScriptJson<'a>(&'a Value);

impl Serialize for JavaScriptJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(fields) => {
                let mut fields: Vec<_> = fields.iter().collect();
                fields.sort_by_key(|(key, _)| {
                    array_index(key).map_or((true, 0), |index| (false, index))
                });
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(key, &JavaScriptJson(value))?;
                }
                map.end()
            }
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&JavaScriptJson(value))?;
                }
                sequence.end()
            }
            Value::Number(number) => {
                let number = number.as_f64().ok_or_else(|| {
                    <S::Error as serde::ser::Error>::custom("JSON number exceeds JavaScript range")
                })?;
                RawValue::from_string(crate::schema_value::number_string(number))
                    .map_err(serde::ser::Error::custom)?
                    .serialize(serializer)
            }
            value => value.serialize(serializer),
        }
    }
}
