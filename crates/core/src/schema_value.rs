//! Values whose storage type can be replaced by an application schema.

mod date;

use crate::{AuthError, AuthResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;

/// A schema field retains values outside its default Rust type and distinguishes omission from null.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SchemaValue<T> {
    /// A value with the default field type.
    Typed(T),
    /// A value supplied by a replacement schema or transform.
    Dynamic(Value),
    /// An invalid JavaScript date. Serialize as null but retain NaN date operations.
    InvalidDate,
    /// The adapter omitted the field.
    #[default]
    Undefined,
}

impl<T> SchemaValue<T> {
    /// Borrow the typed value without turning a missing field into a placeholder.
    pub fn as_ref(&self) -> SchemaValue<&T> {
        match self {
            Self::Typed(value) => SchemaValue::Typed(value),
            Self::Dynamic(value) => SchemaValue::Dynamic(value.clone()),
            Self::InvalidDate => SchemaValue::InvalidDate,
            Self::Undefined => SchemaValue::Undefined,
        }
    }

    /// Transform the default type without changing dynamic or omitted values.
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> SchemaValue<U> {
        match self {
            Self::Typed(value) => SchemaValue::Typed(transform(value)),
            Self::Dynamic(value) => SchemaValue::Dynamic(value),
            Self::InvalidDate => SchemaValue::InvalidDate,
            Self::Undefined => SchemaValue::Undefined,
        }
    }
    /// Return whether the field must be omitted from an object.
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Read the default type when an operation requires that type.
    pub fn typed(&self) -> AuthResult<&T> {
        match self {
            Self::Typed(value) => Ok(value),
            Self::Dynamic(_) | Self::InvalidDate | Self::Undefined => Err(AuthError::internal(
                "The schema field does not have the type required by this operation",
            )),
        }
    }
}

impl<T> SchemaValue<Option<T>> {
    /// Match fields that omit both missing and absent optional values.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Undefined | Self::Typed(None))
    }
}

impl<T: PartialEq> PartialEq<T> for SchemaValue<T> {
    fn eq(&self, other: &T) -> bool {
        matches!(self, Self::Typed(value) if value == other)
    }
}

impl PartialEq<str> for SchemaValue<String> {
    fn eq(&self, other: &str) -> bool {
        matches!(self, Self::Typed(value) if value == other)
    }
}

impl SchemaValue<String> {
    /// Inspect a string value for an adapter comparison without converting omission.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Typed(value) => Some(value),
            _ => None,
        }
    }
}

impl PartialEq<&str> for SchemaValue<String> {
    fn eq(&self, other: &&str) -> bool {
        matches!(self, Self::Typed(value) if value == other)
    }
}

impl SchemaValue<Value> {
    /// Decode a projected JSON field while preserving non-JSON date and omission provenance.
    pub fn into_field<T: DeserializeOwned>(self) -> SchemaValue<T> {
        match self {
            Self::Typed(value) | Self::Dynamic(value) => SchemaValue::from_json(Some(value)),
            Self::InvalidDate => SchemaValue::InvalidDate,
            Self::Undefined => SchemaValue::Undefined,
        }
    }
}

impl<T: DeserializeOwned> SchemaValue<T> {
    /// Preserve the adapter value, including a replacement type or an omitted field.
    pub fn from_json(value: Option<Value>) -> Self {
        match value {
            Some(value) => match serde_json::from_value(value.clone()) {
                Ok(typed) => Self::Typed(typed),
                Err(_) => Self::Dynamic(value),
            },
            None => Self::Undefined,
        }
    }
}

impl<T: Serialize> SchemaValue<T> {
    /// Evaluate an endpoint's truthy guard without decoding a replacement field's default type.
    pub fn is_truthy(&self) -> AuthResult<bool> {
        if matches!(self, Self::InvalidDate) {
            return Ok(true);
        }
        Ok(self
            .json()?
            .as_ref()
            .is_some_and(crate::user_fields::is_truthy))
    }

    /// Return the field's JSON value without replacing omission with null.
    pub fn json(&self) -> AuthResult<Option<Value>> {
        if self.is_undefined() {
            Ok(None)
        } else {
            serde_json::to_value(self).map(Some).map_err(Into::into)
        }
    }

    /// Apply JavaScript string conversion for upstream template-literal fields.
    pub fn display_string(&self) -> AuthResult<String> {
        if matches!(self, Self::InvalidDate) {
            return Ok("Invalid Date".to_owned());
        }
        fn display(value: &Value) -> AuthResult<String> {
            Ok(match value {
                Value::String(value) => value.clone(),
                Value::Null => "null".to_owned(),
                Value::Array(values) => values
                    .iter()
                    .map(|value| {
                        if value.is_null() {
                            Ok(String::new())
                        } else {
                            display(value)
                        }
                    })
                    .collect::<AuthResult<Vec<_>>>()?
                    .join(","),
                Value::Object(_) => "[object Object]".to_owned(),
                Value::Number(number) => {
                    let number = number.as_f64().ok_or_else(|| {
                        AuthError::internal("JSON number exceeds JavaScript number range")
                    })?;
                    number_string(number)
                }
                value => value.to_string(),
            })
        }
        self.json()?
            .as_ref()
            .map(display)
            .unwrap_or_else(|| Ok("undefined".to_owned()))
    }
}

/// Format a number with ECMAScript's string conversion, including exponent thresholds.
pub fn number_string(number: f64) -> String {
    if number == 0.0 {
        "0".to_owned()
    } else if number.is_infinite() {
        if number.is_sign_positive() {
            "Infinity"
        } else {
            "-Infinity"
        }
        .to_owned()
    } else if number.abs() >= 1e21 {
        format!("{number:e}").replace('e', "e+")
    } else if number.abs() < 1e-6 {
        format!("{number:e}")
    } else {
        number.to_string()
    }
}

impl SchemaValue<std::borrow::Cow<'_, str>> {
    /// Own a borrowed identifier while retaining an omitted value.
    pub fn into_owned(self) -> SchemaValue<String> {
        self.map(std::borrow::Cow::into_owned)
    }
}

impl<T> From<T> for SchemaValue<T> {
    fn from(value: T) -> Self {
        Self::Typed(value)
    }
}

impl From<&str> for SchemaValue<String> {
    fn from(value: &str) -> Self {
        Self::Typed(value.to_owned())
    }
}

impl<T: Serialize> Serialize for SchemaValue<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Typed(value) => value.serialize(serializer),
            Self::Dynamic(value) => value.serialize(serializer),
            Self::InvalidDate | Self::Undefined => serializer.serialize_unit(),
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for SchemaValue<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Value::deserialize(deserializer).map(|value| Self::from_json(Some(value)))
    }
}

/// Serialize default date values with the upstream millisecond precision.
pub fn serialize_date<S: Serializer>(
    value: &SchemaValue<chrono::DateTime<chrono::Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        SchemaValue::Typed(value) => crate::utils::date::serialize(value, serializer),
        value => value.serialize(serializer),
    }
}

/// Serialize nullable default date values with the upstream millisecond precision.
pub fn serialize_optional_date<S: Serializer>(
    value: &SchemaValue<Option<chrono::DateTime<chrono::Utc>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        SchemaValue::Typed(value) => crate::utils::date::serialize_option(value, serializer),
        value => value.serialize(serializer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_names_use_javascript_number_and_array_coercion() {
        for (value, expected) in [
            (serde_json::json!(7.0), "7"),
            (serde_json::json!(-0.0), "0"),
            (serde_json::json!(1e21), "1e+21"),
            (serde_json::json!(1e-7), "1e-7"),
            (
                serde_json::json!([null, 7.0, ["nested", null]]),
                ",7,nested,",
            ),
            (serde_json::json!({"name": "object"}), "[object Object]"),
        ] {
            assert_eq!(
                SchemaValue::<String>::Dynamic(value)
                    .display_string()
                    .expect("valid JSON value"),
                expected
            );
        }
    }
}
