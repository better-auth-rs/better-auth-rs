//! Values whose storage type can be replaced by an application schema.

mod date;
mod field;
pub use field::SchemaField;

use crate::{AuthError, AuthResult, FieldDate, FieldValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

/// A schema field retains values outside its default Rust type and distinguishes omission from null.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SchemaValue<T> {
    /// A value with the default field type.
    Typed(T),
    /// A value supplied by a replacement schema or transform.
    Dynamic(FieldValue),
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
            Self::Undefined => SchemaValue::Undefined,
        }
    }

    /// Transform the default type without changing dynamic or omitted values.
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> SchemaValue<U> {
        match self {
            Self::Typed(value) => SchemaValue::Typed(transform(value)),
            Self::Dynamic(value) => SchemaValue::Dynamic(value),
            Self::Undefined => SchemaValue::Undefined,
        }
    }
    /// Return whether the adapter omitted this field.
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Read the default type when an operation requires that type.
    pub fn typed(&self) -> AuthResult<&T> {
        match self {
            Self::Typed(value) => Ok(value),
            Self::Dynamic(_) | Self::Undefined => Err(AuthError::internal(
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

impl<T: SchemaField> SchemaValue<T> {
    /// Return whether JSON serialization omits this value at an object boundary.
    pub fn is_json_omitted(&self) -> bool {
        self.field_value().is_json_omitted()
    }

    /// Preserve replacement types and object handles when decoding an adapter field.
    pub fn from_field(value: FieldValue) -> Self {
        if value.is_undefined() {
            Self::Undefined
        } else {
            T::from_field(value).map_or_else(Self::Dynamic, Self::Typed)
        }
    }

    /// Move the stored value into the adapter without applying JSON conversion.
    pub fn into_field_value(self) -> FieldValue {
        match self {
            Self::Typed(value) => value.into_field(),
            Self::Dynamic(value) => value,
            Self::Undefined => FieldValue::Undefined,
        }
    }

    /// Copy the stored value while preserving Date, array, and object handles.
    pub fn field_value(&self) -> FieldValue {
        self.clone().into_field_value()
    }

    /// Import a value at a JSON boundary without reviving Date strings.
    pub fn from_json(value: Option<JsonValue>) -> AuthResult<Self> {
        value
            .map(FieldValue::from_json)
            .transpose()
            .map(|value| Self::from_field(value.unwrap_or_default()))
    }

    /// Evaluate an endpoint's truthy guard without decoding a replacement field's default type.
    pub fn is_truthy(&self) -> AuthResult<bool> {
        Ok(self.field_value().is_truthy())
    }

    /// Return the field's JSON value without replacing omission with null.
    pub fn json(&self) -> AuthResult<Option<JsonValue>> {
        self.field_value().json()
    }

    /// Apply JavaScript string conversion for upstream template-literal fields.
    pub fn display_string(&self) -> AuthResult<String> {
        self.field_value()
            .display_utf16()?
            .to_utf8()
            .map_err(|error| {
                AuthError::internal(format!(
                    "Rust strings cannot represent unpaired UTF-16 surrogates: {error}"
                ))
            })
    }
}

impl<T: SchemaField> SchemaField for SchemaValue<T> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        Ok(Self::from_field(value))
    }

    fn into_field(self) -> FieldValue {
        self.into_field_value()
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

impl SchemaValue<Option<std::borrow::Cow<'_, str>>> {
    /// Own a nullable string while retaining replacement values and omission.
    pub fn into_owned(self) -> SchemaValue<Option<String>> {
        self.map(|value| value.map(std::borrow::Cow::into_owned))
    }
}

impl<T> From<T> for SchemaValue<T> {
    fn from(value: T) -> Self {
        Self::Typed(value)
    }
}

impl From<chrono::DateTime<chrono::Utc>> for SchemaValue<FieldDate> {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Self::Typed(value.into())
    }
}

impl From<&str> for SchemaValue<String> {
    fn from(value: &str) -> Self {
        Self::Typed(value.to_owned())
    }
}

impl<T: SchemaField> Serialize for SchemaValue<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::value::serialize(&self.field_value(), serializer)
    }
}

impl<'de, T: SchemaField> Deserialize<'de> for SchemaValue<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::field_value::serde::value::deserialize(deserializer).map(Self::from_field)
    }
}

/// Serialize default date values with the upstream millisecond precision.
pub fn serialize_date<S: Serializer>(
    value: &SchemaValue<FieldDate>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.serialize(serializer)
}

/// Serialize nullable default date values with the upstream millisecond precision.
pub fn serialize_optional_date<S: Serializer>(
    value: &SchemaValue<Option<FieldDate>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.serialize(serializer)
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
                SchemaValue::<String>::Dynamic(
                    FieldValue::from_json(value).expect("valid JSON value")
                )
                .display_string()
                .expect("valid JSON value"),
                expected
            );
        }
    }
}
