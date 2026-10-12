//! Adapter values retain JavaScript numbers and object or function identity until an explicit boundary.

use crate::{AuthError, AuthResult};
use chrono::{DateTime, Datelike, Utc};
use indexmap::IndexMap;
use serde_json::Value as JsonValue;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

mod array;
mod date_methods;
pub(crate) use array::{ArrayIdentity, FieldArraySource};
pub use array::{FieldArray, FieldArrayIter};
mod function;
pub use function::FieldFunction;
mod object;
pub(crate) use object::ObjectIdentity;
pub use object::{FieldObject, FieldObjectSource};
mod descriptor;
#[cfg(test)]
#[path = "../../../tests/support/native_property_clone.rs"]
mod native_property_clone;
#[cfg(test)]
#[path = "../../../tests/support/native_property_transition.rs"]
mod native_property_transition;
pub use descriptor::{
    FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor, FieldPropertyUpdate,
};
mod structured_clone;
#[doc(hidden)]
pub use structured_clone::ObjectCloneSeed;
pub use structured_clone::StructuredCloneContext;
pub(crate) use structured_clone::{ArrayCloneSeed, prepare_clone};
mod json;
pub(crate) use json::{project_input_json, stringify_http};
mod method_error;
#[cfg(test)]
mod method_error_tests;
mod primitive;
mod property;
mod string_methods;
pub(crate) use primitive::PrimitiveHint;
pub mod serde;

/// A Date with an immutable timestamp and shared named properties.
/// `PartialEq` compares stored milliseconds; use `same_object` for object identity.
#[derive(Clone)]
pub struct FieldDate(Arc<DateState>);

struct DateState {
    milliseconds: Option<i64>,
    properties: FieldObject,
}

impl FieldDate {
    /// Apply ECMAScript TimeClip while retaining valid milliseconds beyond Chrono's range.
    pub fn from_milliseconds(milliseconds: f64) -> Self {
        Self::from_milliseconds_with_properties(milliseconds, FieldMap::new().into())
    }

    /// Create a distinct Date whose property source owns accessors and descriptors.
    pub fn from_milliseconds_with_properties(milliseconds: f64, properties: FieldObject) -> Self {
        let clipped = (milliseconds.is_finite() && milliseconds.abs() <= 8_640_000_000_000_000.0)
            .then(|| milliseconds.trunc() as i64);
        Self(Arc::new(DateState {
            milliseconds: clipped,
            properties,
        }))
    }

    /// Create a distinct invalid Date object.
    pub fn invalid() -> Self {
        Self::from_milliseconds(f64::NAN)
    }

    /// Read the Date timestamp. Invalid dates return NaN.
    pub fn milliseconds(&self) -> f64 {
        self.0
            .milliseconds
            .map_or(f64::NAN, |milliseconds| milliseconds as f64)
    }

    /// Convert a valid Date to Chrono. Invalid dates return `None`.
    /// Valid dates outside Chrono's range return an error instead of becoming invalid dates.
    pub fn to_datetime(&self) -> AuthResult<Option<DateTime<Utc>>> {
        self.0
            .milliseconds
            .map(|milliseconds| {
                crate::utils::date::from_milliseconds(milliseconds as f64).ok_or_else(|| {
                    AuthError::internal("Valid Date milliseconds exceed Chrono's supported range")
                })
            })
            .transpose()
    }

    fn iso_string(&self) -> AuthResult<Option<String>> {
        let Some(milliseconds) = self.0.milliseconds else {
            return Ok(None);
        };
        const YEAR_2000: i64 = 946_684_800_000;
        const CYCLE_MILLISECONDS: i64 = 146_097 * 86_400_000;
        let offset = milliseconds - YEAR_2000;
        // Gregorian dates repeat every 400 years. Euclidean division keeps negative dates in 2000..2399.
        let date = DateTime::<Utc>::from_timestamp_millis(
            YEAR_2000 + offset.rem_euclid(CYCLE_MILLISECONDS),
        )
        .ok_or_else(|| AuthError::internal("Cannot construct a Date within the Gregorian cycle"))?;
        let year = i64::from(date.year()) + 400 * offset.div_euclid(CYCLE_MILLISECONDS);
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+07}")
        };
        Ok(Some(format!(
            "{year}{}",
            date.format("-%m-%dT%H:%M:%S%.3fZ")
        )))
    }

    /// Compare Date object identity without comparing timestamps.
    pub fn same_object(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Borrow the Date's own named properties without reading the timestamp.
    pub fn properties(&self) -> &FieldObject {
        &self.0.properties
    }
}

impl PartialEq for FieldDate {
    fn eq(&self, other: &Self) -> bool {
        self.0.milliseconds == other.0.milliseconds
    }
}

impl Eq for FieldDate {}

impl std::fmt::Debug for FieldDate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("FieldDate")
            .field(&self.0.milliseconds)
            .finish()
    }
}

impl From<DateTime<Utc>> for FieldDate {
    fn from(value: DateTime<Utc>) -> Self {
        Self::from_milliseconds(value.timestamp_millis() as f64)
    }
}

/// Ordered record fields. Clones preserve the handles stored in field values.
/// An object value supplies identity through its `FieldObject` handle.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldMap(IndexMap<String, FieldValue>);

impl FieldMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove a property without changing the order of the remaining properties.
    pub fn remove(&mut self, name: &str) -> Option<FieldValue> {
        self.0.shift_remove(name)
    }

    /// Preserve source property order, then append remaining fields.
    pub fn in_field_order(mut self, order: &[String]) -> Self {
        let mut fields = Self::new();
        for name in order {
            if let Some(value) = self.remove(name) {
                let _ = fields.insert(name.clone(), value);
            }
        }
        fields.extend(self);
        fields
    }

    /// Overlay present schema slots, preserve extension fields, and restore source order.
    /// A missing slot leaves an extension value unchanged; an explicit Undefined is present.
    pub fn with_schema_fields<'a>(
        mut self,
        order: &[String],
        fields: impl IntoIterator<Item = (&'a str, Option<FieldValue>)>,
    ) -> Self {
        for (name, value) in fields {
            if let Some(value) = value {
                let _ = self.insert(name.into(), value);
            }
        }
        self.in_field_order(order)
    }

    /// Order array-index properties first and retain insertion order for other properties.
    pub(crate) fn sort_property_order(&mut self) {
        self.0.sort_by_key(|name, _| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
    }

    /// Import object fields at a JSON boundary without reviving Date strings.
    pub fn from_json(fields: ::serde_json::Map<String, JsonValue>) -> AuthResult<Self> {
        fields
            .into_iter()
            .map(|(name, value)| Ok((name, FieldValue::from_json(value)?)))
            .collect()
    }

    /// Prepare each child field at a JSON boundary without invoking a root `toJSON` method.
    pub fn json(&self) -> AuthResult<::serde_json::Map<String, JsonValue>> {
        json::project_map(self)
    }
}

impl<const N: usize> From<[(String, FieldValue); N]> for FieldMap {
    fn from(fields: [(String, FieldValue); N]) -> Self {
        fields.into_iter().collect()
    }
}

impl Deref for FieldMap {
    type Target = IndexMap<String, FieldValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FieldMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<(String, FieldValue)> for FieldMap {
    fn from_iter<T: IntoIterator<Item = (String, FieldValue)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for FieldMap {
    type Item = (String, FieldValue);
    type IntoIter = indexmap::map::IntoIter<String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a FieldMap {
    type Item = (&'a String, &'a FieldValue);
    type IntoIter = indexmap::map::Iter<'a, String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut FieldMap {
    type Item = (&'a String, &'a mut FieldValue);
    type IntoIter = indexmap::map::IterMut<'a, String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A field value before adapter conversion or JSON serialization.
/// `PartialEq` compares owned objects structurally and live objects by source identity.
/// Use `strict_equals` or `same_value_zero` for JavaScript comparisons.
/// Memory row merge detection compares `stringify` results; credential guards preserve native value distinctions.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum FieldValue {
    #[default]
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Utf16String(crate::Utf16String),
    Date(FieldDate),
    Array(FieldArray),
    Object(FieldObject),
    Function(FieldFunction),
}

impl FieldValue {
    /// Decode the requested Rust type without serializing the field value.
    pub fn decode<T: crate::SchemaField>(&self) -> AuthResult<T> {
        T::from_field(self.clone())
            .map_err(|_| AuthError::internal("Adapter field does not have the requested Rust type"))
    }

    /// Move this value out and leave undefined in its place.
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_) | Self::Utf16String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Test for raw undefined or function values without invoking conversion hooks.
    pub fn is_json_omitted(&self) -> bool {
        matches!(self, Self::Undefined | Self::Function(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<&FieldDate> {
        match self {
            Self::Date(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&FieldArray> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&FieldObject> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    /// Evaluate JavaScript truthiness without serializing numbers or objects.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::Utf16String(value) => !value.as_utf16().is_empty(),
            Self::Date(_) | Self::Array(_) | Self::Object(_) | Self::Function(_) => true,
        }
    }

    /// Apply JavaScript strict equality, including object identity and NaN inequality.
    pub fn strict_equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Undefined, Self::Undefined) | (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Utf16String(left), Self::Utf16String(right)) => left == right,
            (Self::String(left), Self::Utf16String(right))
            | (Self::Utf16String(right), Self::String(left)) => {
                left.encode_utf16().eq(right.as_utf16().iter().copied())
            }
            (Self::Date(left), Self::Date(right)) => left.same_object(right),
            (Self::Array(left), Self::Array(right)) => left.same_array(right),
            (Self::Object(left), Self::Object(right)) => left.same_object(right),
            (Self::Function(left), Self::Function(right)) => left == right,
            _ => false,
        }
    }

    /// Apply JavaScript SameValue, preserving the distinction between positive and negative zero.
    pub fn same_value(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => {
                (left.is_nan() && right.is_nan())
                    || (left == right && left.is_sign_negative() == right.is_sign_negative())
            }
            _ => self.strict_equals(other),
        }
    }

    /// Apply the SameValueZero comparison used by JavaScript array `includes`.
    pub fn same_value_zero(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Number(left), Self::Number(right)) if left.is_nan() && right.is_nan())
            || self.strict_equals(other)
    }

    /// Import JSON values without reviving strings as Date objects.
    pub fn from_json(value: JsonValue) -> AuthResult<Self> {
        Ok(value.into())
    }

    /// Prepare each property once, including its `toJSON` method, then project JSON values.
    /// Prepared undefined and functions are absent at the root, omitted in objects, and null in arrays.
    pub fn json(&self) -> AuthResult<Option<JsonValue>> {
        json::to_value(self)
    }

    /// Parse JSON without discarding lone UTF-16 surrogates or nested field ordering.
    pub fn parse_json(text: &str) -> AuthResult<Self> {
        crate::utils::json::parse_field_json(text)
    }

    /// Serialize with JavaScript property ordering, numeric formatting, and `toJSON` conversion.
    pub fn stringify(&self) -> AuthResult<Option<String>> {
        json::stringify(self)
    }

    /// Preserve the String or Undefined result when passing JSON serialization to a native callback.
    pub fn stringify_native(&self) -> AuthResult<Self> {
        Ok(self.stringify()?.map_or(Self::Undefined, Self::String))
    }
}

fn string_fields(units: impl Iterator<Item = u16>) -> FieldMap {
    units
        .enumerate()
        .map(|(index, unit)| {
            (
                index.to_string(),
                crate::Utf16String::from_units(vec![unit]).into(),
            )
        })
        .collect()
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for FieldValue {
    fn from(value: f64) -> Self {
        Self::Number(value)
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<crate::Utf16String> for FieldValue {
    fn from(value: crate::Utf16String) -> Self {
        match value.to_utf8() {
            Ok(value) => Self::String(value),
            Err(_) => Self::Utf16String(value),
        }
    }
}

impl From<FieldDate> for FieldValue {
    fn from(value: FieldDate) -> Self {
        Self::Date(value)
    }
}

impl From<DateTime<Utc>> for FieldValue {
    fn from(value: DateTime<Utc>) -> Self {
        Self::Date(value.into())
    }
}

impl From<Vec<FieldValue>> for FieldValue {
    fn from(value: Vec<FieldValue>) -> Self {
        Self::Array(value.into())
    }
}

impl From<FieldArray> for FieldValue {
    fn from(value: FieldArray) -> Self {
        Self::Array(value)
    }
}

impl From<FieldMap> for FieldValue {
    fn from(value: FieldMap) -> Self {
        Self::Object(value.into())
    }
}

#[cfg(test)]
mod object_tests;
#[cfg(test)]
mod tests;

impl From<JsonValue> for FieldValue {
    fn from(value: JsonValue) -> Self {
        match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(value) => Self::Bool(value),
            JsonValue::Number(value) => Self::Number(json_number(&value)),
            JsonValue::String(value) => Self::String(value),
            JsonValue::Array(values) => values
                .into_iter()
                .map(Self::from)
                .collect::<Vec<_>>()
                .into(),
            JsonValue::Object(values) => values
                .into_iter()
                .map(|(name, value)| (name, Self::from(value)))
                .collect::<FieldMap>()
                .into(),
        }
    }
}

fn json_number(value: &serde_json::Number) -> f64 {
    value.as_f64().unwrap_or_else(|| {
        // Arbitrary-precision JSON numbers can exceed f64. JavaScript JSON.parse retains signed infinity.
        if value.to_string().starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }
    })
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum ContainerIdentity {
    Array(ArrayIdentity),
    Object(ObjectIdentity),
}
