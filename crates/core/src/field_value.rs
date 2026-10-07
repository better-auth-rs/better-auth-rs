//! Adapter values retain JavaScript numbers and object identity until an explicit JSON boundary.

use crate::{AuthError, AuthResult};
use chrono::{DateTime, Datelike, Utc};
use indexmap::IndexMap;
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub mod serde;

/// An immutable Date object. Clones retain identity, including for an invalid Date.
/// `PartialEq` compares stored milliseconds; use `same_object` for object identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDate(Arc<Option<i64>>);

impl FieldDate {
    /// Apply ECMAScript TimeClip while retaining valid milliseconds beyond Chrono's range.
    pub fn from_milliseconds(milliseconds: f64) -> Self {
        let clipped = (milliseconds.is_finite() && milliseconds.abs() <= 8_640_000_000_000_000.0)
            .then(|| milliseconds.trunc() as i64);
        Self(Arc::new(clipped))
    }

    /// Create a distinct invalid Date object.
    pub fn invalid() -> Self {
        Self(Arc::new(None))
    }

    /// Read the Date timestamp. Invalid dates return NaN.
    pub fn milliseconds(&self) -> f64 {
        self.0.map_or(f64::NAN, |milliseconds| milliseconds as f64)
    }

    /// Convert a valid Date to Chrono. Invalid dates return `None`.
    /// Valid dates outside Chrono's range return an error instead of becoming invalid dates.
    pub fn to_datetime(&self) -> AuthResult<Option<DateTime<Utc>>> {
        self.0
            .map(|milliseconds| {
                crate::utils::date::from_milliseconds(milliseconds as f64).ok_or_else(|| {
                    AuthError::internal("Valid Date milliseconds exceed Chrono's supported range")
                })
            })
            .transpose()
    }

    fn iso_string(&self) -> AuthResult<Option<String>> {
        let Some(milliseconds) = *self.0 else {
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
}

impl From<DateTime<Utc>> for FieldDate {
    fn from(value: DateTime<Utc>) -> Self {
        Self(Arc::new(Some(value.timestamp_millis())))
    }
}

/// Ordered record fields. Clones preserve the handles stored in field values.
/// An object value supplies identity through its `Arc<FieldMap>`.
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

    /// Import object fields at a JSON boundary without reviving Date strings.
    pub fn from_json(fields: ::serde_json::Map<String, JsonValue>) -> AuthResult<Self> {
        fields
            .into_iter()
            .map(|(name, value)| Ok((name, FieldValue::from_json(value)?)))
            .collect()
    }

    /// Project object fields at a JSON boundary and omit undefined properties.
    pub fn json(&self) -> AuthResult<::serde_json::Map<String, JsonValue>> {
        let mut fields = ::serde_json::Map::new();
        for (name, value) in self {
            if let Some(value) = value.json()? {
                let _ = fields.insert(name.clone(), value);
            }
        }
        Ok(fields)
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
/// `PartialEq` is Rust structural comparison. Use `strict_equals` or `same_value_zero` for JavaScript comparisons.
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
    Array(Arc<[FieldValue]>),
    Object(Arc<FieldMap>),
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

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&FieldMap> {
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
            Self::Date(_) | Self::Array(_) | Self::Object(_) => true,
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
            (Self::Array(left), Self::Array(right)) => Arc::ptr_eq(left, right),
            (Self::Object(left), Self::Object(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    /// Apply the SameValueZero comparison used by JavaScript array `includes`.
    pub fn same_value_zero(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Number(left), Self::Number(right)) if left.is_nan() && right.is_nan())
            || self.strict_equals(other)
    }

    /// Import JSON values without reviving strings as Date objects.
    pub fn from_json(value: JsonValue) -> AuthResult<Self> {
        Ok(match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(value) => Self::Bool(value),
            JsonValue::Number(value) => Self::Number(value.as_f64().ok_or_else(|| {
                AuthError::internal("JSON number exceeds JavaScript number range")
            })?),
            JsonValue::String(value) => Self::String(value),
            JsonValue::Array(values) => values
                .into_iter()
                .map(Self::from_json)
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
            JsonValue::Object(values) => values
                .into_iter()
                .map(|(name, value)| Ok((name, Self::from_json(value)?)))
                .collect::<AuthResult<FieldMap>>()?
                .into(),
        })
    }

    /// Project at a JSON boundary. Top-level undefined has no JSON value.
    /// Object properties omit undefined; array elements encode undefined as null.
    pub fn json(&self) -> AuthResult<Option<JsonValue>> {
        Ok(Some(match self {
            Self::Undefined => return Ok(None),
            Self::Null => JsonValue::Null,
            Self::Bool(value) => JsonValue::Bool(*value),
            Self::Number(_) => serde_json::to_value(serde::Json(self))?,
            Self::String(value) => JsonValue::String(value.clone()),
            Self::Utf16String(value) => JsonValue::String(value.to_utf8().map_err(|error| {
                AuthError::internal(format!(
                    "JSON value cannot represent unpaired UTF-16 surrogates: {error}"
                ))
            })?),
            Self::Date(value) => value
                .iso_string()?
                .map_or(JsonValue::Null, JsonValue::String),
            Self::Array(values) => JsonValue::Array(
                values
                    .iter()
                    .map(|value| value.json().map(|value| value.unwrap_or(JsonValue::Null)))
                    .collect::<AuthResult<_>>()?,
            ),
            Self::Object(values) => {
                let mut output = serde_json::Map::new();
                for (name, value) in values.iter() {
                    if let Some(value) = value.json()? {
                        let _ = output.insert(name.clone(), value);
                    }
                }
                JsonValue::Object(output)
            }
        }))
    }

    /// Serialize with JavaScript property ordering, numeric formatting, and JSON value conversion.
    pub fn stringify(&self) -> AuthResult<Option<String>> {
        if self.is_undefined() {
            Ok(None)
        } else {
            ::serde_json::to_string(&serde::Json(self))
                .map(Some)
                .map_err(Into::into)
        }
    }
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

impl From<FieldMap> for FieldValue {
    fn from(value: FieldMap) -> Self {
        Self::Object(Arc::new(value))
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum Identity {
    Date(usize),
    Array(usize),
    Object(usize),
}

/// Copy one value graph with fresh object identities and preserved aliases.
/// Reuse one context across all records in a transaction snapshot.
/// Create a new context for each independent snapshot.
#[derive(Default)]
pub struct StructuredCloneContext {
    // Retaining source handles prevents pointer reuse between calls through the same context.
    copies: HashMap<Identity, (FieldValue, FieldValue)>,
}

impl StructuredCloneContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy a value while preserving aliases already copied by this context.
    pub fn clone_value(&mut self, value: &FieldValue) -> FieldValue {
        let identity = match value {
            FieldValue::Date(value) => Identity::Date(Arc::as_ptr(&value.0) as usize),
            FieldValue::Array(value) => Identity::Array(Arc::as_ptr(value) as *const () as usize),
            FieldValue::Object(value) => Identity::Object(Arc::as_ptr(value) as usize),
            value => return value.clone(),
        };
        if let Some((_, copied)) = self.copies.get(&identity) {
            return copied.clone();
        }
        let copied = match value {
            FieldValue::Date(value) => FieldDate(Arc::new(*value.0)).into(),
            FieldValue::Array(values) => values
                .iter()
                .map(|value| self.clone_value(value))
                .collect::<Vec<_>>()
                .into(),
            FieldValue::Object(values) => self.clone_map(values).into(),
            value => value.clone(),
        };
        let _ = self
            .copies
            .insert(identity, (value.clone(), copied.clone()));
        copied
    }

    /// Copy record fields using the same alias map as other records in this context.
    pub fn clone_map(&mut self, fields: &FieldMap) -> FieldMap {
        fields
            .iter()
            .map(|(name, value)| (name.clone(), self.clone_value(value)))
            .collect()
    }
}

#[cfg(test)]
mod tests;

impl FieldValue {
    /// Apply JavaScript string conversion while retaining unpaired UTF-16 code units.
    pub fn display_utf16(&self) -> AuthResult<crate::Utf16String> {
        Ok(match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::String(value) => value.as_str().into(),
            Self::Utf16String(value) => value.clone(),
            Self::Bool(value) => value.to_string().into(),
            Self::Number(value) => crate::schema_value::number_string(*value).into(),
            Self::Object(fields) => {
                // Own fields cannot be callable; shadowing toString removes the ordinary primitive conversion.
                if fields.contains_key("toString") {
                    return Err(AuthError::internal(
                        "Cannot convert object to primitive value",
                    ));
                }
                "[object Object]".into()
            }
            Self::Date(value) => match value.to_datetime()? {
                Some(value) => value
                    .with_timezone(&chrono::Local)
                    .format("%a %b %d %Y %H:%M:%S GMT%z (%Z)")
                    .to_string()
                    .into(),
                None => "Invalid Date".into(),
            },
            Self::Array(values) => {
                let mut units = Vec::new();
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        units.push(u16::from(b','));
                    }
                    if !value.is_undefined() && !value.is_null() {
                        units.extend_from_slice(value.display_utf16()?.as_utf16());
                    }
                }
                crate::Utf16String::from_units(units)
            }
        })
    }
}

impl StructuredCloneContext {
    /// Clone one native schema field using the same object graph as its containing record.
    pub fn clone_field<T: crate::SchemaField>(&mut self, value: &T) -> AuthResult<T> {
        self.clone_value(&value.clone().into_field()).decode()
    }
}
