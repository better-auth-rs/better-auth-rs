//! Adapter values retain JavaScript numbers and object identity until an explicit JSON boundary.

use crate::{AuthError, AuthResult};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use indexmap::IndexMap;
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::Arc,
};

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
/// Transaction change detection must compare `stringify` results instead of `PartialEq`.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum FieldValue {
    #[default]
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Date(FieldDate),
    Array(Arc<[FieldValue]>),
    Object(Arc<FieldMap>),
}

impl FieldValue {
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
            Self::Number(value) => {
                serde_json::Number::from_f64(*value).map_or(JsonValue::Null, JsonValue::Number)
            }
            Self::String(value) => JsonValue::String(value.clone()),
            Self::Date(value) => value.to_datetime()?.map_or(JsonValue::Null, |value| {
                let text = if (0..=9999).contains(&value.year()) {
                    value.to_rfc3339_opts(SecondsFormat::Millis, true)
                } else {
                    format!(
                        "{:+07}{}",
                        value.year(),
                        value.format("-%m-%dT%H:%M:%S%.3fZ")
                    )
                };
                JsonValue::String(text)
            }),
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
        self.json()?
            .as_ref()
            .map(crate::utils::json::stringify)
            .transpose()
            .map_err(Into::into)
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
