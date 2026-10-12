use super::{ArrayIdentity, FieldArray, FieldFunction, FieldValue};
use crate::{AuthError, AuthResult};
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimitiveHint {
    String,
    Number,
    Default,
}

enum PrimitiveValue {
    Value(FieldValue),
    FunctionSource,
}

impl PrimitiveValue {
    fn into_value(self) -> AuthResult<FieldValue> {
        match self {
            Self::Value(value) => Ok(value),
            Self::FunctionSource => Err(AuthError::internal(
                "JavaScript function source is unavailable for this Rust field callback",
            )),
        }
    }
}

impl FieldValue {
    /// Invoke `toLowerCase` at a business read, retaining a custom method's native result.
    pub fn lowercase_method(&self, expression: &str) -> AuthResult<Self> {
        match self {
            Self::String(text) => Ok(crate::Utf16String::from(text.as_str())
                .to_lowercase()
                .into()),
            Self::Utf16String(text) => Ok(text.to_lowercase().into()),
            Self::Null | Self::Undefined => {
                let kind = if self.is_null() { "null" } else { "undefined" };
                Err(AuthError::type_error(format!(
                    "{kind} is not an object (evaluating '{expression}.toLowerCase')"
                )))
            }
            _ => match self.model_property("toLowerCase")? {
                Self::Function(method) => method.call_with(self, &[]),
                _ => Err(AuthError::type_error(format!(
                    "{expression}.toLowerCase is not a function. (In '{expression}.toLowerCase()', '{expression}.toLowerCase' is undefined)"
                ))),
            },
        }
    }

    /// Invoke `join(separator)` without converting a custom method's native result.
    pub fn join_method(&self, separator: &Self, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("join")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(separator))
            }
            (Self::Array(values), None) => {
                Ok(Self::array_join(values, separator, &mut HashSet::new())?.into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.join is not a function"
            ))),
        }
    }

    /// Invoke `includes(expected)` and retain a custom method's native result.
    pub fn includes_method(&self, expected: &Self, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("includes")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(expected))
            }
            (Self::Array(values), None) => Ok(values.includes(expected)?.into()),
            (Self::String(_) | Self::Utf16String(_), None) => {
                let units = self.display_utf16()?;
                let needle = expected.display_utf16()?;
                Ok((needle.as_utf16().is_empty()
                    || units
                        .as_utf16()
                        .windows(needle.as_utf16().len())
                        .any(|part| part == needle.as_utf16()))
                .into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.includes is not a function"
            ))),
        }
    }

    /// Invoke `filter(predicate)` without narrowing a custom method's return value.
    pub fn filter_method(&self, predicate: &FieldFunction, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("filter")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, &[predicate.clone().into()])
            }
            (Self::Array(values), None) => Ok(values
                .filter_with_index(|value, index| {
                    Ok(predicate
                        .call_with(
                            &Self::Undefined,
                            &[value.clone(), index.into(), self.clone()],
                        )?
                        .is_truthy())
                })?
                .into()),
            _ => Err(AuthError::type_error(format!(
                "{expression}.filter is not a function"
            ))),
        }
    }

    /// Invoke `find(predicate)`, visiting holes and preserving the selected value's identity.
    pub fn find_method(&self, predicate: &FieldFunction, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("find")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, &[predicate.clone().into()])
            }
            (Self::Array(values), None) => {
                let length = values.len()?;
                for index in 0..length {
                    let value = values.get(index)?.unwrap_or_default();
                    if predicate
                        .call_with(
                            &Self::Undefined,
                            &[value.clone(), index.into(), self.clone()],
                        )?
                        .is_truthy()
                    {
                        return Ok(value);
                    }
                }
                Ok(Self::Undefined)
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.find is not a function"
            ))),
        }
    }

    /// Invoke `map(callback)` and preserve sparse arrays and custom method results.
    /// `argument_expression` supplies source context for a missing method's error.
    pub fn map_method(
        &self,
        callback: &FieldFunction,
        expression: &str,
        argument_expression: Option<&str>,
    ) -> AuthResult<Self> {
        match (self, self.method_property("map")?) {
            (_, Some(Self::Function(method))) => method.call_with(self, &[callback.clone().into()]),
            (Self::Array(values), None) => Ok(values
                .map_with_index(|value, index| {
                    callback.call_with(&Self::Undefined, &[value, index.into(), self.clone()])
                })?
                .into()),
            (_, method) => Err(AuthError::type_error(match (method, argument_expression) {
                (None | Some(Self::Undefined), Some(argument)) => format!(
                    "{expression}.map is not a function. (In '{expression}.map({argument})', '{expression}.map' is undefined)"
                ),
                _ => format!("{expression}.map is not a function"),
            })),
        }
    }

    pub(crate) fn concat_method(&self, arguments: &[Self], expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("concat")?) {
            (_, Some(Self::Function(method))) => method.call_with(self, arguments),
            (Self::Array(values), None) => Ok(values.concat(arguments)?.into()),
            (Self::String(_) | Self::Utf16String(_), None) => {
                let mut units = self.display_utf16()?.as_utf16().to_vec();
                for value in arguments {
                    units.extend_from_slice(value.display_utf16()?.as_utf16());
                }
                Ok(crate::Utf16String::from_units(units).into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.concat is not a function"
            ))),
        }
    }

    /// Invoke `sort(comparator)` with native method dispatch and fallible comparison.
    pub fn sort_method(&self, comparator: &FieldFunction, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("sort")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, &[comparator.clone().into()])
            }
            (Self::Array(values), None) => {
                values.sort_by(|left, right| {
                    let compared =
                        comparator.call_with(&Self::Undefined, &[left.clone(), right.clone()])?;
                    Ok(crate::query::field_number(&compared)?
                        .partial_cmp(&0.0)
                        .unwrap_or(std::cmp::Ordering::Equal))
                })?;
                Ok(self.clone())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.sort is not a function"
            ))),
        }
    }

    pub(crate) fn at_method(&self, index: &Self, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("at")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(index))
            }
            (Self::Array(_) | Self::String(_) | Self::Utf16String(_), None) => {
                let length = crate::query::field_number(&self.model_property("length")?)?;
                let index = crate::query::field_number(index)?;
                let index = if index.is_nan() { 0.0 } else { index.trunc() };
                let index = if index < 0.0 { length + index } else { index };
                if index < 0.0 || index >= length {
                    return Ok(Self::Undefined);
                }
                self.model_property(&crate::schema_value::number_string(index))
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.at is not a function"
            ))),
        }
    }

    /// Invoke `getTime()` and retain the native result until the caller's numeric boundary.
    pub fn get_time_method(&self, expression: &str) -> AuthResult<Self> {
        self.read_date_getter("getTime", |_| {
            AuthError::type_error(format!("{expression}.getTime is not a function"))
        })
    }

    /// Invoke `toISOString()` without calling `toJSON` or narrowing a custom method's result.
    /// `expression` names the method in a non-callable error, such as `key.createdAt.toISOString`.
    pub fn to_iso_string_method(&self, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("toISOString")?) {
            (_, Some(Self::Function(method))) => method.call_with(self, &[]),
            (Self::Date(date), None) => date
                .iso_string()?
                .map(Self::String)
                .ok_or_else(|| AuthError::RangeError("Invalid Date".into())),
            _ => Err(AuthError::type_error(format!(
                "{expression} is not a function"
            ))),
        }
    }

    pub(super) fn method_property(&self, name: &str) -> AuthResult<Option<Self>> {
        if self.is_null() || self.is_undefined() {
            return self.model_property(name).map(Some);
        }
        self.property_source()
            .map(|source| source.get_with_receiver(name, self))
            .transpose()
            .map(Option::flatten)
    }

    /// Call the receiver's `toString` method without applying ToPrimitive fallback.
    pub(crate) fn call_to_string(&self) -> AuthResult<Self> {
        if let Some(fields) = self.property_source() {
            return match fields.get_with_receiver("toString", self)? {
                Some(Self::Function(method)) => method.call_with(self, &[]),
                None => self.builtin_to_string(&mut HashSet::new())?.into_value(),
                Some(_) => Err(AuthError::type_error(
                    "data.status.toString is not a function",
                )),
            };
        }
        if self.is_null() || self.is_undefined() {
            return self.model_property("toString");
        }
        Ok(self.display_utf16()?.into())
    }

    pub(crate) fn primitive(&self, hint: PrimitiveHint) -> AuthResult<Self> {
        self.primitive_with_active(hint, &mut HashSet::new())?
            .into_value()
    }

    pub(crate) fn number_primitive(&self) -> AuthResult<Self> {
        match self.primitive_with_active(PrimitiveHint::Number, &mut HashSet::new())? {
            PrimitiveValue::Value(value) => Ok(value),
            // Function source cannot form a numeric literal. Other consumers require the source text.
            PrimitiveValue::FunctionSource => Ok(Self::Number(f64::NAN)),
        }
    }

    fn primitive_with_active(
        &self,
        hint: PrimitiveHint,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<PrimitiveValue> {
        let Some(fields) = self.property_source() else {
            return Ok(PrimitiveValue::Value(self.clone()));
        };
        let methods = if hint == PrimitiveHint::String
            || (hint == PrimitiveHint::Default && matches!(self, Self::Date(_)))
        {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in methods {
            // Read the next method only after the previous call and its side effects finish.
            let result = match fields.get_with_receiver(name, self)? {
                Some(Self::Function(function)) => {
                    PrimitiveValue::Value(function.call_with(self, &[])?)
                }
                None if name == "toString" => self.builtin_to_string(active)?,
                None => PrimitiveValue::Value(match self {
                    Self::Date(date) => Self::Number(date.milliseconds()),
                    value => value.clone(),
                }),
                Some(_) => continue,
            };
            if !matches!(
                &result,
                PrimitiveValue::Value(
                    Self::Object(_) | Self::Array(_) | Self::Date(_) | Self::Function(_)
                )
            ) {
                return Ok(result);
            }
        }
        Err(AuthError::type_error("No default value"))
    }

    fn builtin_to_string(&self, active: &mut HashSet<ArrayIdentity>) -> AuthResult<PrimitiveValue> {
        Ok(PrimitiveValue::Value(match self {
            Self::Function(_) => return Ok(PrimitiveValue::FunctionSource),
            Self::Date(date) => match date.to_datetime()? {
                Some(value) => value
                    .with_timezone(&chrono::Local)
                    .format("%a %b %d %Y %H:%M:%S GMT%z (%Z)")
                    .to_string()
                    .into(),
                None => "Invalid Date".into(),
            },
            Self::Array(values) => match values.properties().get_with_receiver("join", self)? {
                Some(Self::Function(join)) => join.call_with(self, &[])?,
                Some(_) => "[object Array]".into(),
                None => Self::array_join(values, &Self::Undefined, active)?.into(),
            },
            _ => "[object Object]".into(),
        }))
    }

    /// Apply JavaScript string conversion while retaining unpaired UTF-16 code units.
    pub fn display_utf16(&self) -> AuthResult<crate::Utf16String> {
        self.display_utf16_with_active(&mut HashSet::new())
    }

    fn display_utf16_with_active(
        &self,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<crate::Utf16String> {
        Ok(match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::String(value) => value.as_str().into(),
            Self::Utf16String(value) => value.clone(),
            Self::Bool(value) => value.to_string().into(),
            Self::Number(value) => crate::schema_value::number_string(*value).into(),
            Self::Object(_) | Self::Array(_) | Self::Date(_) | Self::Function(_) => self
                .primitive_with_active(PrimitiveHint::String, active)?
                .into_value()?
                .display_utf16_with_active(active)?,
        })
    }

    fn array_join(
        values: &FieldArray,
        separator: &Self,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<crate::Utf16String> {
        let iterator = values.iter()?;
        let separator = if separator.is_undefined() {
            ",".into()
        } else {
            separator.display_utf16_with_active(active)?
        };
        let identity = values.identity();
        if !active.insert(identity) {
            return Ok("".into());
        }
        let result = (|| {
            let mut units = Vec::new();
            for (index, value) in iterator.enumerate() {
                let value = value?;
                if index != 0 {
                    units.extend_from_slice(separator.as_utf16());
                }
                if !value.is_undefined() && !value.is_null() {
                    units.extend_from_slice(value.display_utf16_with_active(active)?.as_utf16());
                }
            }
            Ok(crate::Utf16String::from_units(units))
        })();
        let _ = active.remove(&identity);
        result
    }
}

#[cfg(test)]
#[path = "primitive_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "collection_method_tests.rs"]
mod collection_tests;
