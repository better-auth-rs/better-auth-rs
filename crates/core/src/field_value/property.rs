//! Native property operations retain receiver identity until an explicit projection boundary.

use super::{
    FieldMap, FieldObject, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    FieldValue, string_fields,
};
use crate::{AuthError, AuthResult};

#[cfg(test)]
#[path = "property_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "coercion_properties_tests.rs"]
mod coercion_tests;

impl FieldValue {
    pub(super) fn property_source(&self) -> Option<&FieldObject> {
        match self {
            Self::Object(object) => Some(object),
            Self::Array(array) => Some(array.properties()),
            Self::Date(date) => Some(date.properties()),
            Self::Function(function) => Some(function.properties()),
            _ => None,
        }
    }

    /// Read one property without converting its value or invoking unrelated getters.
    pub fn model_property(&self, name: &str) -> AuthResult<Self> {
        self.get_property_with_receiver(name, self)
    }

    /// Read a native property with an explicit receiver without redirecting the target lookup.
    pub fn get_property_with_receiver(&self, name: &str, receiver: &Self) -> AuthResult<Self> {
        if let Some(kind) = self.nullish_name() {
            return Err(AuthError::type_error(format!(
                "Cannot read properties of {kind} (reading '{name}')"
            )));
        }
        if let Self::Array(array) = self {
            if name == "length" {
                return Ok(array.len()?.into());
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return Ok(array
                    .get_with_receiver(index as usize, receiver)?
                    .unwrap_or_default());
            }
        }
        if let Some(units) = crate::query::field_string_units(self) {
            return Ok(if name == "length" {
                units.len().into()
            } else {
                crate::utils::json::array_index(name)
                    .and_then(|index| units.get(index as usize))
                    .map(|unit| crate::Utf16String::from_units(vec![*unit]).into())
                    .unwrap_or_default()
            });
        }
        match self.property_source() {
            Some(source) => Ok(source
                .get_with_receiver(name, receiver)?
                .unwrap_or_default()),
            None => Ok(Self::Undefined),
        }
    }

    /// Retain a JavaScript source expression when a nullish receiver produces an engine error.
    pub fn model_property_at(&self, name: &str, expression: &str) -> AuthResult<Self> {
        if let Some(kind) = self.nullish_name() {
            return Err(AuthError::type_error(format!(
                "{kind} is not an object (evaluating '{expression}')"
            )));
        }
        self.model_property(name)
    }

    fn nullish_name(&self) -> Option<&'static str> {
        match self {
            Self::Null => Some("null"),
            Self::Undefined => Some("undefined"),
            _ => None,
        }
    }

    /// Assign one property in strict mode without reading its previous value.
    /// Cloned handles observe the same mutation; a source setter retains its original error.
    pub fn set_model_property(&self, name: &str, value: Self) -> AuthResult<()> {
        if self.set_property(name, value)? {
            Ok(())
        } else {
            Err(AuthError::type_error(
                "Attempted to assign to readonly property.",
            ))
        }
    }

    /// Assign a native property without converting a rejected write into an exception.
    pub fn set_property(&self, name: &str, value: Self) -> AuthResult<bool> {
        self.set_property_with_receiver(name, value, self)
    }

    /// Assign through the target while preserving an explicit native receiver.
    pub fn set_property_with_receiver(
        &self,
        name: &str,
        value: Self,
        receiver: &Self,
    ) -> AuthResult<bool> {
        if let Self::Array(array) = self {
            if name == "length" {
                if let Some(result) = array.length_descriptor()?.assign(receiver, value.clone())? {
                    return Ok(result);
                }
                return receiver.write_data_property(name, value);
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return array.assign_index(index as usize, value, receiver);
            }
        }
        match self.property_source() {
            Some(source) => source.set_with_receiver(name, value, receiver),
            None => Ok(false),
        }
    }

    pub(crate) fn write_data_property(&self, name: &str, value: Self) -> AuthResult<bool> {
        if self.property_source().is_none() {
            return Ok(false);
        }
        match self.own_property_descriptor(name)? {
            Some(FieldPropertyDescriptor {
                property: FieldProperty::Data { writable: true, .. },
                ..
            }) => self.define_own_property(name, FieldPropertyDefinition::value(value)),
            Some(_) => Ok(false),
            None => self.define_own_property(name, FieldPropertyDescriptor::data(value).into()),
        }
    }

    /// Define an own property and retain the native boolean rejection result.
    pub fn define_own_property(
        &self,
        name: &str,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        if let Self::Array(array) = self {
            if name == "length" {
                return array.define_length(definition);
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return array.define_index(index as usize, definition);
            }
        }
        match self.property_source() {
            Some(source) => source.define_own_property(name, definition),
            None => Err(AuthError::type_error(
                "Object.defineProperty called on non-object",
            )),
        }
    }

    /// Define an own property in strict mode.
    pub fn define_model_property(
        &self,
        name: &str,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<()> {
        if self.define_own_property(name, definition)? {
            Ok(())
        } else {
            Err(AuthError::type_error(format!(
                "Cannot redefine property: {name}"
            )))
        }
    }

    /// Delete an own property without evaluating its getter.
    pub fn delete_property(&self, name: &str) -> AuthResult<bool> {
        if let Some(kind) = self.nullish_name() {
            return Err(AuthError::type_error(format!(
                "Cannot convert {kind} to object"
            )));
        }
        if let Self::Array(array) = self {
            if name == "length" {
                return Ok(false);
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return array.delete_index(index as usize);
            }
        }
        if crate::query::field_string_units(self).is_some() {
            return Ok(self.own_property_descriptor(name)?.is_none());
        }
        match self.property_source() {
            Some(source) => source.delete(name),
            None => Ok(true),
        }
    }

    /// Delete an own property in strict mode.
    pub fn delete_model_property(&self, name: &str) -> AuthResult<()> {
        if self.delete_property(name)? {
            Ok(())
        } else {
            Err(AuthError::type_error(format!(
                "Cannot delete property '{name}'"
            )))
        }
    }

    /// Check property presence without reading its getter. Primitive receivers reject JavaScript `in`.
    /// Object sources own prototype lookup; built-in prototype and symbol properties are not synthesized.
    pub fn has_property(&self, name: &str) -> AuthResult<bool> {
        if let Self::Array(array) = self {
            if name == "length" {
                return Ok(true);
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return Ok(array.own_indices()?.contains(&(index as usize)));
            }
        }
        match self.property_source() {
            Some(source) => source.has_property(name),
            None => Err(AuthError::type_error(format!(
                "Cannot use 'in' operator to search for '{name}' in {}",
                String::from_utf16_lossy(self.display_utf16()?.as_utf16()),
            ))),
        }
    }

    /// Capture all own string keys, including non-enumerable array and string length.
    pub fn own_property_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = match self {
            Self::Array(array) => array
                .own_indices()?
                .into_iter()
                .map(|index| index.to_string())
                .collect(),
            _ => Vec::new(),
        };
        if let Some(units) = crate::query::field_string_units(self) {
            keys.extend((0..units.len()).map(|index| index.to_string()));
            keys.push("length".into());
        } else if let Self::Array(array) = self {
            keys.push("length".into());
            keys.extend(array.named_property_keys()?);
        } else if let Some(source) = self.property_source() {
            keys.extend(source.own_keys()?);
        }
        Ok(keys)
    }

    /// Inspect a complete own descriptor without evaluating an accessor.
    pub fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<FieldPropertyDescriptor>> {
        if let Self::Array(array) = self {
            if name == "length" {
                return array.length_descriptor().map(Some);
            }
            if let Some(index) = crate::utils::json::array_index(name) {
                return array.own_property_descriptor(index as usize);
            }
        }
        if let Some(units) = crate::query::field_string_units(self) {
            let value = if name == "length" {
                Some(units.len().into())
            } else {
                crate::utils::json::array_index(name)
                    .and_then(|index| units.get(index as usize))
                    .map(|unit| crate::Utf16String::from_units(vec![*unit]).into())
            };
            return Ok(value.map(|value| FieldPropertyDescriptor {
                enumerable: name != "length",
                configurable: false,
                property: FieldProperty::Data {
                    value,
                    writable: false,
                },
            }));
        }
        match self.property_source() {
            Some(source) => source.own_property_descriptor(name),
            None => Ok(None),
        }
    }

    /// Copy own enumerable string properties while retaining native child identities.
    pub fn enumerable_fields(&self) -> AuthResult<FieldMap> {
        self.enumerable_fields_except(&[])
    }

    /// Copy object-rest properties without reading excluded or non-enumerable getters.
    pub fn enumerable_fields_except(&self, excluded: &[&str]) -> AuthResult<FieldMap> {
        let mut fields = match self {
            Self::String(value) => string_fields(value.encode_utf16()),
            Self::Utf16String(value) => string_fields(value.as_utf16().iter().copied()),
            _ => FieldMap::new(),
        };
        fields.retain(|name, _| !excluded.contains(&name.as_str()));
        for name in self.own_property_keys()? {
            if !excluded.contains(&name.as_str())
                && self
                    .own_property_descriptor(&name)?
                    .is_some_and(|descriptor| descriptor.enumerable)
            {
                let _ = fields.insert(name.clone(), self.model_property(&name)?);
            }
        }
        Ok(fields)
    }
}
