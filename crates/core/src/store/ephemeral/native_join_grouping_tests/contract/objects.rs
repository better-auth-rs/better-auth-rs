//! Fixture objects preserve JavaScript non-enumerable methods and error properties.

use super::*;
use crate::{FieldObject, field_value::FieldObjectSource};

struct Source {
    enumerable: FieldMap,
    hidden: FieldMap,
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys: Vec<_> = self
            .enumerable
            .keys()
            .chain(self.hidden.keys())
            .cloned()
            .collect();
        keys.sort_by_key(|name| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        Ok(keys)
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        let enumerable = self.enumerable.contains_key(name);
        Ok(self
            .enumerable
            .get(name)
            .or_else(|| self.hidden.get(name))
            .map(|value| crate::field_value::FieldPropertyDescriptor {
                enumerable,
                ..crate::field_value::FieldPropertyDescriptor::data(value.clone())
            }))
    }

    fn get_with_receiver(&self, name: &str, _receiver: &Value) -> AuthResult<Option<Value>> {
        Ok(self
            .enumerable
            .get(name)
            .or_else(|| self.hidden.get(name))
            .cloned())
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.enumerable.contains_key(name) || self.hidden.contains_key(name))
    }

    fn set_with_receiver(&self, _: String, _: Value, _: &Value) -> AuthResult<bool> {
        Err(AuthError::type_error("The fixture object is read-only"))
    }

    fn define_own_property(
        &self,
        _: String,
        _: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::type_error("The fixture object is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::type_error("The fixture object is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Ok(self.enumerable.clone())
    }

    fn identity(&self) -> usize {
        self as *const Self as usize
    }
}

pub(super) fn object(enumerable: FieldMap, hidden: FieldMap) -> Value {
    FieldObject::from_source(Arc::new(Source { enumerable, hidden })).into()
}
