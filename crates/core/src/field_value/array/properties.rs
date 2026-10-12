//! Array property operations preserve the exotic length rules and partial shrink failures.

use super::*;
use crate::field_value::FieldPropertyUpdate;

fn empty_values() -> ArrayValues {
    ArrayValues {
        length: 0,
        entries: BTreeMap::new(),
        length_writable: true,
    }
}

fn length_descriptor(values: &ArrayValues) -> FieldPropertyDescriptor {
    FieldPropertyDescriptor {
        enumerable: false,
        configurable: false,
        property: FieldProperty::Data {
            value: values.length.into(),
            writable: values.length_writable,
        },
    }
}

impl FieldArray {
    pub(crate) fn own_property_descriptor(
        &self,
        index: usize,
    ) -> AuthResult<Option<FieldPropertyDescriptor>> {
        match &self.storage {
            ArrayStorage::Owned(values) => Ok(values
                .lock()
                .as_ref()
                .and_then(|values| values.entries.get(&index))
                .cloned()),
            ArrayStorage::Live(source) => source.own_property_descriptor(index),
        }
    }

    pub(crate) fn length_descriptor(&self) -> AuthResult<FieldPropertyDescriptor> {
        match &self.storage {
            ArrayStorage::Owned(values) => Ok(values
                .lock()
                .as_ref()
                .map_or_else(|| length_descriptor(&empty_values()), length_descriptor)),
            ArrayStorage::Live(source) => source.length_descriptor(),
        }
    }

    pub(crate) fn set(&self, index: usize, value: FieldValue) -> AuthResult<()> {
        FieldValue::Array(self.clone()).set_model_property(&index.to_string(), value)
    }

    pub(crate) fn set_length(&self, length: usize) -> AuthResult<()> {
        FieldValue::Array(self.clone()).set_model_property("length", length.into())
    }

    pub(crate) fn assign_index(
        &self,
        index: usize,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        if let ArrayStorage::Live(source) = &self.storage {
            return source.set(index, value, receiver);
        }
        if let Some(descriptor) = self.own_property_descriptor(index)?
            && let Some(result) = descriptor.assign(receiver, value.clone())?
        {
            return Ok(result);
        }
        receiver.write_data_property(&index.to_string(), value)
    }

    pub(crate) fn define_index(
        &self,
        index: usize,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        match &self.storage {
            ArrayStorage::Owned(values) => {
                let mut guard = values.lock();
                let values = guard.get_or_insert_with(empty_values);
                if index >= values.length && !values.length_writable {
                    return Ok(false);
                }
                let Some(descriptor) = definition.apply(values.entries.get(&index)) else {
                    return Ok(false);
                };
                let previous = values.entries.insert(index, descriptor);
                values.length = values.length.max(index + 1);
                drop(guard);
                drop(previous);
                Ok(true)
            }
            ArrayStorage::Live(source) => source.define_index(index, definition),
        }
    }

    pub(crate) fn define_length(
        &self,
        mut definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        if let ArrayStorage::Live(source) = &self.storage {
            return source.define_length(definition);
        }
        if let FieldPropertyUpdate::Data {
            value: Some(value), ..
        } = &mut definition.property
        {
            // ArraySetLength evaluates ToUint32 and ToNumber separately before inspecting the old length.
            let first = crate::query::field_number(value)?;
            let length = if first.is_finite() {
                first.trunc().rem_euclid(4_294_967_296.0)
            } else {
                0.0
            };
            if crate::query::field_number(value)? != length {
                return Err(AuthError::RangeError("Invalid array length".into()));
            }
            *value = length.into();
        }
        match &self.storage {
            ArrayStorage::Owned(values) => {
                let mut guard = values.lock();
                let values = guard.get_or_insert_with(empty_values);
                let old = length_descriptor(values);
                let Some(new) = definition.apply(Some(&old)) else {
                    return Ok(false);
                };
                let FieldProperty::Data {
                    value: FieldValue::Number(length),
                    writable,
                } = new.property
                else {
                    return Ok(false);
                };
                let length = length as usize;
                if length >= values.length {
                    values.length = length;
                    values.length_writable = writable;
                    return Ok(true);
                }
                if !values.length_writable {
                    return Ok(false);
                }
                values.length = length;
                let indices = values
                    .entries
                    .range(length..)
                    .map(|(index, _)| *index)
                    .rev()
                    .collect::<Vec<_>>();
                let mut removed = Vec::new();
                let mut success = true;
                for index in indices {
                    if values
                        .entries
                        .get(&index)
                        .is_some_and(|descriptor| !descriptor.configurable)
                    {
                        values.length = index + 1;
                        success = false;
                        break;
                    }
                    removed.extend(values.entries.remove(&index));
                }
                values.length_writable = writable;
                drop(guard);
                drop(removed);
                Ok(success)
            }
            ArrayStorage::Live(source) => source.define_length(definition),
        }
    }

    pub(crate) fn delete_index(&self, index: usize) -> AuthResult<bool> {
        match &self.storage {
            ArrayStorage::Owned(values) => {
                let mut guard = values.lock();
                let Some(values) = guard.as_mut() else {
                    return Ok(true);
                };
                if values
                    .entries
                    .get(&index)
                    .is_some_and(|descriptor| !descriptor.configurable)
                {
                    return Ok(false);
                }
                let previous = values.entries.remove(&index);
                drop(guard);
                drop(previous);
                Ok(true)
            }
            ArrayStorage::Live(source) => source.delete(index),
        }
    }

    pub(crate) fn delete(&self, index: usize) -> AuthResult<()> {
        FieldValue::Array(self.clone()).delete_model_property(&index.to_string())
    }
}
