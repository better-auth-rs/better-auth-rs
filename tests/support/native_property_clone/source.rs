//! Live fixture sources retain inherited Get behavior while reflection selects only own properties.

use super::*;
use crate::field_value::{FieldArraySource, FieldObjectSource};

#[derive(Clone)]
pub(super) struct Source {
    own: FieldValue,
    pub(super) inherited: FieldObject,
    identity: Arc<()>,
}

impl Source {
    pub(super) fn new(array: bool) -> Arc<Self> {
        Arc::new(Self {
            own: if array {
                FieldArray::with_length(3).into()
            } else {
                FieldMap::new().into()
            },
            inherited: FieldMap::new().into(),
            identity: Arc::new(()),
        })
    }

    pub(super) fn value(&self) -> FieldValue {
        let source = Arc::new(self.clone());
        match &self.own {
            FieldValue::Array(_) => FieldArray::from_source(source).into(),
            _ => FieldObject::from_source(source).into(),
        }
    }

    fn read(&self, name: &str, receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        if self.own.own_property_descriptor(name)?.is_some() {
            self.own
                .get_property_with_receiver(name, receiver)
                .map(Some)
        } else {
            self.inherited.get_with_receiver(name, receiver)
        }
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.identity) as usize
    }

    fn array(&self) -> &FieldArray {
        self.own.as_array().unwrap()
    }
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.own.own_property_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.own.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.read(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.own.set_property_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.own.define_own_property(&name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.own.delete_property(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.value().enumerable_fields()
    }

    fn identity(&self) -> usize {
        self.identity()
    }
}

impl FieldArraySource for Source {
    fn len(&self) -> AuthResult<usize> {
        self.array().len()
    }

    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        self.array().own_indices()
    }

    fn get(&self, index: usize, receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        self.read(&index.to_string(), receiver)
    }

    fn identity(&self) -> usize {
        self.identity()
    }

    fn properties(&self) -> &FieldObject {
        self.array().properties()
    }

    fn own_property_descriptor(&self, index: usize) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.array().own_property_descriptor(index)
    }

    fn length_descriptor(&self) -> AuthResult<FieldPropertyDescriptor> {
        self.array().length_descriptor()
    }

    fn set(&self, index: usize, value: FieldValue, receiver: &FieldValue) -> AuthResult<bool> {
        self.array().assign_index(index, value, receiver)
    }

    fn define_index(&self, index: usize, definition: FieldPropertyDefinition) -> AuthResult<bool> {
        self.array().define_index(index, definition)
    }

    fn define_length(&self, definition: FieldPropertyDefinition) -> AuthResult<bool> {
        self.array().define_length(definition)
    }

    fn delete(&self, index: usize) -> AuthResult<bool> {
        self.array().delete_index(index)
    }
}
