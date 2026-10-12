use super::Headers;
use crate::{
    AuthError, AuthResult, FieldMap, FieldObject, FieldValue,
    field_value::{FieldObjectSource, FieldPropertyDefinition, FieldPropertyDescriptor},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub(super) fn value(headers: Arc<Mutex<Headers>>) -> FieldValue {
    FieldObject::from_source(Arc::new(NativeHeaders {
        headers,
        properties: FieldMap::new().into(),
    }))
    .into()
}

pub(super) fn snapshot(value: &FieldValue) -> AuthResult<Option<Headers>> {
    value
        .as_object()
        .and_then(|object| object.source::<NativeHeaders>())
        .map(|source| Ok(lock(&source.headers)?.clone()))
        .transpose()
}

pub(super) fn lock(headers: &Mutex<Headers>) -> AuthResult<MutexGuard<'_, Headers>> {
    headers
        .lock()
        .map_err(|_| AuthError::internal("Session response headers lock poisoned"))
}

struct NativeHeaders {
    headers: Arc<Mutex<Headers>>,
    // Header entries are internal slots; expando properties do not enter HeadersInit iteration.
    properties: FieldObject,
}

impl FieldObjectSource for NativeHeaders {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.properties.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.properties.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.properties.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.properties.set_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.properties.define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.properties.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.properties.snapshot_fields()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl From<Headers> for FieldValue {
    fn from(headers: Headers) -> Self {
        value(Arc::new(Mutex::new(headers)))
    }
}
