#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;
use crate::field_value::{
    FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
};
use std::{any::Any, sync::Weak};

pub(super) struct Properties {
    fields: FieldObject,
    receiver: Arc<Mutex<Weak<FieldValue>>>,
    observer: Observer,
}

impl Properties {
    pub(super) fn new(observer: &Observer) -> Arc<Self> {
        Arc::new(Self {
            fields: FieldMap::new().into(),
            receiver: Arc::default(),
            observer: observer.clone(),
        })
    }

    pub(super) fn bind(&self, value: FieldValue) -> Arc<FieldValue> {
        let value = Arc::new(value);
        *self.receiver.lock() = Arc::downgrade(&value);
        value
    }

    pub(super) fn getter(&self, name: &str, callback: FieldFunction, enumerable: bool) {
        let expected = self.receiver.clone();
        let observer = self.observer.clone();
        let event_name = name.to_owned();
        let getter = FieldFunction::contextual(move |receiver, _| {
            let expected = expected
                .lock()
                .upgrade()
                .ok_or_else(|| AuthError::internal("Native getter receiver is absent"))?;
            observer.lock().record(
                &format!("get:{event_name}"),
                [(
                    "sameReceiver".into(),
                    receiver.strict_equals(&expected).into(),
                )],
            );
            callback.call_with(receiver, &[])
        });
        self.fields
            .define_own_property(
                name,
                FieldPropertyDescriptor {
                    enumerable,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(getter),
                        set: None,
                    },
                }
                .into(),
            )
            .unwrap();
    }
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }
    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.fields.get_with_receiver(name, receiver)
    }
    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }
    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native revival must read properties individually",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}
