#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native JWT test sources assert receiver identity and retain exact callback failures."
)]

use super::*;
use better_auth_core::{
    FieldFunction, FieldObject,
    field_value::{
        FieldObjectSource, FieldPropertyDefinition, FieldPropertyDescriptor, FieldPropertyUpdate,
    },
    observability::{LogArgument, LogLevel, LogSink},
};
use std::sync::{Arc, Mutex, Weak};

#[derive(Default)]
pub(super) struct Trace {
    pub(super) events: Mutex<Vec<String>>,
    pub(super) errors: Mutex<Vec<FieldValue>>,
    pub(super) logger_failure: Option<FieldValue>,
}

impl Trace {
    pub(super) fn record(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }
}

impl LogSink for Trace {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        assert_eq!(level, LogLevel::Debug);
        self.record(format!("log:{message}"));
        let [LogArgument::Error(error)] = arguments else {
            return Err(AuthError::internal("JWT failure must retain its error"));
        };
        let error = error.downcast_ref::<AuthError>().unwrap();
        self.errors.lock().unwrap().push(
            error
                .raw_value()
                .ok_or_else(|| AuthError::internal("JWT must log the original native error"))?
                .clone(),
        );
        match &self.logger_failure {
            Some(error) => Err(AuthError::from_thrown(error.clone())),
            None => Ok(()),
        }
    }
}

pub(super) struct ObservedFields {
    owner: Weak<Self>,
    pub(super) fields: FieldObject,
    trace: Arc<Trace>,
    failure: Option<(&'static str, FieldValue)>,
}

impl ObservedFields {
    pub(super) fn new(
        fields: FieldMap,
        trace: Arc<Trace>,
        failure: Option<(&'static str, FieldValue)>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|owner| Self {
            owner: owner.clone(),
            fields: fields.into(),
            trace,
            failure,
        })
    }

    pub(super) fn value(self: &Arc<Self>) -> FieldValue {
        FieldObject::from_source(self.clone()).into()
    }

    pub(super) fn getter(&self, name: &str, callback: FieldFunction) -> AuthResult<()> {
        if self.fields.define_own_property(
            name,
            FieldPropertyDefinition {
                enumerable: Some(true),
                configurable: Some(true),
                property: FieldPropertyUpdate::Accessor {
                    get: Some(Some(callback)),
                    set: Some(None),
                },
            },
        )? {
            Ok(())
        } else {
            Err(AuthError::internal(
                "The JWT probe rejected its accessor definition",
            ))
        }
    }
}

impl FieldObjectSource for ObservedFields {
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
        assert!(receiver.strict_equals(&self.owner.upgrade().unwrap().value()));
        self.trace.record(format!("get:{name}"));
        if let Some((property, error)) = &self.failure
            && name == *property
        {
            return Err(AuthError::from_thrown(error.clone()));
        }
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
        Err(AuthError::internal("JWT consumers must not snapshot a key"))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}
