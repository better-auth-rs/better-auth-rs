use super::*;
use better_auth_core::{
    FieldFunction, FieldObject,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};

#[derive(Clone, Default)]
pub(super) struct Log(Arc<Mutex<(String, Vec<Value>)>>);

impl Log {
    pub fn phase(&self, phase: &str) -> String {
        std::mem::replace(&mut self.0.lock().unwrap().0, phase.into())
    }

    pub fn event(&self, event: Value) {
        let mut log = self.0.lock().unwrap();
        let mut fields = serde_json::Map::new();
        let _ = fields.insert("phase".into(), log.0.clone().into());
        fields.extend(event.as_object().unwrap().clone());
        log.1.push(Value::Object(fields));
    }

    pub fn take(&self) -> Vec<Value> {
        std::mem::take(&mut self.0.lock().unwrap().1)
    }
}

#[derive(Clone, Copy)]
pub(super) enum Getter {
    Throw,
    Tail,
    ThrowingTail,
}

pub(super) struct Source {
    fields: FieldObject,
    label: Option<&'static str>,
    log: Log,
}

impl Source {
    pub fn value(
        fields: FieldMap,
        label: Option<&'static str>,
        log: Log,
        failure: FieldValue,
        hidden: &[&str],
        getters: &[(&str, Getter)],
    ) -> FieldValue {
        let fields = fields
            .into_iter()
            .map(|(name, value)| {
                let property =
                    if let Some((_, getter)) = getters.iter().find(|(key, _)| *key == name) {
                        let getter = *getter;
                        let log = log.clone();
                        let failure = failure.clone();
                        let key = name.clone();
                        FieldProperty::Accessor {
                            get: Some(FieldFunction::contextual(move |_, _| {
                                if let Some(label) = label {
                                    let kind = if matches!(getter, Getter::Throw) {
                                        "getter-throw"
                                    } else {
                                        "getter"
                                    };
                                    log.event(json!({"kind": kind, "object": label, "key": key}));
                                }
                                match getter {
                                    Getter::Throw | Getter::ThrowingTail => {
                                        Err(AuthError::from_thrown(failure.clone()))
                                    }
                                    Getter::Tail => Ok(object([("kept", true.into())])),
                                }
                            })),
                            set: None,
                        }
                    } else {
                        FieldProperty::Data {
                            value,
                            writable: !hidden.contains(&name.as_str()),
                        }
                    };
                let configurable = !hidden.contains(&name.as_str())
                    && !getters.iter().any(|(key, getter)| {
                        *key == name && matches!(getter, Getter::Tail | Getter::ThrowingTail)
                    });
                let descriptor = FieldPropertyDescriptor {
                    enumerable: !hidden.contains(&name.as_str()),
                    configurable,
                    property,
                };
                (name, descriptor)
            })
            .collect::<indexmap::IndexMap<_, _>>()
            .into();
        FieldValue::Object(FieldObject::from_source(Arc::new(Self {
            fields,
            label,
            log,
        })))
    }

    fn event(&self, kind: &str, key: &str) {
        if let Some(label) = self.label {
            self.log
                .event(json!({"kind": kind, "object": label, "key": key}));
        }
    }
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        let keys = self.fields.own_keys()?;
        if let Some(label) = self.label {
            self.log
                .event(json!({"kind": "own-keys", "object": label, "keys": keys}));
        }
        Ok(keys)
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.event("descriptor", name);
        self.fields.own_property_descriptor(name)
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        self.fields.has_property(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if !self.fields.has_property(name)? {
            return Ok(None);
        }
        self.event("get", name);
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
        let mut fields = FieldMap::new();
        for name in self.own_keys()? {
            if self
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
                && let Some(value) = self.get_with_receiver(&name, &FieldValue::Undefined)?
            {
                let _ = fields.insert(name, value);
            }
        }
        Ok(fields)
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
