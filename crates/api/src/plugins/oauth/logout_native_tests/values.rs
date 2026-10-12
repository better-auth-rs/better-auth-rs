use super::*;
use better_auth_core::FieldFunction;
use better_auth_core::field_value::{
    FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
};
use std::sync::{
    Weak,
    atomic::{AtomicUsize, Ordering},
};

struct Method {
    name: &'static str,
    label: &'static str,
    observer: Observer,
    fields: FieldMap,
    getter_failure: Option<FieldValue>,
    invoke: FieldFunction,
}

struct Properties {
    fields: FieldMap,
    name: &'static str,
    getter: FieldFunction,
}

impl Method {
    fn bind(self, milliseconds: Option<f64>) -> Arc<FieldValue> {
        Arc::new_cyclic(|receiver: &Weak<FieldValue>| {
            let expected = receiver.clone();
            let observer = self.observer.clone();
            let phase = format!("call:{}:{}", self.name, self.label);
            let invoke = self.invoke.clone();
            let callback = FieldFunction::contextual(move |receiver, arguments| {
                let expected = expected
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Native method receiver is absent"))?;
                lock(&observer)?.call(&phase, receiver, &expected, arguments)?;
                invoke.call_with(receiver, arguments)
            });
            let expected = receiver.clone();
            let observer = self.observer.clone();
            let name = self.name;
            let label = self.label;
            let failure = self.getter_failure;
            let getter = FieldFunction::contextual(move |receiver, _| {
                let expected = expected
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Native getter receiver is absent"))?;
                lock(&observer)?.record(
                    &format!("get:{name}:{label}"),
                    [(
                        "sameReceiver".into(),
                        receiver.strict_equals(&expected).into(),
                    )],
                );
                if name == "getTime" {
                    assert_ne!(label, "excluded");
                }
                if let Some(error) = &failure {
                    return Err(AuthError::from_thrown(error.clone()));
                }
                Ok(callback.clone().into())
            });
            let source = FieldObject::from_source(Arc::new(Properties {
                fields: self.fields,
                name,
                getter,
            }));
            match milliseconds {
                Some(milliseconds) => {
                    FieldDate::from_milliseconds_with_properties(milliseconds, source).into()
                }
                None => source.into(),
            }
        })
    }
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = FieldObject::from(self.fields.clone()).own_keys()?;
        keys.push(self.name.into());
        Ok(keys)
    }
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(if name == self.name {
            Some(FieldPropertyDescriptor {
                enumerable: false,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(self.getter.clone()),
                    set: None,
                },
            })
        } else {
            self.fields
                .get(name)
                .cloned()
                .map(FieldPropertyDescriptor::data)
        })
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == self.name {
            self.getter.call_with(receiver, &[]).map(Some)
        } else {
            Ok(self.fields.get(name).cloned())
        }
    }
    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Logout must not mutate projected timestamp properties",
        ))
    }
    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Logout must not mutate projected timestamp properties",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Logout must not delete projected timestamp properties",
        ))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Logout timestamp consumption must preserve native property access",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

pub(super) fn projected(
    name: &str,
    observer: &Observer,
    original: &FieldValue,
) -> AuthResult<Vec<Arc<FieldValue>>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let conversion_failure: FieldValue = FieldMap::from([
        ("conversionFailure".into(), name.into()),
        ("original".into(), original.clone()),
    ])
    .into();
    ["first", "second", "excluded"]
        .into_iter()
        .zip([0.0, 1.0, 2.0])
        .map(|(label, index)| {
            if name == "builtin-dates" {
                return Ok(Arc::new(date(NOW + index)));
            }
            let number_error = if label == "first" && name == "value-of-error" {
                Some(original.clone())
            } else if label == "first" && name == "later-method-precedes-conversion-error" {
                Some(conversion_failure.clone())
            } else {
                None
            };
            let method_calls = calls.clone();
            let observed = observer.clone();
            let number_result = Method {
                name: "valueOf",
                label,
                observer: observer.clone(),
                fields: FieldMap::new(),
                getter_failure: None,
                invoke: FieldFunction::contextual(move |_, _| {
                    let count = method_calls.load(Ordering::SeqCst);
                    lock(&observed)?.record(
                        &format!("number:{label}"),
                        [("methodCalls".into(), count.into())],
                    );
                    if let Some(error) = &number_error {
                        return Err(AuthError::from_thrown(error.clone()));
                    }
                    Ok(if label == "first" {
                        if count < 2 { 100 } else { 0 }
                    } else {
                        10
                    }
                    .into())
                }),
            }
            .bind(None);
            let method_error = ((label == "first" && name == "get-time-method-error")
                || (label == "second" && name == "later-method-precedes-conversion-error"))
                .then(|| original.clone());
            let getter_failure =
                (label == "first" && name == "get-time-getter-error").then(|| original.clone());
            let deferred = [
                "deferred-number-conversion",
                "value-of-error",
                "later-method-precedes-conversion-error",
            ]
            .contains(&name);
            let nan = name == "nan-stable-order";
            let infinity = name == "infinity-stable-order";
            let method_calls = calls.clone();
            Ok(Method {
                name: "getTime",
                label,
                observer: observer.clone(),
                getter_failure,
                fields: if name == "date-own-get-time" {
                    FieldMap::new()
                } else {
                    FieldMap::from([("label".into(), label.into())])
                },
                invoke: FieldFunction::contextual(move |_, _| {
                    let _ = method_calls.fetch_add(1, Ordering::SeqCst);
                    if let Some(error) = &method_error {
                        return Err(AuthError::from_thrown(error.clone()));
                    }
                    Ok(if deferred {
                        number_result.as_ref().clone()
                    } else if nan {
                        FieldValue::Undefined
                    } else if infinity {
                        f64::INFINITY.into()
                    } else if label == "first" {
                        "5".into()
                    } else {
                        "9".into()
                    })
                }),
            }
            .bind((name == "date-own-get-time").then_some(NOW + index)))
        })
        .collect()
}
