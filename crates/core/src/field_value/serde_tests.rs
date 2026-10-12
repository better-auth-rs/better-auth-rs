#![expect(
    clippy::panic_in_result_fn,
    reason = "Contracts assert getter scheduling and original error allocation; setup failures propagate."
)]

use super::*;
use crate::{
    AuthError, AuthResult,
    endpoint_input::ValidatedBody,
    field_value::{FieldObject, FieldObjectSource},
};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicUsize, Ordering},
};

type Getter = dyn Fn(&str) -> AuthResult<()> + Send + Sync;

struct Source {
    fields: Mutex<FieldMap>,
    getter: Box<Getter>,
}

impl Source {
    fn fields(&self) -> AuthResult<MutexGuard<'_, FieldMap>> {
        self.fields
            .lock()
            .map_err(|_| AuthError::internal("JSON source lock poisoned"))
    }
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        FieldObject::from(self.fields()?.clone()).own_keys()
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<super::super::FieldPropertyDescriptor>> {
        Ok(self
            .fields()?
            .get(name)
            .cloned()
            .map(super::super::FieldPropertyDescriptor::data))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if !self.fields()?.contains_key(name) {
            return Ok(None);
        }
        (self.getter)(name)?;
        Ok(self.fields()?.get(name).cloned())
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        let _ = self.fields()?.insert(name, value);
        Ok(true)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        let _ = self.fields()?.remove(name);
        Ok(true)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "JSON must read one property before traversing its value",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

#[test]
fn json_reads_children_before_later_properties_and_preserves_original_errors() -> AuthResult<()> {
    for boundary in ["value", "text", "input"] {
        for fail in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let original = Arc::new(AtomicUsize::new(0));
            let outer = Arc::new(Source {
                fields: Mutex::new(FieldMap::new()),
                getter: Box::new({
                    let events = events.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("JSON event lock poisoned"))?
                            .push(format!("outer.{name}"));
                        Ok(())
                    }
                }),
            });
            let child = Arc::new(Source {
                fields: Mutex::new([("value".into(), 1.into())].into()),
                getter: Box::new({
                    let outer = Arc::downgrade(&outer);
                    let events = events.clone();
                    let original = original.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("JSON event lock poisoned"))?
                            .push(format!("child.{name}"));
                        if fail {
                            let message = "JSON getter original error".to_owned();
                            original.store(message.as_ptr() as usize, Ordering::SeqCst);
                            return Err(AuthError::internal(message));
                        }
                        let outer = outer
                            .upgrade()
                            .ok_or_else(|| AuthError::internal("Missing JSON parent"))?;
                        let mut fields = outer.fields()?;
                        let _ = fields.insert("tail".into(), "after".into());
                        let _ = fields.remove("drop");
                        let _ = fields.insert("added".into(), true.into());
                        Ok(())
                    }
                }),
            });
            *outer.fields()? = [
                (
                    "child".into(),
                    FieldValue::Object(FieldObject::from_source(child)),
                ),
                ("tail".into(), "before".into()),
                ("drop".into(), true.into()),
            ]
            .into();
            let value = FieldValue::Object(FieldObject::from_source(outer.clone()));
            let result = if boundary == "text" {
                value.stringify()
            } else {
                let projected = if boundary == "input" {
                    let mut request = crate::AuthRequest::new(crate::HttpMethod::Post, "/input");
                    request.set_endpoint_body(ValidatedBody::unvalidated_native(value));
                    request.input_body()
                } else {
                    value.json()
                };
                projected.and_then(|value| {
                    value
                        .map(|value| serde_json::to_string(&value).map_err(Into::into))
                        .transpose()
                })
            };
            if fail {
                assert!(matches!(result, Err(AuthError::Internal(message))
                    if message == "JSON getter original error" && message.as_ptr() as usize == original.load(Ordering::SeqCst)));
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("JSON event lock poisoned"))?,
                    ["outer.child", "child.value"]
                );
                assert_eq!(
                    outer.fields()?.get("tail"),
                    Some(&FieldValue::from("before"))
                );
            } else {
                assert_eq!(
                    result?,
                    Some(r#"{"child":{"value":1},"tail":"after"}"#.into())
                );
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("JSON event lock poisoned"))?,
                    ["outer.child", "child.value", "outer.tail"]
                );
                assert_eq!(
                    outer
                        .fields()?
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    ["child", "tail", "added"]
                );
                assert_eq!(
                    outer.fields()?.get("tail"),
                    Some(&FieldValue::from("after"))
                );
                assert_eq!(outer.fields()?.get("added"), Some(&FieldValue::from(true)));
            }
        }
    }
    Ok(())
}

#[test]
fn direct_maps_visit_numeric_keys_first_without_reordering_the_input() -> AuthResult<()> {
    let insertion = ["tail", "10", "2", "01", "4294967295", "1"];
    let order = ["1", "2", "10", "tail", "01", "4294967295"];
    for clone in [false, true] {
        for fail in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let original = Arc::new(AtomicUsize::new(0));
            let fields: FieldMap = insertion
                .into_iter()
                .map(|name| {
                    let events = events.clone();
                    let original = original.clone();
                    (
                        name.into(),
                        FieldValue::Object(FieldObject::from_source(Arc::new(Source {
                            fields: Mutex::new([("value".into(), name.into())].into()),
                            getter: Box::new(move |_| {
                                events
                                    .lock()
                                    .map_err(|_| AuthError::internal("Map event lock poisoned"))?
                                    .push(name);
                                if fail && name == "2" {
                                    let message = "numeric map getter original error".to_owned();
                                    original.store(message.as_ptr() as usize, Ordering::SeqCst);
                                    return Err(AuthError::internal(message));
                                }
                                Ok(())
                            }),
                        }))),
                    )
                })
                .collect();
            let result = if clone {
                crate::StructuredCloneContext::new()
                    .clone_map(&fields)
                    .and_then(|fields| {
                        assert_eq!(fields.keys().map(String::as_str).collect::<Vec<_>>(), order);
                        fields.json()
                    })
            } else {
                fields.json()
            };
            assert_eq!(
                fields.keys().map(String::as_str).collect::<Vec<_>>(),
                insertion
            );
            if fail {
                assert!(matches!(result, Err(AuthError::Internal(message))
                    if message == "numeric map getter original error" && message.as_ptr() as usize == original.load(Ordering::SeqCst)));
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("Map event lock poisoned"))?,
                    ["1", "2"]
                );
            } else {
                let result = result?;
                assert_eq!(result.keys().map(String::as_str).collect::<Vec<_>>(), order);
                assert_eq!(
                    serde_json::to_string(&result)?,
                    r#"{"1":{"value":"1"},"2":{"value":"2"},"10":{"value":"10"},"tail":{"value":"tail"},"01":{"value":"01"},"4294967295":{"value":"4294967295"}}"#
                );
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("Map event lock poisoned"))?,
                    order
                );
            }
        }
    }
    Ok(())
}

#[test]
fn json_method_lookup_and_calls_preserve_errors_and_prior_mutations() -> AuthResult<()> {
    for text in [false, true] {
        for failure in [None, Some("lookup"), Some("call")] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let original = Arc::new(AtomicUsize::new(0));
            let outer = Arc::new(Source {
                fields: Mutex::new(FieldMap::new()),
                getter: Box::new({
                    let events = events.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("Method event lock poisoned"))?
                            .push(format!("outer.{name}"));
                        Ok(())
                    }
                }),
            });
            let child = Arc::new(Source {
                fields: Mutex::new(FieldMap::from([(
                    "toJSON".into(),
                    crate::FieldFunction::contextual({
                        let outer = Arc::downgrade(&outer);
                        let events = events.clone();
                        let original = original.clone();
                        move |_, _| {
                            events
                                .lock()
                                .map_err(|_| AuthError::internal("Method event lock poisoned"))?
                                .push("call".into());
                            let outer = outer
                                .upgrade()
                                .ok_or_else(|| AuthError::internal("Missing JSON parent"))?;
                            let _ = outer.fields()?.insert("tail".into(), "call".into());
                            if failure == Some("call") {
                                let message = "Original toJSON call error".to_owned();
                                original.store(message.as_ptr() as usize, Ordering::SeqCst);
                                return Err(AuthError::internal(message));
                            }
                            Ok("converted".into())
                        }
                    })
                    .into(),
                )])),
                getter: Box::new({
                    let outer = Arc::downgrade(&outer);
                    let events = events.clone();
                    let original = original.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("Method event lock poisoned"))?
                            .push(format!("child.{name}"));
                        let outer = outer
                            .upgrade()
                            .ok_or_else(|| AuthError::internal("Missing JSON parent"))?;
                        let _ = outer.fields()?.insert("tail".into(), "lookup".into());
                        if failure == Some("lookup") {
                            let message = "Original toJSON lookup error".to_owned();
                            original.store(message.as_ptr() as usize, Ordering::SeqCst);
                            return Err(AuthError::internal(message));
                        }
                        Ok(())
                    }
                }),
            });
            *outer.fields()? = FieldMap::from([
                (
                    "child".into(),
                    FieldValue::Object(FieldObject::from_source(child)),
                ),
                ("tail".into(), "before".into()),
            ]);
            let value = FieldValue::Object(FieldObject::from_source(outer.clone()));
            let result = if text {
                value.stringify()
            } else {
                value.json().and_then(|value| {
                    value
                        .map(|value| serde_json::to_string(&value).map_err(Into::into))
                        .transpose()
                })
            };
            let expected_events = match failure {
                Some("lookup") => vec!["outer.child", "child.toJSON"],
                Some(_) => vec!["outer.child", "child.toJSON", "call"],
                None => vec!["outer.child", "child.toJSON", "call", "outer.tail"],
            };
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Method event lock poisoned"))?,
                expected_events
            );
            assert_eq!(
                outer.fields()?.get("tail"),
                Some(&FieldValue::from(if failure == Some("lookup") {
                    "lookup"
                } else {
                    "call"
                }))
            );
            if let Some(failure) = failure {
                assert!(matches!(result, Err(AuthError::Internal(message))
                    if message == format!("Original toJSON {failure} error")
                        && message.as_ptr() as usize == original.load(Ordering::SeqCst)));
            } else {
                assert_eq!(
                    result?,
                    Some(r#"{"child":"converted","tail":"call"}"#.into())
                );
            }
        }
    }
    Ok(())
}

#[test]
fn typed_json_probes_do_not_read_live_properties() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(Source {
        fields: Mutex::new(FieldMap::from([("toJSON".into(), true.into())])),
        getter: Box::new({
            let calls = calls.clone();
            move |_| {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                Err(AuthError::internal(
                    "Typed JSON probe must not read properties",
                ))
            }
        }),
    });
    let value = FieldValue::Object(FieldObject::from_source(source));
    let result = <serde_json::Value as crate::SchemaField>::from_field(value.clone());
    assert!(matches!(result, Err(original) if original.strict_equals(&value)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn endpoint_input_projection_keeps_native_reads_without_calling_json_methods() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let method = FieldValue::from(crate::FieldFunction::contextual({
        let calls = calls.clone();
        move |_, _| {
            let _ = calls.fetch_add(1, Ordering::SeqCst);
            Ok("converted".into())
        }
    }));
    let child: FieldValue =
        FieldMap::from([("toJSON".into(), method.clone()), ("kept".into(), 1.into())]).into();
    let value = FieldValue::Object(FieldObject::from_source(Arc::new(Source {
        fields: Mutex::new(FieldMap::from([
            ("toJSON".into(), method),
            ("when".into(), FieldDate::from_milliseconds(0.0).into()),
            ("absent".into(), FieldValue::Undefined),
            ("child".into(), child),
            (
                "array".into(),
                vec![FieldValue::Undefined, FieldDate::invalid().into()].into(),
            ),
        ])),
        getter: Box::new({
            let events = events.clone();
            move |name| {
                events
                    .lock()
                    .map_err(|_| AuthError::internal("Input event lock poisoned"))?
                    .push(name.to_owned());
                Ok(())
            }
        }),
    })));
    let mut request = crate::AuthRequest::new(crate::HttpMethod::Post, "/input");
    request.set_endpoint_body(ValidatedBody::unvalidated_native(value.clone()));
    assert!(request.input_field_value()?.strict_equals(&value));
    assert_eq!(
        request.input_body()?,
        Some(serde_json::json!({
            "when": "1970-01-01T00:00:00.000Z",
            "child": {"kept": 1},
            "array": [null, null],
        }))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Input event lock poisoned"))?,
        ["toJSON", "when", "absent", "child", "array"],
    );
    assert!(request.input_field_value()?.strict_equals(&value));
    assert_eq!(value.stringify()?, Some(r#""converted""#.into()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
