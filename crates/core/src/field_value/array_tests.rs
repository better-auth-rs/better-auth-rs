#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify getter order, array ownership, and failure atomicity; source errors propagate."
)]

use super::*;
use crate::{AuthError, StructuredCloneContext};
use std::sync::Mutex;

type OnRead = Box<dyn Fn(usize) -> AuthResult<()> + Send + Sync>;

struct Source {
    length: usize,
    properties: FieldObject,
    entries: Mutex<BTreeMap<usize, FieldValue>>,
    on_read: OnRead,
    target: Mutex<Option<FieldArray>>,
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> AuthError {
    AuthError::internal("Array contract lock poisoned")
}

impl FieldArraySource for Source {
    fn properties(&self) -> &FieldObject {
        &self.properties
    }
    fn len(&self) -> AuthResult<usize> {
        Ok(self.length)
    }
    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        Ok(self
            .entries
            .lock()
            .map_err(poisoned)?
            .keys()
            .copied()
            .collect())
    }
    fn get(&self, index: usize, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        (self.on_read)(index)?;
        Ok(self.entries.lock().map_err(poisoned)?.get(&index).cloned())
    }
    fn own_property_descriptor(&self, index: usize) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .entries
            .lock()
            .map_err(poisoned)?
            .get(&index)
            .cloned()
            .map(FieldPropertyDescriptor::data))
    }
    fn length_descriptor(&self) -> AuthResult<FieldPropertyDescriptor> {
        Ok(FieldPropertyDescriptor {
            enumerable: false,
            configurable: false,
            property: FieldProperty::Data {
                value: self.length.into(),
                writable: true,
            },
        })
    }
    fn set(&self, _: usize, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::type_error(
            "The live array source does not support index assignment",
        ))
    }
    fn define_index(&self, _: usize, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::type_error(
            "The live array source does not support index definition",
        ))
    }
    fn define_length(&self, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::type_error(
            "The live array source does not support length assignment",
        ))
    }
    fn delete(&self, _: usize) -> AuthResult<bool> {
        Err(AuthError::type_error(
            "The live array source does not support index deletion",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
    fn clone_seed(&self) -> AuthResult<Option<ArrayCloneSeed>> {
        let seed = FieldArray::new().clone_seed()?;
        *self.target.lock().map_err(poisoned)? = Some(seed.array.clone());
        Ok(Some(seed))
    }
}

#[test]
fn indexed_accessors_preserve_alternate_receivers_and_clone_hidden_indices_as_data()
-> AuthResult<()> {
    let value: FieldValue = vec![0.into(), 1.into(), 2.into()].into();
    value.set_model_property("marker", "target".into())?;
    let receiver: FieldValue = FieldMap::from([("marker".into(), "receiver".into())]).into();
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = reads.clone();
    assert!(
        value.define_own_property(
            "0",
            FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        receiver.model_property("marker")
                    })),
                    set: Some(crate::FieldFunction::contextual(|receiver, arguments| {
                        let assigned = arguments
                            .first()
                            .cloned()
                            .ok_or_else(|| AuthError::internal("Missing setter value"))?;
                        receiver.set_model_property("marker", assigned)?;
                        Ok(FieldValue::Undefined)
                    })),
                },
            }
            .into()
        )?
    );
    let hidden_reads = reads.clone();
    assert!(
        value.define_own_property(
            "1",
            FieldPropertyDescriptor {
                enumerable: false,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(crate::FieldFunction::contextual(move |_, _| {
                        hidden_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok("hidden-index".into())
                    })),
                    set: None,
                },
            }
            .into()
        )?
    );
    assert_eq!(
        value.get_property_with_receiver("0", &receiver)?,
        "receiver".into()
    );
    assert!(value.set_property_with_receiver("0", "assigned".into(), &receiver)?);
    assert_eq!(receiver.model_property("marker")?, "assigned".into());
    assert_eq!(value.model_property("marker")?, "target".into());
    assert!(value.set_property_with_receiver("2", "receiver-index".into(), &receiver)?);
    assert_eq!(receiver.model_property("2")?, "receiver-index".into());
    assert_eq!(value.model_property("2")?, 2.into());
    assert!(<Vec<FieldValue> as crate::SchemaField>::from_field(value.clone()).is_err());
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cloned = StructuredCloneContext::new().clone_value(&value)?;
    assert_eq!(cloned.model_property("length")?, 3.into());
    assert_eq!(
        cloned.own_property_descriptor("1")?,
        Some(FieldPropertyDescriptor::data("hidden-index".into()))
    );
    assert_eq!(
        cloned.own_property_descriptor("0")?,
        Some(FieldPropertyDescriptor::data("target".into()))
    );
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn array_object_rest_preserves_holes_exclusions_and_shared_values_after_getter_deletion()
-> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let child = FieldValue::from(crate::FieldMap::from([("value".into(), 1.into())]));
    let source: Arc<Source> = Arc::new_cyclic(|weak: &std::sync::Weak<Source>| {
        let weak = weak.clone();
        let reads = reads.clone();
        Source {
            length: 5,
            properties: FieldMap::new().into(),
            entries: Mutex::new(
                [
                    (0, child.clone()),
                    (1, "excluded".into()),
                    (2, "removed-by-first".into()),
                    (4, FieldValue::Undefined),
                ]
                .into(),
            ),
            on_read: Box::new(move |index| {
                if index == 1 {
                    return Err(AuthError::internal(
                        "The excluded array getter must not run",
                    ));
                }
                let source = weak
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Missing rest array source"))?;
                if !source
                    .entries
                    .lock()
                    .map_err(poisoned)?
                    .contains_key(&index)
                {
                    return Ok(());
                }
                reads.lock().map_err(poisoned)?.push(index);
                if index == 0 {
                    let mut entries = source.entries.lock().map_err(poisoned)?;
                    let _ = entries.remove(&2);
                    let _ = entries.insert(5, "not-enumerated".into());
                }
                Ok(())
            }),
            target: Mutex::new(None),
        }
    });
    let array = FieldArray::from_source(source);
    let rest = FieldValue::from(array.clone()).enumerable_fields_except(&["1"])?;
    assert_eq!(
        rest.keys().map(String::as_str).collect::<Vec<_>>(),
        ["0", "4"]
    );
    assert_eq!(*reads.lock().map_err(poisoned)?, [0, 4]);
    assert!(rest["0"].strict_equals(&child));
    assert!(rest["4"].is_undefined());
    assert_eq!(array.own_indices()?, [0, 1, 4, 5]);
    Ok(())
}

#[test]
fn clone_reads_arrays_depth_first_and_preserves_holes_and_own_undefined() -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let outer = Arc::new(Source {
        length: 4,
        properties: FieldMap::new().into(),
        entries: Mutex::new(
            [
                (1, 1.into()),
                (2, "remove".into()),
                (3, FieldValue::Undefined),
            ]
            .into(),
        ),
        on_read: Box::new(move |index| {
            log.lock().map_err(poisoned)?.push(format!("outer:{index}"));
            Ok(())
        }),
        target: Mutex::new(None),
    });
    let weak = Arc::downgrade(&outer);
    let log = events.clone();
    let nested = FieldArray::from_source(Arc::new(Source {
        length: 1,
        properties: FieldMap::new().into(),
        entries: Mutex::new([(0, "nested".into())].into()),
        on_read: Box::new(move |index| {
            log.lock()
                .map_err(poisoned)?
                .push(format!("nested:{index}"));
            let outer = weak
                .upgrade()
                .ok_or_else(|| AuthError::internal("Missing outer array"))?;
            let mut entries = outer.entries.lock().map_err(poisoned)?;
            let _ = entries.insert(1, 2.into());
            let _ = entries.remove(&2);
            let _ = entries.insert(4, "not-enumerated".into());
            Ok(())
        }),
        target: Mutex::new(None),
    }));
    let _ = outer
        .entries
        .lock()
        .map_err(poisoned)?
        .insert(0, nested.into());
    let source = FieldArray::from_source(outer);
    let copied = StructuredCloneContext::new().clone_value(&source.clone().into())?;
    let copied = copied
        .as_array()
        .ok_or_else(|| AuthError::internal("Expected cloned array"))?;
    assert_eq!(
        *events.lock().map_err(poisoned)?,
        ["outer:0", "nested:0", "outer:1", "outer:3"]
    );
    assert_eq!(copied.len()?, 4);
    assert_eq!(copied.own_indices()?, [0, 1, 3]);
    assert_eq!(copied.get(1)?, Some(2.into()));
    assert_eq!(copied.get(2)?, None);
    assert_eq!(copied.get(3)?, Some(FieldValue::Undefined));
    assert!(!copied.same_array(&source));
    assert_eq!(copied.map(Ok)?.own_indices()?, [0, 1, 3]);
    assert_eq!(copied.filter(|_| Ok(true))?.len()?, 3);
    assert!(<Vec<FieldValue> as crate::SchemaField>::from_field(copied.clone().into()).is_err());
    assert_eq!(
        FieldValue::from(copied.clone()).stringify()?.as_deref(),
        Some("[[\"nested\"],2,null,null]")
    );
    Ok(())
}

#[test]
fn direct_array_cycles_share_one_clone_identity_and_json_rejects_the_cycle() -> AuthResult<()> {
    let source = Arc::new(Source {
        length: 2,
        properties: FieldMap::new().into(),
        entries: Mutex::new(BTreeMap::new()),
        on_read: Box::new(|_| Ok(())),
        target: Mutex::new(None),
    });
    let array = FieldArray::from_source(source.clone());
    source
        .entries
        .lock()
        .map_err(poisoned)?
        .extend([(0, array.clone().into()), (1, "tail".into())]);
    let mut context = StructuredCloneContext::new();
    let copied = context.clone_value(&array.clone().into())?;
    let copied_array = copied
        .as_array()
        .ok_or_else(|| AuthError::internal("Expected copied array"))?;
    assert!(
        copied_array
            .get(0)?
            .is_some_and(|value| value.strict_equals(&copied))
    );
    assert!(!copied.strict_equals(&array.clone().into()));
    assert!(
        context
            .clone_value(&array.clone().into())?
            .strict_equals(&copied)
    );
    assert!(matches!(copied.stringify(), Err(AuthError::TypeError(_))));
    assert!(matches!(copied.json(), Err(AuthError::TypeError(_))));
    assert_eq!(copied.display_utf16()?, ",tail".into());
    source.entries.lock().map_err(poisoned)?.clear();
    Ok(())
}

#[test]
fn array_getter_errors_retain_allocation_stop_reads_and_prevent_deferred_publication()
-> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let error = "array-getter-original".to_owned();
    let allocation = error.as_ptr() as usize;
    let failure = Arc::new(Mutex::new(Some(AuthError::Internal(error))));
    let log = events.clone();
    let source = Arc::new(Source {
        length: 2,
        properties: FieldMap::new().into(),
        entries: Mutex::new([(0, true.into()), (1, false.into())].into()),
        on_read: Box::new(move |index| {
            log.lock().map_err(poisoned)?.push(index);
            Err(failure
                .lock()
                .map_err(poisoned)?
                .take()
                .ok_or_else(|| AuthError::internal("Repeated failed getter"))?)
        }),
        target: Mutex::new(None),
    });
    let mut context = StructuredCloneContext::deferred();
    let earlier = context.clone_value(&vec![FieldValue::from("earlier")].into())?;
    let value = FieldArray::from_source(source.clone()).into();
    let result = context.clone_value(&value);
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == allocation)
    );
    assert_eq!(*events.lock().map_err(poisoned)?, [0]);
    drop(context);
    assert_eq!(
        earlier
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected earlier array"))?
            .len()?,
        0
    );
    assert_eq!(
        source
            .target
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| AuthError::internal("Expected failed clone placeholder"))?
            .len()?,
        0
    );
    Ok(())
}

#[test]
fn live_array_schema_narrowing_is_lazy_and_json_retains_original_getter_errors() -> AuthResult<()> {
    for stringify in [false, true] {
        let reads = Arc::new(Mutex::new(Vec::new()));
        let observed = reads.clone();
        let message = "array-json-original".to_owned();
        let allocation = message.as_ptr() as usize;
        let error = Arc::new(Mutex::new(Some(AuthError::Internal(message))));
        let array = FieldArray::from_source(Arc::new(Source {
            length: 2,
            properties: FieldMap::new().into(),
            entries: Mutex::new([(0, "first".into()), (1, "unread".into())].into()),
            on_read: Box::new(move |index| {
                observed.lock().map_err(poisoned)?.push(index);
                Err(error
                    .lock()
                    .map_err(poisoned)?
                    .take()
                    .ok_or_else(|| AuthError::internal("Repeated JSON getter"))?)
            }),
            target: Mutex::new(None),
        }));
        let value = FieldValue::from(array);
        let handle = crate::SchemaValue::<FieldArray>::from_field(value.clone());
        assert!(
            handle.typed()?.same_array(
                value
                    .as_array()
                    .ok_or_else(|| AuthError::internal("Expected original array"))?
            )
        );
        let narrowed = crate::SchemaValue::<Vec<String>>::from_field(value.clone());
        assert!(narrowed.field_value().strict_equals(&value));
        assert!(reads.lock().map_err(poisoned)?.is_empty());
        let result = if stringify {
            value.stringify().map(|_| ())
        } else {
            value.json().map(|_| ())
        };
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == allocation)
        );
        assert_eq!(*reads.lock().map_err(poisoned)?, [0]);
    }
    Ok(())
}
