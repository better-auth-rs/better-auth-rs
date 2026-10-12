#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check receiver identity, rejected definitions, and partial persistence; native errors propagate."
)]

use super::*;
use crate::field_value::{FieldProperty, FieldPropertyUpdate};
use crate::store::ephemeral::table::TableRef;
use std::sync::atomic::{AtomicUsize, Ordering};

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Missing descriptor fixture"))
}

#[test]
fn promoted_rows_preserve_descriptors_and_setter_failure_effects() -> AuthResult<()> {
    let table = TableRef::new(Arc::default());
    let row = table.push(FieldMap::from([
        ("id".into(), "row".into()),
        ("2".into(), "second".into()),
        ("1".into(), "first".into()),
        ("01".into(), "named".into()),
        ("hidden".into(), "before".into()),
    ]))?;
    let value = row.field_value();
    let object = required(value.as_object())?;
    let identity = object.identity();
    assert_eq!(value.own_property_keys()?, ["1", "2", "id", "01", "hidden"]);
    let hidden = FieldPropertyDescriptor {
        enumerable: false,
        configurable: false,
        property: FieldProperty::Data {
            value: FieldValue::Null,
            writable: false,
        },
    };
    value.define_model_property("hidden", hidden.clone().into())?;
    assert_eq!(object.identity(), identity);
    assert_eq!(value.own_property_keys()?, ["1", "2", "id", "01", "hidden"]);
    assert_eq!(
        value.own_property_descriptor("hidden")?,
        Some(hidden.clone())
    );
    assert!(!value.set_property("hidden", true.into())?);
    assert!(!value.delete_property("hidden")?);
    assert!(!value.define_own_property("hidden", FieldPropertyDefinition::value(1.into()))?);
    assert_eq!(row.field("hidden")?, Some(FieldValue::Null));
    assert_eq!(
        row.shallow_fields()?,
        FieldMap::from([
            ("1".into(), "first".into()),
            ("2".into(), "second".into()),
            ("id".into(), "row".into()),
            ("01".into(), "named".into()),
        ])
    );

    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let failure: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
    let thrown = failure.clone();
    let descriptor = FieldPropertyDescriptor {
        enumerable: true,
        configurable: true,
        property: FieldProperty::Accessor {
            get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                let _ = observed.fetch_add(1, Ordering::SeqCst);
                receiver.model_property("id")
            })),
            set: Some(crate::FieldFunction::contextual(
                move |receiver, arguments| {
                    assert_eq!(required(receiver.as_object())?.identity(), identity);
                    receiver
                        .set_model_property("setterEffect", required(arguments.first())?.clone())?;
                    Err(AuthError::from_thrown(thrown.clone()))
                },
            )),
        },
    };
    value.define_model_property("stop", descriptor.clone().into())?;
    assert_eq!(value.own_property_descriptor("stop")?, Some(descriptor));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let result = row.apply_patch(FieldMap::from([
        ("first".into(), 1.into()),
        ("stop".into(), 2.into()),
        ("last".into(), 3.into()),
    ]));
    let Err(error) = result else {
        return Err(AuthError::internal("The native setter must throw"));
    };
    assert!(error.into_thrown_value()?.strict_equals(&failure));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(row.field("first")?, Some(1.into()));
    assert_eq!(row.field("setterEffect")?, Some(2.into()));
    assert_eq!(row.field("last")?, None);
    assert_eq!(value.own_property_descriptor("hidden")?, Some(hidden));
    assert_eq!(row.field("stop")?, Some("row".into()));
    let other: FieldValue = FieldMap::from([("id".into(), "other".into())]).into();
    assert_eq!(
        object.get_with_receiver("stop", &other)?,
        Some("other".into())
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert!(row.delete_field("stop")?);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn promoted_row_clone_captures_accessors_once_and_normalizes_descriptors() -> AuthResult<()> {
    let table = TableRef::new(Arc::default());
    let shared: FieldValue = FieldMap::from([("payload".into(), 7.into())]).into();
    let source = table.push(FieldMap::from([
        ("id".into(), "source".into()),
        ("alias".into(), shared.clone()),
    ]))?;
    let source_value = source.field_value();
    let identity = required(source_value.as_object())?.identity();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let payload = shared.clone();
    source_value.define_model_property(
        "value",
        FieldPropertyDescriptor {
            enumerable: true,
            configurable: false,
            property: FieldProperty::Accessor {
                get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                    assert_eq!(required(receiver.as_object())?.identity(), identity);
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Ok(payload.clone())
                })),
                set: None,
            },
        }
        .into(),
    )?;
    source_value.define_model_property(
        "hidden",
        FieldPropertyDefinition {
            property: FieldPropertyUpdate::Data {
                value: Some(true.into()),
                writable: Some(false),
            },
            ..FieldPropertyDefinition::default()
        },
    )?;
    let mut context = crate::StructuredCloneContext::deferred();
    let (copy, before) = source.structured_clone(&mut context)?;
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(required(before.get("value"))?.strict_equals(&shared));
    assert!(!before.contains_key("hidden"));
    context.publish();
    let cloned = required(copy.field("value")?)?;
    assert!(!cloned.strict_equals(&shared));
    assert!(required(copy.field("alias")?)?.strict_equals(&cloned));
    assert_eq!(
        copy.field_value().own_property_descriptor("value")?,
        Some(FieldPropertyDescriptor::data(cloned))
    );
    assert!(
        copy.field_value()
            .own_property_descriptor("hidden")?
            .is_none()
    );
    let (_, first) = source.structured_clone(&mut context)?;
    assert!(required(first.get("value"))?.strict_equals(&shared));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    copy.set_field("value".into(), false.into())?;
    assert!(!source_value.set_property("value", false.into())?);
    Ok(())
}

#[test]
fn promoted_quota_increment_keeps_gate_and_native_second_read_semantics() -> AuthResult<()> {
    let gate = MemoryGate::default();
    let row = TableRef::new(gate.clone()).push(FieldMap::from([("id".into(), "key".into())]))?;
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    row.field_value().define_model_property(
        "remaining",
        FieldPropertyDescriptor {
            enumerable: true,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                    let concurrent = gate.clone();
                    assert!(
                        std::thread::spawn(move || concurrent.try_lock().is_none())
                            .join()
                            .map_err(|_| AuthError::internal("Quota lock observer panicked"))?
                    );
                    let read = observed.fetch_add(1, Ordering::SeqCst);
                    receiver.set_model_property("read", read.into())?;
                    Ok(if read == 0 { 4.into() } else { "7".into() })
                })),
                set: Some(crate::FieldFunction::contextual(|receiver, arguments| {
                    receiver.set_model_property("stored", required(arguments.first())?.clone())?;
                    Ok(FieldValue::Undefined)
                })),
            },
        }
        .into(),
    )?;
    row.increment_number_fields(&[("remaining".into(), -1.0)])?;
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(row.field("read")?, Some(1.into()));
    assert_eq!(row.field("stored")?, Some("7-1".into()));
    Ok(())
}
