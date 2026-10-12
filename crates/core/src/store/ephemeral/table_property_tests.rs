#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check native array descriptors, partial shrink, and staged clone publication; errors propagate."
)]

use super::*;
use crate::{
    FieldMap,
    field_value::{FieldProperty, FieldPropertyUpdate},
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Missing table descriptor fixture"))
}

#[test]
fn table_length_shrink_preserves_partial_deletions_and_readonly_length() -> AuthResult<()> {
    let table = TableRef::<FieldMap>::new(Arc::default());
    for id in ["first", "fixed", "removed"] {
        let _ = table.push(FieldMap::from([("id".into(), id.into())]))?;
    }
    let value = FieldValue::Array(table.array());
    let fixed = required(value.own_property_descriptor("1")?)?;
    value.define_model_property(
        "1",
        FieldPropertyDefinition {
            configurable: Some(false),
            ..FieldPropertyDefinition::default()
        },
    )?;
    assert!(!value.define_own_property(
        "length",
        FieldPropertyDefinition {
            property: FieldPropertyUpdate::Data {
                value: Some(0.into()),
                writable: Some(false)
            },
            ..FieldPropertyDefinition::default()
        }
    )?);
    assert_eq!(table.len()?, 2);
    assert_eq!(table.array().own_indices()?, [0, 1]);
    assert_eq!(
        value.own_property_descriptor("1")?,
        Some(FieldPropertyDescriptor {
            configurable: false,
            ..fixed
        })
    );
    assert_eq!(
        value.own_property_descriptor("length")?,
        Some(FieldPropertyDescriptor {
            enumerable: false,
            configurable: false,
            property: FieldProperty::Data {
                value: 2.into(),
                writable: false
            },
        })
    );
    assert!(table.push(FieldMap::new()).is_err());
    assert!(!value.delete_property("1")?);
    assert!(value.delete_property("0")?);
    assert_eq!(table.len()?, 2);
    assert_eq!(table.array().own_indices()?, [1]);
    let copied = table.shallow_copy()?;
    assert_eq!(copied.len()?, 2);
    assert_eq!(copied.array().own_indices()?, [1]);
    assert!(FieldValue::Array(copied.array()).delete_property("1")?);
    let _ = copied.push(FieldMap::from([("id".into(), "new".into())]))?;
    assert_eq!(copied.len()?, 3);
    assert_eq!(table.len()?, 2);
    Ok(())
}

#[test]
fn table_accessor_clone_uses_live_receiver_and_one_staged_index_store() -> AuthResult<()> {
    let table = TableRef::new(Arc::default());
    let row = table.push(FieldMap::from([("id".into(), "source".into())]))?;
    let array = table.array();
    let identity = array.identity();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let retained = row.field_value();
    FieldValue::Array(array.clone()).define_model_property(
        "0",
        FieldPropertyDescriptor {
            enumerable: true,
            configurable: false,
            property: FieldProperty::Accessor {
                get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                    assert_eq!(required(receiver.as_array())?.identity(), identity);
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    receiver.set_model_property("effect", true.into())?;
                    Ok(retained.clone())
                })),
                set: None,
            },
        }
        .into(),
    )?;
    assert!(array.own_property_descriptor(0)?.is_some());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let mut context = StructuredCloneContext::deferred();
    let mut origins = Vec::new();
    let target = table.deep_clone_with(&mut context, |live, cloned, before| {
        origins.push((live, cloned, before))
    })?;
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(target.len()?, 0);
    assert_eq!(origins.len(), 1);
    assert!(required(origins.first())?.0.same_row(&row));
    context.publish();
    assert_eq!(target.len()?, 1);
    let cloned_row = required(target.row_at(0)?)?;
    assert!(cloned_row.same_row(&required(origins.first())?.1));
    assert!(!cloned_row.same_row(&row));
    assert_eq!(
        FieldValue::Array(target.array()).own_property_descriptor("0")?,
        Some(FieldPropertyDescriptor::data(cloned_row.field_value()))
    );
    assert_eq!(
        FieldValue::Array(array.clone()).model_property("effect")?,
        true.into()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(FieldValue::Array(target.array()).delete_property("0")?);
    assert_eq!(target.len()?, 1);
    assert_eq!(array.own_indices()?, [0]);
    Ok(())
}
