#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::{AuthError, FieldArray, FieldDate};

#[test]
fn ordered_defaults_skip_nullish_overrides_and_keep_native_children() -> AuthResult<()> {
    let child: FieldValue = FieldMap::from([("date".into(), FieldDate::invalid().into())]).into();
    let query: FieldValue = FieldMap::from([
        ("code".into(), FieldValue::Null),
        ("state".into(), "query-state".into()),
        (
            "nested".into(),
            FieldMap::from([("left".into(), child.clone())]).into(),
        ),
        ("absent".into(), FieldValue::Undefined),
    ])
    .into();
    let body: FieldValue = FieldMap::from([
        ("code".into(), "body-code".into()),
        ("state".into(), "body-state".into()),
        (
            "nested".into(),
            FieldMap::from([("right".into(), child.clone())]).into(),
        ),
        ("absent".into(), false.into()),
    ])
    .into();
    let merged = defu(&[query.clone(), body.clone()])?;
    assert_eq!(merged.model_property("code")?, "body-code".into());
    assert_eq!(merged.model_property("state")?, "query-state".into());
    assert_eq!(merged.model_property("absent")?, false.into());
    let nested = merged.model_property("nested")?;
    assert_eq!(
        nested
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["right", "left"]
    );
    assert!(nested.model_property("left")?.strict_equals(&child));
    assert!(nested.model_property("right")?.strict_equals(&child));
    assert!(query.model_property("code")?.is_null());
    assert_eq!(body.model_property("state")?, "body-state".into());
    Ok(())
}

#[test]
fn array_spread_materializes_holes_and_keeps_aliases_in_source_order() -> AuthResult<()> {
    let child: FieldValue = FieldMap::from([("kept".into(), FieldValue::Undefined)]).into();
    let query: FieldValue = FieldArray::with_length(3).into();
    query.set_model_property("0", child.clone())?;
    query.set_model_property("2", "query-last".into())?;
    let body: FieldValue = FieldArray::with_length(2).into();
    body.set_model_property("1", child.clone())?;
    let merged = defu(&[
        FieldMap::from([("items".into(), query.clone())]).into(),
        FieldMap::from([("items".into(), body.clone())]).into(),
    ])?
    .model_property("items")?;
    let array = merged
        .as_array()
        .ok_or_else(|| AuthError::internal("Expected merged array"))?;
    assert_eq!(array.own_indices()?, [0, 1, 2, 3, 4]);
    assert!(merged.model_property("0")?.strict_equals(&child));
    assert!(merged.model_property("4")?.strict_equals(&child));
    assert!(merged.model_property("1")?.is_undefined());
    assert!(merged.model_property("3")?.is_undefined());
    assert_eq!(merged.model_property("2")?, "query-last".into());
    assert_eq!(
        query.as_array().map(FieldArray::own_indices).transpose()?,
        Some(vec![0, 2])
    );
    assert_eq!(
        body.as_array().map(FieldArray::own_indices).transpose()?,
        Some(vec![1])
    );
    Ok(())
}
