#![expect(
    clippy::panic_in_result_fn,
    reason = "The contracts assert receiver identity, method scheduling, and original errors; setup failures propagate."
)]

use super::*;
use crate::{
    FieldDate, FieldFunction, FieldMap, FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::sync::{Arc, Mutex};

#[test]
fn hint_selects_the_first_primitive_method_with_the_original_receiver() -> AuthResult<()> {
    for (hint, expected) in [
        (PrimitiveHint::String, "toString"),
        (PrimitiveHint::Number, "valueOf"),
        (PrimitiveHint::Default, "valueOf"),
    ] {
        let object = FieldObject::from(FieldMap::new());
        let identity = object.identity();
        let events = Arc::new(Mutex::new(Vec::new()));
        for name in ["toString", "valueOf"] {
            let events = events.clone();
            object.set(
                name,
                FieldFunction::contextual(move |receiver, arguments| {
                    let FieldValue::Object(receiver) = receiver else {
                        return Err(AuthError::internal("Primitive receiver is not the object"));
                    };
                    assert_eq!(receiver.identity(), identity);
                    assert!(arguments.is_empty());
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?
                        .push(name);
                    Ok(name.into())
                })
                .into(),
            )?;
        }
        assert_eq!(FieldValue::Object(object).primitive(hint)?, expected.into());
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?,
            [expected]
        );
    }
    Ok(())
}

#[test]
fn fallback_observes_method_replacement_and_rejects_all_object_results() -> AuthResult<()> {
    for result in [
        FieldValue::from(FieldMap::new()),
        FieldValue::from(Vec::<FieldValue>::new()),
        crate::FieldDate::from_milliseconds(0.0).into(),
        FieldFunction::contextual(|_, _| {
            Err(AuthError::internal(
                "Returned functions must not be invoked",
            ))
        })
        .into(),
    ] {
        let object = FieldObject::from(FieldMap::new());
        object.set(
            "toString",
            FieldFunction::contextual(|_, _| {
                Err(AuthError::internal("Replaced method must not be invoked"))
            })
            .into(),
        )?;
        object.set(
            "valueOf",
            FieldFunction::contextual(move |receiver, _| {
                let FieldValue::Object(receiver) = receiver else {
                    return Err(AuthError::internal("Primitive receiver is not the object"));
                };
                receiver.set(
                    "toString",
                    FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
                )?;
                Ok(result.clone())
            })
            .into(),
        )?;
        assert!(
            FieldValue::Object(object)
                .primitive(PrimitiveHint::Number)?
                .is_undefined()
        );
    }
    Ok(())
}

#[test]
fn noncallable_properties_suppress_builtins_and_callback_errors_stay_original() -> AuthResult<()> {
    let fallback = FieldFunction::contextual(|_, _| Ok(FieldValue::Number(-0.0)));
    for first in [FieldValue::Undefined, FieldValue::Null, false.into()] {
        let value = FieldValue::from(FieldMap::from([
            ("toString".into(), first.clone()),
            ("valueOf".into(), fallback.clone().into()),
        ]));
        let primitive = value.primitive(PrimitiveHint::String)?;
        assert!(
            matches!(primitive, FieldValue::Number(number) if number == 0.0 && number.is_sign_negative())
        );
        let value = FieldValue::from(FieldMap::from([
            ("toString".into(), first),
            ("valueOf".into(), FieldValue::Null),
        ]));
        assert!(
            matches!(value.primitive(PrimitiveHint::String), Err(AuthError::TypeError(message)) if message == "No default value")
        );
    }
    let message = String::from("primitive callback original error");
    let original = message.as_ptr() as usize;
    let failure = Mutex::new(Some(message));
    let value = FieldValue::from(FieldMap::from([
        (
            "valueOf".into(),
            FieldFunction::contextual(move |_, _| {
                let message = failure
                    .lock()
                    .map_err(|_| AuthError::internal("Primitive error lock poisoned"))?
                    .take()
                    .ok_or_else(|| AuthError::internal("Primitive callback repeated"))?;
                Err(AuthError::internal(message))
            })
            .into(),
        ),
        (
            "toString".into(),
            FieldFunction::contextual(|_, _| {
                Err(AuthError::internal("Fallback ran after the original error"))
            })
            .into(),
        ),
    ]));
    let result = value.primitive(PrimitiveHint::Number);
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == original)
    );
    Ok(())
}

#[test]
fn public_conversions_share_hints_and_evaluate_operands_left_to_right() -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let operand = |name: &'static str| {
        let fields = ["valueOf", "toString"].map(|method| {
            let events = events.clone();
            (
                method.into(),
                FieldFunction::contextual(move |_, _| {
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?
                        .push((name, method));
                    Ok(if method == "valueOf" {
                        42.0.into()
                    } else {
                        "2030-01-01T00:00:00.000Z".into()
                    })
                })
                .into(),
            )
        });
        FieldValue::from(FieldMap::from(fields))
    };
    let left = operand("left");
    let right = operand("right");
    assert_eq!(left.display_utf16()?, "2030-01-01T00:00:00.000Z".into());
    assert_eq!(crate::query::field_number(&left)?, 42.0);
    assert_eq!(
        crate::query::field_compare(&left, &right)?,
        Some(std::cmp::Ordering::Equal)
    );
    assert_eq!(crate::query::field_add(&left, &right)?, 84.0.into());
    assert_eq!(crate::query::field_date(&left)?.milliseconds(), 42.0);
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?,
        [
            ("left", "toString"),
            ("left", "valueOf"),
            ("left", "valueOf"),
            ("right", "valueOf"),
            ("left", "valueOf"),
            ("right", "valueOf"),
            ("left", "valueOf"),
        ]
    );
    Ok(())
}

#[test]
fn date_default_and_numeric_consumers_select_different_native_methods() -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let fields = ["valueOf", "toString"].map(|name| {
        let events = events.clone();
        (
            name.into(),
            FieldFunction::contextual(move |_, _| {
                events
                    .lock()
                    .map_err(|_| AuthError::internal("Date primitive event lock poisoned"))?
                    .push(name);
                Ok(if name == "valueOf" {
                    7.0.into()
                } else {
                    "date-primitive".into()
                })
            })
            .into(),
        )
    });
    let date: FieldValue =
        FieldDate::from_milliseconds_with_properties(0.0, FieldMap::from(fields).into()).into();
    assert_eq!(
        crate::query::field_add(&date, &"!".into())?,
        "date-primitive!".into()
    );
    assert_eq!(crate::query::field_number(&date)?, 7.0);
    assert_eq!(date.display_utf16()?, "date-primitive".into());
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Date primitive event lock poisoned"))?,
        ["toString", "valueOf", "toString"]
    );
    Ok(())
}

struct UnreadableProperties;

impl UnreadableProperties {
    fn forbidden<T>() -> AuthResult<T> {
        Err(AuthError::internal(
            "The Date constructor must not inspect the original Date's properties",
        ))
    }
}

impl FieldObjectSource for UnreadableProperties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Self::forbidden()
    }
    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Self::forbidden()
    }
    fn get_with_receiver(&self, _: &str, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        Self::forbidden()
    }
    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Self::forbidden()
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        Self::forbidden()
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Self::forbidden()
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
fn date_constructor_copies_the_native_timestamp_without_property_reads() -> AuthResult<()> {
    for milliseconds in [1234.0, f64::NAN] {
        let original: FieldValue = FieldDate::from_milliseconds_with_properties(
            milliseconds,
            FieldObject::from_source(Arc::new(UnreadableProperties)),
        )
        .into();
        let copied = crate::query::field_date(&original)?;
        if milliseconds.is_nan() {
            assert!(copied.milliseconds().is_nan());
        } else {
            assert_eq!(copied.milliseconds(), milliseconds);
        }
        assert!(!FieldValue::from(copied).strict_equals(&original));
    }
    Ok(())
}

#[test]
fn noncallable_array_join_uses_the_object_tag_instead_of_indexed_values() -> AuthResult<()> {
    for join in [FieldValue::Undefined, FieldValue::Null, false.into()] {
        let array: FieldValue = vec![42.0.into()].into();
        array.set_model_property("join", join)?;
        assert_eq!(array.display_utf16()?, "[object Array]".into());
        assert_eq!(array.call_to_string()?, "[object Array]".into());
        assert!(crate::query::field_number(&array)?.is_nan());
    }
    Ok(())
}

#[test]
fn function_numeric_conversion_preserves_the_source_reflection_boundary_and_original_errors()
-> AuthResult<()> {
    const SOURCE_ERROR: &str =
        "JavaScript function source is unavailable for this Rust field callback";
    let function: FieldValue = FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into();
    assert!(crate::query::field_number(&function)?.is_nan());
    assert!(
        matches!(function.display_utf16(), Err(AuthError::Internal(message)) if message == SOURCE_ERROR)
    );
    assert!(
        matches!(crate::query::field_compare(&function, &1.0.into()), Err(AuthError::Internal(message)) if message == SOURCE_ERROR)
    );
    function.set_model_property(
        "toString",
        FieldFunction::contextual(|_, _| Ok("9".into())).into(),
    )?;
    assert_eq!(crate::query::field_number(&function)?, 9.0);
    assert_eq!(function.display_utf16()?, "9".into());
    assert_eq!(
        crate::query::field_add(&function, &1.0.into())?,
        "91".into()
    );
    let original = String::from(SOURCE_ERROR);
    let original_allocation = original.as_ptr() as usize;
    let error = Mutex::new(Some(original));
    function.set_model_property(
        "valueOf",
        FieldFunction::contextual(move |_, _| {
            let original = error
                .lock()
                .map_err(|_| AuthError::internal("Function primitive error lock poisoned"))?
                .take()
                .ok_or_else(|| AuthError::internal("Function primitive callback repeated"))?;
            Err(AuthError::internal(original))
        })
        .into(),
    )?;
    assert!(
        matches!(crate::query::field_number(&function), Err(AuthError::Internal(message)) if message.as_ptr() as usize == original_allocation)
    );
    Ok(())
}

#[test]
fn builtin_join_captures_length_before_separator_and_reads_elements_after_separator()
-> AuthResult<()> {
    let array: FieldValue = vec!["first".into(), "second".into()].into();
    let receiver = array.clone();
    let separator: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| {
            receiver.set_model_property("0", "changed".into())?;
            receiver.set_model_property("2", "late".into())?;
            Ok("|".into())
        })
        .into(),
    )])
    .into();
    assert_eq!(
        array.join_method(&separator, "array")?,
        "changed|second".into()
    );
    assert_eq!(array.model_property("length")?, 3.into());

    let array: FieldValue = vec!["a".into(), "b".into()].into();
    assert_eq!(array.join_method(&array, "array")?, "aa,bb".into());
    assert_eq!(
        array.join_method(&FieldValue::Null, "array")?,
        "anullb".into()
    );
    assert_eq!(
        array.join_method(&FieldValue::Undefined, "array")?,
        "a,b".into()
    );
    let separator: FieldValue = crate::Utf16String::from_units(vec![0xd800]).into();
    assert_eq!(
        array
            .join_method(&separator, "array")?
            .display_utf16()?
            .as_utf16(),
        [u16::from(b'a'), 0xd800, u16::from(b'b')]
    );
    Ok(())
}

#[test]
fn builtin_join_preserves_sparse_nullish_and_circular_elements() -> AuthResult<()> {
    let array: FieldValue = FieldArray::with_length(5).into();
    array.set_model_property("0", "first".into())?;
    array.set_model_property("2", FieldValue::Null)?;
    array.set_model_property("3", FieldValue::Undefined)?;
    array.set_model_property("4", array.clone())?;
    let result = array.join_method(&"|".into(), "array");
    array.set_model_property("length", 0.into())?;
    assert_eq!(result?, "first||||".into());

    let empty: FieldValue = Vec::<FieldValue>::new().into();
    let error: FieldValue = FieldMap::from([("message".into(), "separator error".into())]).into();
    let original = error.clone();
    let separator: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(original.clone()))).into(),
    )])
    .into();
    let result = empty.join_method(&separator, "empty");
    assert!(
        matches!(result, Err(actual) if actual.raw_value().is_some_and(|value| value.strict_equals(&error)))
    );
    Ok(())
}
