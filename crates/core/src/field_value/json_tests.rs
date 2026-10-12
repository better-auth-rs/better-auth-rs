#![expect(
    clippy::panic_in_result_fn,
    reason = "JSON contracts assert callback scheduling, identity, and complete boundary results."
)]

use super::*;
use crate::{FieldDate, FieldFunction, FieldObject, Utf16String};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn converting(
    callback: impl Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
) -> FieldValue {
    FieldMap::from([("toJSON".into(), FieldFunction::contextual(callback).into())]).into()
}

fn encode(value: &FieldValue, text: bool) -> AuthResult<Option<String>> {
    if text {
        value.stringify()
    } else {
        value
            .json()?
            .map(|value| serde_json::to_string(&value).map_err(Into::into))
            .transpose()
    }
}

#[test]
fn methods_receive_each_property_key_and_the_original_receiver() -> AuthResult<()> {
    for text in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let child = converting({
            let calls = calls.clone();
            move |receiver, arguments| {
                assert_eq!(arguments.len(), 1);
                let key = arguments
                    .first()
                    .and_then(FieldValue::as_str)
                    .ok_or_else(|| AuthError::internal("Missing toJSON key"))?;
                let object = receiver
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Missing toJSON receiver"))?;
                calls
                    .lock()
                    .map_err(|_| AuthError::internal("toJSON event lock poisoned"))?
                    .push((object.identity(), key.to_owned()));
                Ok(key.into())
            }
        });
        let receiver = child
            .as_object()
            .ok_or_else(|| AuthError::internal("Missing child object"))?
            .identity();
        assert_eq!(encode(&child, text)?, Some(r#""""#.into()));
        let value: FieldValue = FieldMap::from([
            ("member".into(), child.clone()),
            ("array".into(), vec![child.clone(), child].into()),
        ])
        .into();
        assert_eq!(
            encode(&value, text)?,
            Some(r#"{"member":"member","array":["0","1"]}"#.into())
        );
        assert_eq!(
            *calls
                .lock()
                .map_err(|_| AuthError::internal("toJSON event lock poisoned"))?,
            [
                (receiver, "".into()),
                (receiver, "member".into()),
                (receiver, "0".into()),
                (receiver, "1".into()),
            ]
        );
    }
    Ok(())
}

#[test]
fn omission_is_decided_after_preparation_without_running_pure_predicates() -> AuthResult<()> {
    for text in [false, true] {
        for omitted in [
            FieldValue::Undefined,
            FieldFunction::contextual(|_, _| Ok(FieldValue::Null)).into(),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let value = converting({
                let calls = calls.clone();
                move |_, _| {
                    let _ = calls.fetch_add(1, Ordering::SeqCst);
                    Ok(omitted.clone())
                }
            });
            assert!(!value.is_json_omitted());
            assert!(!crate::field_value::serde::optional_value::is_json_omitted(
                &Some(value.clone())
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(encode(&value, text)?, None);
            assert_eq!(
                encode(
                    &FieldMap::from([("child".into(), value.clone())]).into(),
                    text
                )?,
                Some("{}".into())
            );
            assert_eq!(encode(&vec![value].into(), text)?, Some("[null]".into()));
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }
    }
    Ok(())
}

#[test]
fn prepared_results_do_not_invoke_another_json_method() -> AuthResult<()> {
    for text in [false, true] {
        let returned: FieldValue = FieldMap::from([
            (
                "toJSON".into(),
                FieldFunction::contextual(|_, _| {
                    Err(AuthError::internal("Returned object's method must not run"))
                })
                .into(),
            ),
            ("kept".into(), true.into()),
        ])
        .into();
        assert_eq!(
            encode(&converting(move |_, _| Ok(returned.clone())), text)?,
            Some(r#"{"kept":true}"#.into())
        );
        for date in [FieldDate::from_milliseconds(0.0), FieldDate::invalid()] {
            let expected = if date.milliseconds().is_nan() {
                "null"
            } else {
                r#""1970-01-01T00:00:00.000Z""#
            };
            assert_eq!(encode(&date.clone().into(), text)?, Some(expected.into()));
            assert_eq!(
                encode(&converting(move |_, _| Ok(date.clone().into())), text)?,
                Some("{}".into())
            );
        }
        let ordinary: FieldValue = FieldMap::from([
            ("toJSON".into(), "not callable".into()),
            ("kept".into(), true.into()),
        ])
        .into();
        assert_eq!(
            encode(&ordinary, text)?,
            Some(r#"{"toJSON":"not callable","kept":true}"#.into())
        );
    }
    Ok(())
}

#[test]
fn preparation_can_break_or_introduce_ancestor_cycles() -> AuthResult<()> {
    for text in [false, true] {
        let object = FieldObject::from(FieldMap::new());
        object.set("self", FieldValue::Object(object.clone()))?;
        object.set(
            "toJSON",
            FieldFunction::contextual(|_, _| Ok("detached".into())).into(),
        )?;
        let broken = encode(&FieldValue::Object(object.clone()), text);
        let _ = object.delete("self")?;
        assert_eq!(broken?, Some(r#""detached""#.into()));

        let object = FieldObject::from(FieldMap::new());
        object.set(
            "toJSON",
            FieldFunction::contextual(|receiver, arguments| {
                if arguments.first().and_then(FieldValue::as_str) == Some("again") {
                    Ok(7.into())
                } else {
                    Ok(receiver.clone())
                }
            })
            .into(),
        )?;
        object.set("again", FieldValue::Object(object.clone()))?;
        let broken = encode(&FieldValue::Object(object.clone()), text);
        let _ = object.delete("again")?;
        assert_eq!(broken?, Some(r#"{"again":7}"#.into()));

        let parent = FieldObject::from(FieldMap::new());
        let child = converting({
            let parent = parent.clone();
            move |_, _| Ok(FieldValue::Object(parent.clone()))
        });
        parent.set("child", child)?;
        let introduced = encode(&FieldValue::Object(parent.clone()), text);
        let _ = parent.delete("child")?;
        assert!(matches!(introduced, Err(AuthError::TypeError(message))
            if message == "Converting circular structure to JSON"));
    }
    Ok(())
}

#[test]
fn method_mutations_precede_property_name_capture() -> AuthResult<()> {
    for text in [false, true] {
        let value = converting(|receiver, _| {
            let object = receiver
                .as_object()
                .ok_or_else(|| AuthError::internal("Missing toJSON receiver"))?;
            let _ = object.delete("drop")?;
            object.set("added", true.into())?;
            object.set("1", "numeric".into())?;
            Ok(receiver.clone())
        });
        let object = value
            .as_object()
            .ok_or_else(|| AuthError::internal("Missing toJSON object"))?;
        object.set("drop", "removed".into())?;
        object.set("tail", "kept".into())?;
        assert_eq!(
            encode(&value, text)?,
            Some(r#"{"1":"numeric","tail":"kept","added":true}"#.into())
        );
        assert_eq!(object.own_keys()?, ["1", "toJSON", "tail", "added"],);
    }
    Ok(())
}

#[test]
fn field_maps_prepare_child_keys_without_calling_a_root_method() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let child = converting(|_, arguments| {
        arguments
            .first()
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing map child key"))
    });
    let fields = FieldMap::from([
        (
            "toJSON".into(),
            FieldFunction::contextual({
                let calls = calls.clone();
                move |_, _| {
                    let _ = calls.fetch_add(1, Ordering::SeqCst);
                    Ok("root".into())
                }
            })
            .into(),
        ),
        ("child".into(), child),
    ]);
    assert_eq!(
        serde_json::Value::Object(fields.json()?),
        serde_json::json!({"child": "child"})
    );
    assert_eq!(
        crate::field_value::serde::map::serialize(&fields, serde_json::value::Serializer)?,
        serde_json::json!({"child": "child"})
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        FieldValue::from(fields).stringify()?,
        Some(r#""root""#.into())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn prepared_utf16_text_keeps_lone_surrogates_while_json_values_reject_them() -> AuthResult<()> {
    let value = converting(|_, _| Ok(Utf16String::from_units(vec![0xd800]).into()));
    assert_eq!(value.stringify()?, Some(r#""\ud800""#.into()));
    assert!(matches!(value.json(), Err(AuthError::Internal(message))
        if message.starts_with("JSON value cannot represent unpaired UTF-16 surrogates:")));
    Ok(())
}
