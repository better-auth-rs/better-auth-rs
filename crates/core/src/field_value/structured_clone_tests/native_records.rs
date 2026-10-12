//! Rust native clone contracts; these cases do not add upstream HTTP coverage.

use super::{Events, Source, poisoned};
use crate::{
    ApiKey, AuthError, AuthRecordFields, AuthResult, FieldDate, FieldMap, FieldObject, FieldValue,
    FromFieldMap, Passkey, SchemaValue, SessionView, StructuredCloneContext, UserView,
};
use std::sync::{Arc, Mutex};

fn observed(name: &'static str, fields: FieldMap, events: &Events) -> FieldValue {
    FieldValue::Object(FieldObject::from_source(Arc::new(Source {
        name,
        fields: Mutex::new(fields),
        events: events.clone(),
        on_read: Box::new(|_| Ok(())),
        target: None,
    })))
}

fn value(name: &'static str, events: &Events) -> FieldValue {
    observed(name, [("value".into(), name.into())].into(), events)
}

fn field<'a>(fields: &'a FieldMap, name: &str) -> AuthResult<&'a FieldValue> {
    fields
        .get(name)
        .ok_or_else(|| AuthError::internal(format!("Missing native clone field {name}")))
}

fn plugin_order<T: AuthRecordFields + FromFieldMap>(
    construct: impl FnOnce(FieldMap, FieldValue) -> AuthResult<T>,
    hidden_name: impl FnOnce(&T) -> FieldValue,
) -> AuthResult<()> {
    let events = Events::default();
    let extra = value("extra", &events);
    let hidden = observed(
        "hidden",
        [
            ("alias".into(), extra.clone()),
            ("value".into(), "hidden".into()),
        ]
        .into(),
        &events,
    );
    let shadow = observed("shadow", [("alias".into(), extra.clone())].into(), &events);
    let date = FieldDate::from_milliseconds(42.0);
    let record = construct(
        [
            ("extra".into(), extra.clone()),
            ("10".into(), value("10", &events)),
            ("2".into(), value("2", &events)),
            ("name".into(), hidden.clone()),
            ("createdAt".into(), date.clone().into()),
            ("id".into(), "plugin".into()),
        ]
        .into(),
        shadow,
    )?;
    let copied = record.structured_clone(&mut StructuredCloneContext::new())?;
    let fields = copied.field_values()?;
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["2", "10", "extra", "name", "createdAt", "id"]
    );
    assert_eq!(
        fields,
        FieldMap::from([
            (
                "2".into(),
                FieldMap::from([("value".into(), "2".into())]).into()
            ),
            (
                "10".into(),
                FieldMap::from([("value".into(), "10".into())]).into()
            ),
            (
                "extra".into(),
                FieldMap::from([("value".into(), "extra".into())]).into()
            ),
            (
                "name".into(),
                FieldMap::from([(
                    "alias".into(),
                    FieldMap::from([("value".into(), "extra".into())]).into(),
                )])
                .into(),
            ),
            ("createdAt".into(), date.clone().into()),
            ("id".into(), "plugin".into()),
        ])
    );
    let copied_extra = field(&fields, "extra")?;
    let copied_hidden = hidden_name(&copied);
    assert!(!copied_extra.strict_equals(&extra));
    assert!(!copied_hidden.strict_equals(&hidden));
    assert!(!field(&fields, "createdAt")?.strict_equals(&date.into()));
    assert!(
        field(&fields, "name")?
            .model_property("alias")?
            .strict_equals(copied_extra)
    );
    assert!(
        copied_hidden
            .model_property("alias")?
            .strict_equals(copied_extra)
    );
    assert_eq!(copied_hidden.model_property("value")?, "hidden".into());
    assert_eq!(
        *events.lock().map_err(poisoned)?,
        [
            "keys:2",
            "get:2.value",
            "keys:10",
            "get:10.value",
            "keys:extra",
            "get:extra.value",
            "keys:shadow",
            "get:shadow.alias",
            "keys:hidden",
            "get:hidden.alias",
            "get:hidden.value",
        ]
    );
    Ok(())
}

#[test]
fn plugin_clones_visit_numeric_and_visible_order_before_shadowed_native_slots() -> AuthResult<()> {
    plugin_order(
        |fields, shadow| {
            let mut key = ApiKey::from_field_values(fields)?;
            let _ = key.additional_fields.insert("name".into(), shadow);
            Ok(key)
        },
        |key| key.name.field_value(),
    )?;
    plugin_order(
        |fields, shadow| {
            let mut passkey = Passkey::from_field_values(fields)?;
            let _ = passkey.additional_fields.insert("name".into(), shadow);
            Ok(passkey)
        },
        |passkey| passkey.name.field_value(),
    )
}

#[test]
fn plugin_clones_preserve_explicit_dynamic_and_nested_typed_variants() -> AuthResult<()> {
    macro_rules! check {
        ($model:ty, $nested:ident, $property:literal) => {{
            let date = FieldDate::from_milliseconds(123.0);
            let mut record = <$model>::from_field_values(FieldMap::from([
                ("id".into(), "plugin".into()),
                ("name".into(), FieldValue::Undefined),
                ($property.into(), date.clone().into()),
                ("alias".into(), date.clone().into()),
            ]))?;
            record.id = SchemaValue::Dynamic("plugin".into());
            record.name = SchemaValue::Dynamic(FieldValue::Undefined);
            record.$nested = SchemaValue::Typed(Some(date.clone()));
            let copied = record.structured_clone(&mut StructuredCloneContext::new())?;
            assert!(matches!(&copied.id, SchemaValue::Dynamic(FieldValue::String(value)) if value == "plugin"));
            assert!(matches!(&copied.name, SchemaValue::Dynamic(FieldValue::Undefined)));
            assert!(matches!(&copied.$nested, SchemaValue::Typed(Some(_))));
            assert!(copied.updated_at.is_undefined());
            let fields = copied.field_values()?;
            assert_eq!(fields.keys().map(String::as_str).collect::<Vec<_>>(), ["id", "name", $property, "alias"]);
            assert_eq!(field(&fields, "name")?, &FieldValue::Undefined);
            assert!(field(&fields, $property)?.strict_equals(field(&fields, "alias")?));
            assert!(!field(&fields, $property)?.strict_equals(&date.into()));
            assert_eq!(fields, record.field_values()?);
        }};
    }
    check!(ApiKey, last_request, "lastRequest");
    check!(Passkey, created_at, "createdAt");
    Ok(())
}

fn hidden_retry<T: AuthRecordFields + FromFieldMap>(
    construct: impl Fn(FieldMap, FieldValue) -> AuthResult<T>,
    recover: impl Fn(&mut T, FieldValue),
    hidden_value: impl Fn(&T) -> FieldValue,
) -> AuthResult<()> {
    for getter_failure in [false, true] {
        let events = Events::default();
        let visible = observed("visible", [("value".into(), 1.into())].into(), &events);
        let message = "hidden-native-clone-original".to_owned();
        let allocation = message.as_ptr() as usize;
        let failure = Arc::new(Mutex::new(Some(AuthError::Internal(message))));
        let hidden = if getter_failure {
            FieldValue::Object(FieldObject::from_source(Arc::new(Source {
                name: "hidden",
                fields: Mutex::new([("value".into(), 1.into())].into()),
                events: events.clone(),
                on_read: Box::new(move |_| {
                    Err(failure.lock().map_err(poisoned)?.take().ok_or_else(|| {
                        AuthError::internal("Repeated hidden native clone failure")
                    })?)
                }),
                target: None,
            })))
        } else {
            crate::FieldFunction::contextual(|_, _| {
                Err(AuthError::internal(
                    "Native cloning must not invoke functions",
                ))
            })
            .into()
        };
        let date = FieldDate::from_milliseconds(42.0);
        let mut context = StructuredCloneContext::new();
        let previous = context.clone_value(&date.clone().into())?;
        let mut record = construct(
            [
                ("extra".into(), visible.clone()),
                ("createdAt".into(), date.into()),
                ("id".into(), "owner".into()),
            ]
            .into(),
            hidden,
        )?;
        let property_order = record.field_values()?.keys().cloned().collect::<Vec<_>>();
        let rejected = record.structured_clone(&mut context);
        let mut failed_events = vec!["keys:visible", "get:visible.value"];
        if getter_failure {
            failed_events.extend(["keys:hidden", "get:hidden.value"]);
            assert!(
                matches!(rejected, Err(AuthError::Internal(message)) if message == "hidden-native-clone-original" && message.as_ptr() as usize == allocation)
            );
        } else {
            assert!(matches!(rejected, Err(AuthError::DataClone)));
        }
        assert_eq!(*events.lock().map_err(poisoned)?, failed_events);
        let source = visible
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected live visible object"))?;
        source.set("value", 2.into())?;
        recover(
            &mut record,
            observed(
                "recovered",
                [("alias".into(), visible.clone())].into(),
                &events,
            ),
        );
        events.lock().map_err(poisoned)?.clear();
        let copied = record.structured_clone(&mut context)?;
        let fields = copied.field_values()?;
        let copied_visible = field(&fields, "extra")?;
        assert_eq!(copied_visible.model_property("value")?, 2.into());
        assert!(!copied_visible.strict_equals(&visible));
        assert!(
            hidden_value(&copied)
                .model_property("alias")?
                .strict_equals(copied_visible)
        );
        assert!(field(&fields, "createdAt")?.strict_equals(&previous));
        assert_eq!(fields.keys().cloned().collect::<Vec<_>>(), property_order);
        assert_eq!(
            *events.lock().map_err(poisoned)?,
            [
                "keys:visible",
                "get:visible.value",
                "keys:recovered",
                "get:recovered.alias"
            ]
        );
        source.set("value", 3.into())?;
        assert_eq!(copied_visible.model_property("value")?, 2.into());
    }
    Ok(())
}

#[test]
fn hidden_native_failure_rolls_back_visible_memo_before_same_context_retry() -> AuthResult<()> {
    hidden_retry(
        |fields, hidden| {
            let mut user = UserView::from_field_values(fields)?;
            user.metadata = hidden;
            Ok(user)
        },
        |user, value| user.metadata = value,
        |user| user.metadata.clone(),
    )?;
    hidden_retry(
        |fields, hidden| {
            let mut key = ApiKey::from_field_values(fields)?;
            key.name = SchemaValue::Dynamic(hidden);
            let _ = key.additional_fields.insert("name".into(), "public".into());
            Ok(key)
        },
        |key, value| key.name = SchemaValue::Dynamic(value),
        |key| key.name.field_value(),
    )?;
    hidden_retry(
        |fields, hidden| {
            let mut passkey = Passkey::from_field_values(fields)?;
            passkey.name = SchemaValue::Dynamic(hidden);
            let _ = passkey
                .additional_fields
                .insert("name".into(), "public".into());
            Ok(passkey)
        },
        |passkey, value| passkey.name = SchemaValue::Dynamic(value),
        |passkey| passkey.name.field_value(),
    )
}

#[test]
fn session_clone_keeps_enumerable_active_separate_from_private_liveness() -> AuthResult<()> {
    for active in [false, true] {
        let events = Events::default();
        let extra = value("extra", &events);
        let mut session = SessionView::from_field_values(
            [
                ("extra".into(), extra.clone()),
                ("10".into(), value("10", &events)),
                ("2".into(), value("2", &events)),
                ("token".into(), value("hidden", &events)),
                ("id".into(), "session".into()),
            ]
            .into(),
        )?;
        session.active = active;
        let _ = session
            .additional_fields
            .insert("token".into(), value("public", &events));
        let _ = session.additional_fields.insert(
            "active".into(),
            observed("active", [("alias".into(), extra.clone())].into(), &events),
        );
        let copied = session.structured_clone(&mut StructuredCloneContext::new())?;
        assert_eq!(copied.active, active);
        assert_eq!(copied.visible_fields, session.visible_fields);
        let fields = FieldMap::from(copied.clone());
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["2", "10", "extra", "token", "id", "active"]
        );
        assert_eq!(
            field(&fields, "token")?.model_property("value")?,
            "public".into()
        );
        assert_eq!(
            copied.token.field_value().model_property("value")?,
            "hidden".into()
        );
        assert!(
            field(&fields, "active")?
                .model_property("alias")?
                .strict_equals(field(&fields, "extra")?)
        );
        assert!(!field(&fields, "extra")?.strict_equals(&extra));
        assert_eq!(
            serde_json::to_value(&copied)?,
            serde_json::json!({
                "2": {"value": "2"}, "10": {"value": "10"},
                "extra": {"value": "extra"}, "token": {"value": "public"},
                "id": "session", "active": {"alias": {"value": "extra"}},
            })
        );
        assert_eq!(
            *events.lock().map_err(poisoned)?,
            [
                "keys:2",
                "get:2.value",
                "keys:10",
                "get:10.value",
                "keys:extra",
                "get:extra.value",
                "keys:public",
                "get:public.value",
                "keys:active",
                "get:active.alias",
                "keys:hidden",
                "get:hidden.value",
            ]
        );
    }
    Ok(())
}
