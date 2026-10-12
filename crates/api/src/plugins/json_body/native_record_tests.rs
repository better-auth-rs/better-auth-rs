#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify record admission, getter order, and original error identity."
)]

use super::{native_object, native_record};
use better_auth_core::{
    AuthError, AuthResult, FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{FieldObjectSource, FieldPropertyDefinition, FieldPropertyDescriptor},
};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

struct Observed {
    label: &'static str,
    fields: FieldMap,
    inherited: FieldMap,
    hidden: Vec<&'static str>,
    failure: Option<&'static str>,
    sentinel: FieldValue,
    events: Events,
}

impl Observed {
    fn new(label: &'static str, fields: FieldMap, events: &Events) -> Self {
        Self {
            label,
            fields,
            inherited: FieldMap::new(),
            hidden: Vec::new(),
            failure: None,
            sentinel: FieldMap::new().into(),
            events: events.clone(),
        }
    }

    fn object(self) -> FieldObject {
        FieldObject::from_source(Arc::new(self))
    }

    fn record(&self, operation: &str) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Record events lock poisoned"))?
            .push(format!("{}:{operation}", self.label));
        if self.failure == Some(operation) {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        Ok(())
    }
}

impl FieldObjectSource for Observed {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.record("keys")?;
        FieldObject::from(self.fields.clone()).own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.record(&format!("descriptor:{name}"))?;
        Ok(self
            .fields
            .get(name)
            .cloned()
            .map(|value| FieldPropertyDescriptor {
                enumerable: !self.hidden.contains(&name),
                ..FieldPropertyDescriptor::data(value)
            }))
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        self.record(&format!("has:{name}"))?;
        Ok(self.fields.contains_key(name) || self.inherited.contains_key(name))
    }

    fn get_with_receiver(&self, name: &str, _: &FieldValue) -> AuthResult<Option<FieldValue>> {
        self.record(&format!("get:{name}"))?;
        Ok(self
            .fields
            .get(name)
            .or_else(|| self.inherited.get(name))
            .cloned())
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::type_error("The record input is read-only"))
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::type_error("The record input is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::type_error("The record input is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Record validation must not snapshot the input",
        ))
    }

    fn identity(&self) -> usize {
        self as *const Self as usize
    }
}

fn events(trace: &Events) -> AuthResult<Vec<String>> {
    Ok(trace
        .lock()
        .map_err(|_| AuthError::internal("Record events lock poisoned"))?
        .clone())
}

fn constructor(properties: FieldObject) -> FieldValue {
    FieldFunction::contextual_with_properties(
        |_, _| {
            Err(AuthError::internal(
                "Record validation must not call constructors",
            ))
        },
        properties,
    )
    .into()
}

#[test]
fn skips_proto_before_descriptors_and_preserves_native_leaf_identity() -> AuthResult<()> {
    let child: FieldValue = FieldMap::from([("value".into(), 1.into())]).into();
    for forbidden in ["descriptor:__proto__", "get:__proto__", "get:hidden"] {
        let trace = Events::default();
        let mut source = Observed::new(
            "record",
            FieldMap::from([
                ("__proto__".into(), FieldValue::Null),
                ("child".into(), child.clone()),
                ("missing".into(), FieldValue::Undefined),
                ("hidden".into(), "unread".into()),
            ]),
            &trace,
        );
        source.hidden.push("hidden");
        source.failure = Some(forbidden);
        let output = native_record(&FieldValue::Object(source.object()))?
            .ok_or_else(|| AuthError::internal("Expected record output"))?;
        assert_eq!(
            output.keys().map(String::as_str).collect::<Vec<_>>(),
            ["child", "missing"]
        );
        assert!(
            output
                .get("child")
                .is_some_and(|value| value.strict_equals(&child))
        );
        assert_eq!(output.get("missing"), Some(&FieldValue::Undefined));
        assert_eq!(
            events(&trace)?,
            [
                "record:get:constructor",
                "record:keys",
                "record:descriptor:child",
                "record:get:child",
                "record:descriptor:missing",
                "record:get:missing",
                "record:descriptor:hidden",
            ]
        );
    }
    Ok(())
}

#[test]
fn constructor_checks_own_prototype_property_without_reading_its_getter() -> AuthResult<()> {
    for own in [false, true] {
        let trace = Events::default();
        let mut prototype = Observed::new("prototype", FieldMap::new(), &trace);
        prototype.failure = Some("get:isPrototypeOf");
        prototype.hidden.push("isPrototypeOf");
        let fields = if own {
            &mut prototype.fields
        } else {
            &mut prototype.inherited
        };
        let _ = fields.insert("isPrototypeOf".into(), FieldValue::Undefined);
        let constructor = constructor(
            Observed::new(
                "constructor",
                FieldMap::from([("prototype".into(), FieldValue::Object(prototype.object()))]),
                &trace,
            )
            .object(),
        );
        let mut record = Observed::new(
            "record",
            FieldMap::from([("value".into(), 1.into())]),
            &trace,
        );
        let _ = record.inherited.insert("constructor".into(), constructor);
        let output = native_record(&FieldValue::Object(record.object()))?;
        assert_eq!(
            output,
            own.then(|| FieldMap::from([("value".into(), 1.into())]))
        );
        let mut expected = vec![
            "record:get:constructor",
            "constructor:get:prototype",
            "prototype:descriptor:isPrototypeOf",
        ];
        if own {
            expected.extend(["record:keys", "record:descriptor:value", "record:get:value"]);
        }
        assert_eq!(events(&trace)?, expected);
    }
    Ok(())
}

#[test]
fn getter_descriptor_and_enumeration_errors_keep_identity_and_stop_in_order() -> AuthResult<()> {
    let expected = [
        "record:get:constructor",
        "constructor:get:prototype",
        "prototype:descriptor:isPrototypeOf",
        "record:keys",
        "record:descriptor:value",
        "record:get:value",
    ];
    for (index, (label, operation)) in [
        ("record", "get:constructor"),
        ("constructor", "get:prototype"),
        ("prototype", "descriptor:isPrototypeOf"),
        ("record", "keys"),
        ("record", "descriptor:value"),
        ("record", "get:value"),
    ]
    .into_iter()
    .enumerate()
    {
        let trace = Events::default();
        let sentinel: FieldValue = FieldMap::from([("failure".into(), operation.into())]).into();
        let observed = |name, fields| {
            let mut source = Observed::new(name, fields, &trace);
            source.failure = (name == label).then_some(operation);
            source.sentinel = sentinel.clone();
            source
        };
        let prototype = observed(
            "prototype",
            FieldMap::from([("isPrototypeOf".into(), true.into())]),
        );
        let constructor = constructor(
            observed(
                "constructor",
                FieldMap::from([("prototype".into(), FieldValue::Object(prototype.object()))]),
            )
            .object(),
        );
        let mut record = observed("record", FieldMap::from([("value".into(), 1.into())]));
        let _ = record.inherited.insert("constructor".into(), constructor);
        let error = native_record(&FieldValue::Object(record.object()))
            .err()
            .ok_or_else(|| AuthError::internal("Expected the original record failure"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&sentinel))
        );
        assert_eq!(
            events(&trace)?,
            expected.iter().take(index + 1).copied().collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn rejects_nonrecord_values_and_nonobject_function_prototypes() -> AuthResult<()> {
    let invalid = [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        4.into(),
        "text".into(),
        Vec::<FieldValue>::new().into(),
        constructor(FieldMap::new().into()),
    ];
    for value in invalid {
        assert!(!native_object(&value));
        assert!(native_record(&value)?.is_none());
        let record: FieldValue = FieldMap::from([(
            "constructor".into(),
            constructor(FieldMap::from([("prototype".into(), value)]).into()),
        )])
        .into();
        assert!(native_record(&record)?.is_none());
    }
    Ok(())
}

#[test]
fn modified_date_constructor_distinguishes_absence_from_explicit_undefined() -> AuthResult<()> {
    for constructor in [
        None,
        Some(FieldValue::Undefined),
        Some(FieldValue::Null),
        Some(0.into()),
    ] {
        let trace = Events::default();
        let mut fields = FieldMap::from([("value".into(), 1.into())]);
        if let Some(value) = &constructor {
            let _ = fields.insert("constructor".into(), value.clone());
        }
        let value: FieldValue = FieldDate::from_milliseconds_with_properties(
            0.0,
            Observed::new("date", fields, &trace).object(),
        )
        .into();
        assert!(native_object(&value));
        let output = native_record(&value)?;
        assert_eq!(output.is_some(), constructor.is_some());
        let mut expected = vec!["date:get:constructor"];
        if constructor.as_ref().is_none_or(FieldValue::is_undefined) {
            expected.push("date:has:constructor");
        }
        if constructor.is_some() {
            expected.extend([
                "date:keys",
                "date:descriptor:value",
                "date:get:value",
                "date:descriptor:constructor",
                "date:get:constructor",
            ]);
        }
        assert_eq!(events(&trace)?, expected);
    }
    assert!(native_record(&FieldDate::invalid().into())?.is_none());
    Ok(())
}
