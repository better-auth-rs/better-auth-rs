//! Replay the frozen source transitions through the shared object and array property boundary.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "Frozen successful source observations define complete states and callback arguments."
)]

use crate::native_test_observation::assert_replay;
use crate::{
    AuthError, AuthResult, FieldFunction, FieldMap, FieldProperty, FieldPropertyDefinition,
    FieldPropertyDescriptor, FieldPropertyUpdate, FieldValue,
};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

#[path = "native_property_graph.rs"]
mod graph;

struct Transition<'a> {
    expected: &'a Json,
    path: String,
    states: usize,
    graph: graph::PropertyGraph,
    events: Arc<Mutex<Vec<Json>>>,
}

impl<'a> Transition<'a> {
    fn new(expected: &'a Json, index: usize) -> Self {
        Self {
            expected,
            path: format!("/cases/{index}"),
            states: 0,
            graph: graph::PropertyGraph::default(),
            events: Arc::default(),
        }
    }

    fn record(&mut self, phase: &str, value: &FieldValue, result: bool) -> AuthResult<()> {
        let state = &self.expected["states"][self.states];
        assert_eq!(state["phase"], phase, "{}: state order", self.path);
        assert_eq!(state["result"], result, "{}: operation result", self.path);
        self.graph.assert_snapshot(
            value,
            &state["graph"],
            &format!("{}/states/{}/graph", self.path, self.states),
        )?;
        self.states += 1;
        Ok(())
    }

    fn finish(self) -> Vec<String> {
        assert_eq!(
            self.states,
            self.expected["states"].as_array().unwrap().len()
        );
        assert_replay(
            &json!(*self.events.lock().unwrap()),
            &self.expected["events"],
            &format!("{}/events", self.path),
        );
        self.graph.finish(
            &self.expected["functions"],
            &format!("{}/functions", self.path),
        )
    }
}

fn object<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldValue {
    FieldMap::from(fields.map(|(name, value)| (name.into(), value))).into()
}

fn accessor(
    get: Option<Option<FieldFunction>>,
    set: Option<Option<FieldFunction>>,
) -> FieldPropertyDefinition {
    FieldPropertyDefinition {
        property: FieldPropertyUpdate::Accessor { get, set },
        ..FieldPropertyDefinition::default()
    }
}

fn defaults(harness: &mut Transition<'_>) -> AuthResult<()> {
    let value = object([]);
    let defined = value.define_own_property("value", FieldPropertyDefinition::default())?;
    harness.record("default", &value, defined)?;
    assert!(!value.set_property("value", 1.into())?);
    assert!(!value.delete_property("value")?);
    let redefined = value.define_own_property(
        "value",
        FieldPropertyDefinition {
            configurable: Some(true),
            ..Default::default()
        },
    )?;
    harness.record("rejected-mutations", &value, redefined)?;
    let same = value.define_own_property(
        "value",
        FieldPropertyDefinition::value(FieldValue::Undefined),
    )?;
    harness.record("same-undefined", &value, same)
}

fn same_value(harness: &mut Transition<'_>, before: f64, replacement: f64) -> AuthResult<()> {
    let value = object([]);
    assert!(value.define_own_property("value", FieldPropertyDefinition::value(before.into()))?);
    let result =
        value.define_own_property("value", FieldPropertyDefinition::value(replacement.into()))?;
    assert!(value.model_property("value")?.same_value(&before.into()));
    harness.record("redefine", &value, result)?;
    harness.record(
        "zero-sign",
        &object([(
            "negative",
            value
                .model_property("value")?
                .same_value(&(-0.0).into())
                .into(),
        )]),
        true,
    )
}

fn replacement(harness: &mut Transition<'_>) -> AuthResult<()> {
    let value = object([("value", 1.into())]);
    let events = harness.events.clone();
    let get = FieldFunction::contextual(move |receiver, arguments| {
        assert!(arguments.is_empty());
        events.lock().unwrap().push(json!("get"));
        receiver.model_property("marker")
    });
    let result = value.define_own_property("value", accessor(Some(Some(get.clone())), None))?;
    harness.record(
        "accessor",
        &object([("object", value.clone()), ("get", get.into())]),
        result,
    )?;
    let receiver = object([("marker", 9.into())]);
    assert_eq!(
        value.get_property_with_receiver("value", &receiver)?,
        9.into()
    );
    let result = value.set_property("value", 2.into())?;
    harness.record("getter-only", &value, result)?;
    let result = value.define_own_property("value", FieldPropertyDefinition::value(3.into()))?;
    harness.record("data", &value, result)?;
    assert!(!value.set_property("value", 4.into())?);
    Ok(())
}

fn receiver_and_errors(harness: &mut Transition<'_>) -> AuthResult<()> {
    let failure = object([("original", true.into())]);
    let receiver = object([("marker", "receiver".into())]);
    let value = object([]);
    let events = harness.events.clone();
    let expected = receiver.clone();
    let get = FieldFunction::contextual(move |receiver, arguments| {
        assert!(arguments.is_empty());
        events
            .lock()
            .unwrap()
            .push(json!(["get", receiver.strict_equals(&expected)]));
        receiver.model_property("marker")
    });
    let events = harness.events.clone();
    let expected = receiver.clone();
    let original = failure.clone();
    let set = FieldFunction::contextual(move |receiver, arguments| {
        assert_eq!(arguments.len(), 1);
        let value = &arguments[0];
        events.lock().unwrap().push(json!([
            "set",
            receiver.strict_equals(&expected),
            value.json()?
        ]));
        receiver.set_model_property("changed", value.clone())?;
        if value == &FieldValue::from("failure") {
            return Err(AuthError::from_thrown(original.clone()));
        }
        Ok(FieldValue::Undefined)
    });
    let result = value.define_own_property(
        "value",
        FieldPropertyDescriptor {
            enumerable: true,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(get.clone()),
                set: Some(set.clone()),
            },
        }
        .into(),
    )?;
    harness.record(
        "defined",
        &object([
            ("object", value.clone()),
            ("get", get.into()),
            ("set", set.into()),
        ]),
        result,
    )?;
    assert_eq!(
        value.get_property_with_receiver("value", &receiver)?,
        "receiver".into()
    );
    assert!(value.set_property_with_receiver("value", "changed".into(), &receiver)?);
    let caught = value
        .set_property_with_receiver("value", "failure".into(), &receiver)
        .unwrap_err()
        .into_thrown_value()?;
    assert!(caught.strict_equals(&failure));
    harness.record(
        "setter-failure",
        &object([
            ("object", value.clone()),
            ("receiver", receiver),
            ("failure", failure),
            ("caught", caught),
        ]),
        false,
    )?;
    let result = value.delete_property("value")?;
    harness.record("delete-without-get", &value, result)
}

fn fixed_accessor(harness: &mut Transition<'_>) -> AuthResult<()> {
    let events = harness.events.clone();
    let get = FieldFunction::contextual(move |_, arguments| {
        assert!(arguments.is_empty());
        events.lock().unwrap().push(json!("unexpected-get"));
        Ok(7.into())
    });
    let value = object([]);
    assert!(value.define_own_property("value", accessor(Some(Some(get.clone())), None))?);
    let result = value.define_own_property("value", accessor(Some(Some(get.clone())), None))?;
    harness.record(
        "same-getter",
        &object([("object", value.clone()), ("get", get.into())]),
        result,
    )?;
    assert!(!value.define_own_property("value", accessor(Some(None), None))?);
    assert!(!value.define_own_property("value", FieldPropertyDefinition::value(7.into()))?);
    let result = value.delete_property("value")?;
    harness.record("rejected", &value, result)
}

fn partial_array(harness: &mut Transition<'_>, writable: bool) -> AuthResult<()> {
    let value = FieldValue::from(vec![0.into(), 1.into(), 2.into(), 3.into()]);
    assert!(value.define_own_property(
        "2",
        FieldPropertyDefinition {
            configurable: Some(false),
            ..Default::default()
        }
    )?);
    harness.record("before", &value, true)?;
    let result = value.define_own_property(
        "length",
        FieldPropertyDefinition {
            property: FieldPropertyUpdate::Data {
                value: Some(0.into()),
                writable: Some(writable),
            },
            ..Default::default()
        },
    )?;
    harness.record("partial-deletion", &value, result)?;
    let result = value.define_own_property("4", FieldPropertyDescriptor::data(4.into()).into())?;
    harness.record("extend", &value, result)
}

fn array_accessor(harness: &mut Transition<'_>) -> AuthResult<()> {
    let value = FieldValue::from(vec![0.into(), 1.into(), 2.into()]);
    let events = harness.events.clone();
    let get = FieldFunction::contextual(move |_, arguments| {
        assert!(arguments.is_empty());
        events.lock().unwrap().push(json!("unexpected-get"));
        Ok(2.into())
    });
    assert!(value.define_own_property(
        "2",
        FieldPropertyDefinition {
            configurable: Some(true),
            ..accessor(Some(Some(get)), None)
        }
    )?);
    harness.record("before", &value, true)?;
    let result = value.define_own_property("length", FieldPropertyDefinition::value(1.into()))?;
    harness.record("after", &value, result)
}

#[test]
fn property_transitions_match_frozen_source_descriptors_events_and_native_identities()
-> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../fixtures/native-property-transition-1.7.6.json"
    ))?;
    let coverage: Json = serde_json::from_str(include_str!(
        "../fixtures/native-property-transition-1.7.6.coverage.json"
    ))?;
    let mut unpaired = Vec::new();
    for (index, expected) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let mut harness = Transition::new(expected, index);
        match expected["name"].as_str().unwrap() {
            "new-property-defaults-and-redefinition" => defaults(&mut harness)?,
            "same-value-nan" => same_value(&mut harness, f64::NAN, f64::NAN)?,
            "same-value-positive-zero" => same_value(&mut harness, 0.0, -0.0)?,
            "same-value-negative-zero" => same_value(&mut harness, -0.0, 0.0)?,
            "data-accessor-data-replacement" => replacement(&mut harness)?,
            "accessor-receiver-errors-and-delete" => receiver_and_errors(&mut harness)?,
            "nonconfigurable-accessor-redefinition" => fixed_accessor(&mut harness)?,
            "array-length-partial-failure-true" => partial_array(&mut harness, true)?,
            "array-length-partial-failure-false" => partial_array(&mut harness, false)?,
            "array-accessor-shrink-does-not-read-getters" => array_accessor(&mut harness)?,
            name => panic!("Unimplemented frozen property transition: {name}"),
        }
        unpaired.extend(harness.finish());
    }
    assert_replay(
        &json!(unpaired),
        &coverage["unpairedPaths"],
        "/coverage/unpairedPaths",
    );
    Ok(())
}
