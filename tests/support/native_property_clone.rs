//! Replay clone selection against complete frozen source graphs and callback events.

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "Frozen source observations define the complete fixture shapes, native callbacks, and operation results."
)]

use crate::field_value::ContainerIdentity;
use crate::native_test_observation::assert_replay;
use crate::{
    AuthError, AuthResult, FieldArray, FieldFunction, FieldMap, FieldObject, FieldProperty,
    FieldPropertyDefinition, FieldPropertyDescriptor, FieldValue, StructuredCloneContext,
};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

use crate::native_property_graph as graph;
#[path = "native_property_clone/source.rs"]
mod source;

type Events = Arc<Mutex<Vec<Json>>>;

fn identity(value: &FieldValue) -> ContainerIdentity {
    match value {
        FieldValue::Object(value) => ContainerIdentity::Object(value.identity()),
        FieldValue::Array(value) => ContainerIdentity::Array(value.identity()),
        _ => panic!("The source fixture target must be an object or array"),
    }
}

fn getter(
    target: &FieldValue,
    key: &'static str,
    phase: String,
    enumerable: bool,
    events: Events,
    read: impl Fn() -> AuthResult<FieldValue> + Send + Sync + 'static,
) -> AuthResult<()> {
    let expected = identity(target);
    target.define_model_property(
        key,
        FieldPropertyDescriptor {
            enumerable,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(FieldFunction::contextual(move |receiver, arguments| {
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push(json!({
                        "phase": phase,
                        "sameReceiver": identity(receiver) == expected,
                    }));
                    read()
                })),
                set: None,
            },
        }
        .into(),
    )
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    DeleteInherited,
    HideLater,
    ShowHidden,
    ThrowOriginal,
    HiddenStatic,
    FillHole,
    Grow,
    Shrink,
}

impl Mode {
    fn parse(value: &str) -> Self {
        match value {
            "delete-inherited" => Self::DeleteInherited,
            "hide-later" => Self::HideLater,
            "show-hidden" => Self::ShowHidden,
            "throw-original" => Self::ThrowOriginal,
            "hidden-static" => Self::HiddenStatic,
            "fill-hole" => Self::FillHole,
            "grow" => Self::Grow,
            "shrink" => Self::Shrink,
            _ => panic!("Unknown frozen clone mode: {value}"),
        }
    }
}

fn inherited_getter(source: &source::Source, key: &'static str, events: Events) -> AuthResult<()> {
    let expected = identity(&source.value());
    assert!(
        source.inherited.define_own_property(
            key,
            FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(FieldFunction::contextual(move |receiver, arguments| {
                        assert!(arguments.is_empty());
                        events.lock().unwrap().push(json!({
                            "phase": format!("get:inherited:{key}"),
                            "sameReceiver": identity(receiver) == expected,
                        }));
                        Ok("inherited-value".into())
                    })),
                    set: None,
                },
            }
            .into(),
        )?
    );
    Ok(())
}

struct Scenario {
    source: Arc<source::Source>,
    original: FieldValue,
    snapshot: FieldValue,
    events: Events,
}

impl Scenario {
    fn new(expected: &Json) -> AuthResult<Self> {
        let kind = expected["kind"].as_str().unwrap();
        assert!(matches!(kind, "object" | "array"));
        let mode_name = expected["mode"].as_str().unwrap();
        let mode = Mode::parse(mode_name);
        assert_eq!(expected["name"], format!("{kind}-{mode_name}"));
        let array = kind == "array";
        let source = source::Source::new(array);
        let root = source.value();
        let child: FieldValue = FieldMap::new().into();
        let original: FieldValue = FieldMap::from([
            ("failure".into(), format!("{kind}-{mode_name}").into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let events = Events::default();
        let [first, later, tail] = if array {
            ["0", "1", "2"]
        } else {
            ["first", "later", "tail"]
        };
        let returned = child.clone();
        getter(
            &root,
            first,
            format!("get:root:{first}"),
            true,
            events.clone(),
            move || Ok(returned.clone()),
        )?;
        if !matches!(mode, Mode::FillHole) {
            getter(
                &root,
                later,
                format!("get:root:{later}"),
                !matches!(mode, Mode::ShowHidden | Mode::HiddenStatic),
                events.clone(),
                || Ok("later-value".into()),
            )?;
        }
        getter(
            &root,
            tail,
            format!("get:root:{tail}"),
            true,
            events.clone(),
            || Ok("tail-value".into()),
        )?;
        let original_error = original.clone();
        let retained = Arc::downgrade(&source);
        let observed = events.clone();
        getter(
            &child,
            "mutate",
            "get:child:mutate".into(),
            true,
            events.clone(),
            move || {
                let source = retained.upgrade().unwrap();
                let root = source.value();
                root.set_model_property("mutation", "retained".into())?;
                match mode {
                    Mode::DeleteInherited => {
                        assert!(root.delete_property(later)?);
                        inherited_getter(&source, later, observed.clone())?;
                    }
                    Mode::HideLater | Mode::ShowHidden => root.define_model_property(
                        later,
                        FieldPropertyDefinition {
                            enumerable: Some(matches!(mode, Mode::ShowHidden)),
                            ..Default::default()
                        },
                    )?,
                    Mode::ThrowOriginal => {
                        return Err(AuthError::from_thrown(original_error.clone()));
                    }
                    Mode::FillHole => getter(
                        &root,
                        later,
                        format!("get:root:{later}"),
                        true,
                        observed.clone(),
                        || Ok("inserted-value".into()),
                    )?,
                    Mode::Grow => getter(
                        &root,
                        "3",
                        "get:root:3".into(),
                        true,
                        observed.clone(),
                        || Ok("grown-value".into()),
                    )?,
                    Mode::Shrink => root.set_model_property("length", 1.into())?,
                    Mode::HiddenStatic => {
                        assert!(!root.own_property_descriptor(later)?.unwrap().enumerable);
                    }
                }
                Ok("child-value".into())
            },
        )?;
        let snapshot = FieldMap::from([
            ("root".into(), root),
            ("inherited".into(), source.inherited.clone().into()),
            ("original".into(), original.clone()),
        ])
        .into();
        Ok(Self {
            source,
            original,
            snapshot,
            events,
        })
    }

    fn replay(&self, expected: &Json, index: usize) -> AuthResult<Vec<String>> {
        let path = format!("/cases/{index}");
        let mut graph = graph::PropertyGraph::default();
        graph.assert_snapshot(
            &self.snapshot,
            &expected["before"],
            &format!("{path}/before"),
        )?;
        assert!(self.events.lock().unwrap().is_empty());
        let root = self.source.value();
        let outcome = &expected["outcome"];
        match StructuredCloneContext::new().clone_value(&root) {
            Ok(copy) => {
                assert_eq!(outcome["returned"], true, "{path}");
                assert_eq!(outcome.as_object().unwrap().len(), 2, "{path}");
                assert!(!copy.strict_equals(&root));
                graph.assert_snapshot(
                    &copy,
                    &outcome["result"],
                    &format!("{path}/outcome/result"),
                )?;
            }
            Err(error) => {
                assert_eq!(outcome["returned"], false, "{path}");
                assert_eq!(outcome.as_object().unwrap().len(), 3, "{path}");
                let thrown = error.into_thrown_value()?;
                assert_eq!(
                    outcome["sameOriginal"],
                    thrown.strict_equals(&self.original),
                    "{path}"
                );
                graph.assert_snapshot(
                    &thrown,
                    &outcome["error"],
                    &format!("{path}/outcome/error"),
                )?;
            }
        }
        graph.assert_snapshot(&self.snapshot, &expected["after"], &format!("{path}/after"))?;
        assert_eq!(root.model_property("mutation")?, "retained".into());
        assert_replay(
            &json!(*self.events.lock().unwrap()),
            &expected["events"],
            &format!("{path}/events"),
        );
        Ok(graph.finish(Some(&expected["functions"]), &format!("{path}/functions")))
    }
}

fn replay_fixture(fixture: &str, coverage: &str, names: &[&str]) -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(fixture)?;
    let coverage: Json = serde_json::from_str(coverage)?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), names.len());
    let mut unpaired = Vec::new();
    for (index, (expected, name)) in cases.iter().zip(names).enumerate() {
        assert_eq!(expected["name"], *name);
        unpaired.extend(Scenario::new(expected)?.replay(expected, index)?);
    }
    assert_replay(
        &json!(unpaired),
        &coverage["unpairedPaths"],
        "/coverage/unpairedPaths",
    );
    Ok(())
}

#[test]
fn property_clone_matches_frozen_source_graphs_errors_and_getter_schedule() -> AuthResult<()> {
    replay_fixture(
        include_str!("../fixtures/native-property-clone-1.7.6.json"),
        include_str!("../fixtures/native-property-clone-1.7.6.coverage.json"),
        &[
            "object-delete-inherited",
            "object-hide-later",
            "object-show-hidden",
            "object-throw-original",
            "array-delete-inherited",
            "array-hide-later",
            "array-show-hidden",
            "array-throw-original",
        ],
    )
}

#[test]
fn property_clone_matches_frozen_source_array_boundaries() -> AuthResult<()> {
    replay_fixture(
        include_str!("../fixtures/native-property-clone-array-boundaries-1.7.6.json"),
        include_str!("../fixtures/native-property-clone-array-boundaries-1.7.6.coverage.json"),
        &[
            "array-hidden-static",
            "array-fill-hole",
            "array-grow",
            "array-shrink",
        ],
    )
}
