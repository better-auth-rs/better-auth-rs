//! Inspect shared descriptors without invoking getters or converting native identities.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "Frozen graphs define complete descriptors, native aliases, and callback identities."
)]

use crate::native_test_observation::{NativeObservation, assert_replay};
use crate::{AuthResult, FieldProperty, FieldValue};
use serde_json::{Value as Json, json};

#[derive(Default)]
pub(crate) struct PropertyGraph {
    observer: NativeObservation,
    unpaired: Vec<String>,
}

impl PropertyGraph {
    pub(crate) fn assert_snapshot(
        &mut self,
        actual: &FieldValue,
        expected: &Json,
        path: &str,
    ) -> AuthResult<()> {
        self.visit(actual, expected, path, &mut Vec::new())
    }

    fn visit(
        &mut self,
        actual: &FieldValue,
        expected: &Json,
        path: &str,
        identities: &mut Vec<(String, FieldValue)>,
    ) -> AuthResult<()> {
        if let Some(reference) = expected.get("reference").and_then(Json::as_str) {
            let (_, original) = identities
                .iter()
                .find(|(name, _)| name == reference)
                .expect("A graph reference must point to an observed native value");
            assert!(original.strict_equals(actual), "{path}: native alias");
            return Ok(());
        }
        let Some(identity) = expected.get("identity").and_then(Json::as_str) else {
            assert!(
                !matches!(
                    actual,
                    FieldValue::Object(_)
                        | FieldValue::Array(_)
                        | FieldValue::Function(_)
                        | FieldValue::Date(_)
                ),
                "{path}: source primitive became an object"
            );
            if let FieldValue::Number(number) = actual
                && number.is_finite()
            {
                // The source serializes finite numbers through JSON; zero sign has its own observation.
                assert_eq!(Some(*number), expected.as_f64(), "{path}: native number");
            } else {
                assert_replay(&self.observer.observe(actual)?, expected, path);
            }
            return Ok(());
        };
        assert!(
            !identities
                .iter()
                .any(|(_, value)| value.strict_equals(actual)),
            "{path}: distinct source identities must remain distinct"
        );
        identities.push((identity.into(), actual.clone()));
        let kind = match actual {
            FieldValue::Object(_) => "object",
            FieldValue::Array(_) => "array",
            FieldValue::Function(_) => "function",
            FieldValue::Date(_) => "date",
            _ => panic!("{path}: source object became a primitive"),
        };
        assert_eq!(expected["type"], kind, "{path}: native object kind");
        if kind == "function" {
            assert_replay(
                &self.observer.observe(actual)?,
                &expected["value"],
                &format!("{path}/value"),
            );
            self.unpaired
                .extend([format!("{path}/ownKeys"), format!("{path}/properties")]);
            return Ok(());
        }
        let keys = actual.own_property_keys()?;
        assert_replay(
            &json!(keys),
            &expected["ownKeys"],
            &format!("{path}/ownKeys"),
        );
        let properties = expected["properties"].as_array().unwrap();
        assert_eq!(keys.len(), properties.len(), "{path}: complete descriptors");
        for (index, (key, property)) in keys.iter().zip(properties).enumerate() {
            assert_eq!(property[0], *key, "{path}: descriptor order");
            let descriptor = actual.own_property_descriptor(key)?.unwrap();
            let expected = &property[1];
            let path = format!("{path}/properties/{index}/1");
            assert_eq!(expected["enumerable"], descriptor.enumerable, "{path}");
            assert_eq!(expected["configurable"], descriptor.configurable, "{path}");
            match descriptor.property {
                FieldProperty::Data { value, writable } => {
                    assert_eq!(expected.as_object().unwrap().len(), 4, "{path}: data slot");
                    assert_eq!(expected["writable"], writable, "{path}");
                    self.visit(
                        &value,
                        expected.get("value").unwrap(),
                        &format!("{path}/value"),
                        identities,
                    )?;
                }
                FieldProperty::Accessor { get, set } => {
                    assert_eq!(
                        expected.as_object().unwrap().len(),
                        4,
                        "{path}: accessor slot"
                    );
                    self.visit(
                        &get.map(FieldValue::from).unwrap_or_default(),
                        expected.get("get").unwrap(),
                        &format!("{path}/get"),
                        identities,
                    )?;
                    self.visit(
                        &set.map(FieldValue::from).unwrap_or_default(),
                        expected.get("set").unwrap(),
                        &format!("{path}/set"),
                        identities,
                    )?;
                }
            }
        }
        if kind == "date" {
            assert_replay(
                &self.observer.observe(actual)?["value"],
                &expected["value"],
                &format!("{path}/value"),
            );
        }
        Ok(())
    }

    pub(crate) fn finish(mut self, functions: &Json, path: &str) -> Vec<String> {
        let functions = functions.as_array().unwrap();
        assert_eq!(
            self.observer.function_ids(),
            functions
                .iter()
                .map(|value| value["identity"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
            "{path}: stable function identities"
        );
        for (index, function) in functions.iter().enumerate() {
            assert_eq!(
                function
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["identity", "name", "length", "source", "string", "ownKeys"]
            );
            self.unpaired.extend(
                ["name", "length", "source", "string", "ownKeys"]
                    .map(|field| format!("{path}/{index}/{field}")),
            );
        }
        self.unpaired
    }
}
