#![expect(
    clippy::unreachable,
    reason = "Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

//! Replay the frozen descriptor graph without invoking accessors during observation.

use super::super::__private_core::{
    FieldObject,
    field_value::{FieldProperty, FieldPropertyDescriptor},
};
use super::*;

#[allow(
    dead_code,
    reason = "The shared harness also compiles in targets that do not replay getter cases."
)]
pub(crate) fn cases(consumer: &str) -> impl Iterator<Item = &'static Json> + '_ {
    static FIXTURE: OnceLock<Json> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../fixtures/native-sort-getter-runtime-1.7.6.json"
        ))
        .expect("The frozen accessor observation must decode")
    })["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |case| case["consumer"] == consumer)
}

pub(super) fn row(properties: FieldMap, getters: FieldMap) -> FieldValue {
    let object: FieldObject = properties.into();
    for (name, getter) in getters {
        let FieldValue::Function(getter) = getter else {
            unreachable!();
        };
        object
            .define_own_property(
                name,
                FieldPropertyDescriptor {
                    enumerable: true,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(getter),
                        set: None,
                    },
                }
                .into(),
            )
            .unwrap();
    }
    object.into()
}

struct Graph<'a> {
    state: &'a mut State,
    identities: Vec<FieldValue>,
}

impl Graph<'_> {
    fn value(&mut self, value: &FieldValue) -> AuthResult<Json> {
        let kind = match value {
            FieldValue::Object(_) => "object",
            FieldValue::Array(_) => "array",
            FieldValue::Date(_) => "date",
            _ => return self.state.observer.observe(value),
        };
        if let Some(index) = self
            .identities
            .iter()
            .position(|known| known.strict_equals(value))
        {
            return Ok(json!({"reference": format!("object-{}", index + 1)}));
        }
        self.identities.push(value.clone());
        let identity = format!("object-{}", self.identities.len());
        let keys = match value {
            FieldValue::Array(array) => {
                let mut keys = array
                    .own_indices()?
                    .into_iter()
                    .map(|index| index.to_string())
                    .collect::<Vec<_>>();
                keys.push("length".into());
                assert_eq!(
                    value.own_property_keys()?,
                    keys,
                    "The source fixture constructs arrays without named properties"
                );
                keys
            }
            FieldValue::Object(object) => object.own_keys()?,
            FieldValue::Date(date) => date.properties().own_keys()?,
            _ => unreachable!(),
        };
        let mut properties = Vec::new();
        for name in &keys {
            let descriptor = match value {
                FieldValue::Array(_) => value.own_property_descriptor(name)?.unwrap(),
                FieldValue::Object(object) => object.own_property_descriptor(name)?.unwrap(),
                FieldValue::Date(date) => date.properties().own_property_descriptor(name)?.unwrap(),
                _ => unreachable!(),
            };
            let property = match descriptor.property {
                FieldProperty::Accessor { get, set } => {
                    json!({"enumerable": descriptor.enumerable,
                        "get": self.value(&get.map(FieldValue::from).unwrap_or_default())?,
                        "set": self.value(&set.map(FieldValue::from).unwrap_or_default())?})
                }
                FieldProperty::Data { value, .. } => {
                    json!({"enumerable": descriptor.enumerable, "value": self.value(&value)?})
                }
            };
            properties.push(json!([name, property]));
        }
        let mut result =
            json!({"identity":identity,"type":kind,"ownKeys":keys,"properties":properties});
        if let FieldValue::Date(_) = value {
            result["value"] = self.state.observer.observe(value)?["value"].clone();
        }
        Ok(result)
    }
}

pub(super) fn snapshot(state: &mut State, result: Option<FieldValue>) -> AuthResult<Json> {
    let mut root = FieldMap::from([
        ("rows".into(), state.rows.clone().into()),
        ("cells".into(), state.cells.clone().into()),
    ]);
    if let Some(result) = result {
        let _ = root.insert("result".into(), result);
    }
    Graph {
        state,
        identities: Vec::new(),
    }
    .value(&root.into())
}

pub(super) fn finish(
    state: &mut State,
    before: Json,
    result: AuthResult<FieldValue>,
) -> AuthResult<Json> {
    let (outcome, result) = match result {
        Ok(value) => (json!({"returned":true}), Some(value)),
        Err(error) => {
            let value = error.into_thrown_value()?;
            (
                json!({"returned":false,"sameOriginal":value.strict_equals(&state.original),"error":{"thrown":state.observer.observe(&value)?}}),
                None,
            )
        }
    };
    let after = snapshot(state, result)?;
    Ok(
        json!({"before":before,"outcome":outcome,"after":after,"events":state.observer.events,"counts":state.counts,"functions":state.observer.function_ids()}),
    )
}
