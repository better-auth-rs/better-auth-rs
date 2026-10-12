#![expect(
    clippy::panic_in_result_fn,
    reason = "The source contract compares complete callback order, receiver identity, original errors, and returned values."
)]

use crate::{
    AuthError, AuthResult, FieldArray, FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{FieldObjectSource, FieldProperty, FieldPropertyDescriptor},
};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

struct Observation {
    receiver: Mutex<Option<FieldValue>>,
    events: Mutex<Vec<String>>,
    original: FieldValue,
}

struct Properties {
    fields: FieldObject,
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Native coercion contract lock poisoned"))
}

fn same_receiver(observation: &Observation, receiver: &FieldValue) -> AuthResult<bool> {
    Ok(lock(&observation.receiver)?
        .as_ref()
        .is_some_and(|expected| expected.strict_equals(receiver)))
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Coercion must read each method without snapshotting",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
}

enum Return {
    Value(FieldValue),
    Receiver,
    Throw,
}

fn method(name: &'static str, result: Return, observation: &Arc<Observation>) -> FieldValue {
    let observation = observation.clone();
    FieldFunction::contextual(move |receiver, arguments| {
        lock(&observation.events)?.push(format!(
            "call:{name}:{}:{}",
            same_receiver(&observation, receiver)?,
            arguments.len()
        ));
        match &result {
            Return::Value(value) => Ok(value.clone()),
            Return::Receiver => Ok(receiver.clone()),
            Return::Throw => Err(AuthError::from_thrown(observation.original.clone())),
        }
    })
    .into()
}

fn observe(value: &FieldValue) -> AuthResult<Json> {
    match value {
        FieldValue::Number(value) if value.is_nan() => Ok(json!({"type":"number", "value":"NaN"})),
        FieldValue::Undefined => Ok(json!({"type":"undefined"})),
        value => value
            .json()?
            .ok_or_else(|| AuthError::internal("Missing coercion result")),
    }
}

fn scenario(kind: &str, mode: &str) -> AuthResult<Json> {
    let observation = Arc::new(Observation {
        receiver: Mutex::new(None),
        events: Mutex::new(Vec::new()),
        original: AuthError::internal("original native coercion error").into_thrown_value()?,
    });
    let mut fields = FieldMap::new();
    let mut getter_failure = None;
    if mode.starts_with("json-") {
        let result = if mode == "json-valueof-call-throws" {
            Return::Throw
        } else {
            Return::Value(if mode == "json-nan" {
                f64::NAN.into()
            } else {
                1.into()
            })
        };
        let _ = fields.insert("valueOf".into(), method("valueOf", result, &observation));
        if mode == "json-valueof-get-throws" {
            getter_failure = Some("valueOf");
        }
        if mode != "json-invalid-finite" {
            let result = if mode == "json-iso-call-throws" {
                Return::Throw
            } else {
                Return::Value("custom-iso".into())
            };
            let value = if mode == "json-iso-non-callable" {
                FieldValue::Null
            } else {
                method("toISOString", result, &observation)
            };
            let _ = fields.insert("toISOString".into(), value);
            if mode == "json-iso-get-throws" {
                getter_failure = Some("toISOString");
            }
        }
    } else if mode == "join" {
        let _ = fields.insert(
            "join".into(),
            method("join", Return::Value("joined".into()), &observation),
        );
    } else if mode != "native-number" {
        let result = match mode {
            "fallback" => Return::Receiver,
            "call-throws" => Return::Throw,
            _ => Return::Value(7.into()),
        };
        let value = if mode == "non-callable" {
            FieldValue::Null
        } else {
            method("valueOf", result, &observation)
        };
        let _ = fields.insert("valueOf".into(), value);
        if mode == "get-throws" {
            getter_failure = Some("valueOf");
        }
        let text = if mode == "string" {
            "string-result"
        } else {
            "8"
        };
        let _ = fields.insert(
            "toString".into(),
            method("toString", Return::Value(text.into()), &observation),
        );
    }
    let fields = fields
        .into_iter()
        .map(|(name, value)| {
            let observation = observation.clone();
            let key = name.clone();
            let get = FieldFunction::contextual(move |receiver, _| {
                lock(&observation.events)?.push(format!(
                    "get:{key}:{}",
                    same_receiver(&observation, receiver)?
                ));
                if getter_failure == Some(key.as_str()) {
                    return Err(AuthError::from_thrown(observation.original.clone()));
                }
                Ok(value.clone())
            });
            (
                name,
                FieldPropertyDescriptor {
                    enumerable: false,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(get),
                        set: None,
                    },
                },
            )
        })
        .collect::<indexmap::IndexMap<_, _>>();
    let properties = FieldObject::from_source(Arc::new(Properties {
        fields: fields.into(),
    }));
    let value: FieldValue = match kind {
        "array" => FieldArray::from_values_with_properties(vec![1.into()], properties).into(),
        "date" => FieldDate::from_milliseconds_with_properties(
            if mode == "json-invalid-finite" {
                f64::NAN
            } else {
                0.0
            },
            properties,
        )
        .into(),
        "function" => {
            FieldFunction::contextual_with_properties(|_, _| Ok(FieldValue::Undefined), properties)
                .into()
        }
        _ => return Err(AuthError::internal("Unknown native coercion kind")),
    };
    *lock(&observation.receiver)? = Some(value.clone());
    let result = if mode.starts_with("json-") {
        value
            .stringify()
            .map(|value| value.map_or(FieldValue::Undefined, Into::into))
    } else if mode == "string" || mode == "join" {
        value.display_utf16().map(Into::into)
    } else {
        crate::query::field_number(&value).map(FieldValue::Number)
    };
    let outcome = match result {
        Ok(value) => json!({"kind":"returned", "value":observe(&value)?}),
        Err(error) => {
            let error = error.into_thrown_value()?;
            json!({"kind":"thrown", "name":observe(&error.model_property("name")?)?,
                "message":observe(&error.model_property("message")?)?,
                "sameOriginal":error.strict_equals(&observation.original)})
        }
    };
    let events = std::mem::take(&mut *lock(&observation.events)?);
    let _ = lock(&observation.receiver)?.take();
    Ok(
        json!({"contract":"native-coercion-properties", "kind":kind, "mode":mode,
        "events":events, "outcome":outcome}),
    )
}

#[test]
fn native_coercion_matches_complete_source_observations() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native-coercion-properties-1.7.6.json"
    )))?;
    let mut records = Vec::new();
    for kind in ["array", "date", "function"] {
        for mode in [
            "number",
            "string",
            "fallback",
            "get-throws",
            "call-throws",
            "non-callable",
        ] {
            records.push(scenario(kind, mode)?);
        }
    }
    for mode in [
        "json-nan",
        "json-iso",
        "json-iso-get-throws",
        "json-iso-call-throws",
        "json-iso-non-callable",
        "json-invalid-finite",
        "json-valueof-get-throws",
        "json-valueof-call-throws",
    ] {
        records.push(scenario("date", mode)?);
    }
    records.push(scenario("array", "join")?);
    records.push(scenario("function", "native-number")?);
    assert_eq!(Json::Array(records), fixture);
    Ok(())
}
