#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares complete source observations, native aliases, and original callback errors."
)]

use super::*;
use crate::{
    FieldArray, FieldDate, FieldFunction, StructuredCloneContext, field_value::FieldObjectSource,
};
use serde_json::{Value as Json, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Observation {
    receiver: Mutex<Option<FieldValue>>,
    events: Mutex<Vec<String>>,
}

struct Properties {
    fields: FieldObject,
    observation: Arc<Observation>,
    reads: AtomicUsize,
    write_failure: Mutex<Option<AuthError>>,
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Native property contract lock poisoned"))
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
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        if let Some(error) = lock(&self.write_failure)?.take() {
            let same = lock(&self.observation.receiver)?
                .as_ref()
                .is_some_and(|expected| expected.strict_equals(receiver));
            lock(&self.observation.events)?.push(format!("set:{same}"));
            return Err(error);
        }
        self.fields.set_with_receiver(&name, value, receiver)
    }
    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native property operations must not snapshot the property source",
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

fn drain(observation: &Observation) -> AuthResult<Vec<String>> {
    Ok(std::mem::take(&mut *lock(&observation.events)?))
}

#[test]
fn native_property_spread_json_and_clone_match_complete_source_observations() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native-named-properties-1.7.6.json"
    )))?;
    let mut records = Vec::new();
    for kind in ["array", "date", "function"] {
        let observation = Arc::new(Observation::default());
        let child: FieldValue =
            FieldMap::from([("ownUndefined".into(), FieldValue::Undefined)]).into();
        let fields: FieldObject = FieldMap::from([
            ("alias".into(), child.clone()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let observed = observation.clone();
        let selected = child.clone();
        assert!(
            fields.define_own_property(
                "selected",
                FieldPropertyDescriptor {
                    enumerable: true,
                    configurable: false,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |receiver, _| {
                            let same = lock(&observed.receiver)?
                                .as_ref()
                                .is_some_and(|expected| expected.strict_equals(receiver));
                            lock(&observed.events)?.push(format!("get:{same}"));
                            Ok(selected.clone())
                        })),
                        set: None,
                    },
                }
                .into(),
            )?
        );
        assert!(
            fields.define_own_property(
                "hidden",
                FieldPropertyDescriptor {
                    enumerable: false,
                    configurable: false,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(|_, _| {
                            Err(AuthError::internal("Hidden getter must not run"))
                        })),
                        set: None,
                    },
                }
                .into(),
            )?
        );
        let properties = FieldObject::from_source(Arc::new(Properties {
            fields,
            observation: observation.clone(),
            reads: AtomicUsize::new(0),
            write_failure: Mutex::new(None),
        }));
        let value: FieldValue = match kind {
            "array" => FieldArray::with_length_and_properties(3, properties).into(),
            "date" => FieldDate::from_milliseconds_with_properties(0.0, properties).into(),
            _ => FieldFunction::contextual_with_properties(
                |_, _| Ok(FieldValue::Undefined),
                properties,
            )
            .into(),
        };
        *lock(&observation.receiver)? = Some(value.clone());
        if kind == "array" {
            value.set_model_property("0", "first".into())?;
            value.set_model_property("2", "last".into())?;
        }
        let spread = value.enumerable_fields()?;
        let spread_events = drain(&observation)?;
        let encoded = value.stringify()?;
        let json_events = drain(&observation)?;
        let cloned = StructuredCloneContext::new().clone_value(&value);
        let clone_events = drain(&observation)?;
        let clone = match cloned {
            Err(AuthError::DataClone) => {
                json!({"name":"DataCloneError", "message": AuthError::DataClone.to_string()})
            }
            Err(error) => return Err(error),
            Ok(copy) => {
                let alias = copy.model_property("alias")?;
                let selected = copy.model_property("selected")?;
                let mut record = json!({
                    "keys": copy.enumerable_fields()?.keys().collect::<Vec<_>>(),
                    "ownUndefined": copy.has_property("ownUndefined")?,
                    "aliasRetained": alias.strict_equals(&selected),
                    "aliasFresh": !alias.strict_equals(&child),
                });
                if let Some(array) = copy.as_array() {
                    record["arrayLength"] = array.len()?.into();
                }
                if let Some(date) = copy.as_date() {
                    record["date"] = date.iso_string()?.into();
                }
                assert!(!copy.strict_equals(&value));
                record
            }
        };
        let mut record = json!({
            "contract":"native-named-properties", "kind": kind,
            "keys": spread.keys().collect::<Vec<_>>(), "spreadKeys": spread.keys().collect::<Vec<_>>(),
            "spreadAlias": spread.get("alias").is_some_and(|value| value.strict_equals(&child)),
            "spreadSelected": spread.get("selected").is_some_and(|value| value.strict_equals(&child)),
            "spreadEvents":spread_events, "jsonEvents":json_events, "cloneEvents":clone_events, "clone":clone,
        });
        if let Some(encoded) = encoded {
            record["json"] = encoded.into();
        }
        records.push(record);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        value.set_model_property(
            "toJSON",
            FieldFunction::contextual(move |receiver, arguments| {
                lock(&observed)?.push((receiver.clone(), arguments.to_vec()));
                Ok("custom".into())
            })
            .into(),
        )?;
        let custom =
            FieldValue::from(FieldMap::from([("value".into(), value.clone())])).stringify()?;
        let observed = std::mem::take(&mut *lock(&calls)?);
        assert_eq!(observed.len(), 1);
        let (receiver, arguments) = observed
            .first()
            .ok_or_else(|| AuthError::internal("Missing toJSON call"))?;
        records.push(json!({
            "contract":"native-named-properties-to-json", "kind":kind, "custom": custom,
            "receiver":receiver.strict_equals(&value),
            "arguments":arguments.iter().map(FieldValue::json).collect::<AuthResult<Vec<_>>>()?,
            "events":drain(&observation)?,
        }));
        let _ = lock(&observation.receiver)?.take();
    }
    assert_eq!(Json::Array(records), fixture);
    Ok(())
}

#[test]
fn property_writes_preserve_sparse_indices_length_and_factory_aliases() -> AuthResult<()> {
    let array: FieldValue = FieldArray::with_length(4).into();
    let alias = array.clone();
    array.set_model_property("2", FieldValue::Undefined)?;
    array.set_model_property("label", "first".into())?;
    assert!(alias.has_property("2")?);
    assert!(!alias.has_property("1")?);
    assert_eq!(
        alias
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["2", "label"]
    );
    alias.set_model_property("length", 2.into())?;
    assert!(!array.has_property("2")?);
    assert_eq!(array.model_property("length")?, 2.into());
    assert_eq!(array.stringify()?.as_deref(), Some("[null,null]"));
    assert!(matches!(
        array.set_model_property("length", 1.5.into()),
        Err(AuthError::RangeError(_))
    ));
    assert_eq!(array.model_property("length")?, 2.into());
    let factory = crate::user_fields::UserFieldFactory::new(|| Ok("result".into()));
    let first: FieldValue = FieldFunction::from(factory.clone()).into();
    let second: FieldValue = FieldFunction::from(factory.clone()).into();
    first.set_model_property("alias", array.clone())?;
    assert!(first.strict_equals(&second));
    assert!(second.model_property("alias")?.strict_equals(&array));
    assert_eq!(factory.call()?, "result".into());
    assert!(first.stringify()?.is_none());
    assert!(matches!(
        StructuredCloneContext::new().clone_value(&first),
        Err(AuthError::DataClone)
    ));
    array.set_model_property("self", array.clone())?;
    let copied = StructuredCloneContext::new().clone_value(&array)?;
    assert!(copied.model_property("self")?.strict_equals(&copied));
    assert_eq!(copied.stringify()?.as_deref(), Some("[null,null]"));
    let _ = array
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing source array"))?
        .properties()
        .delete("self")?;
    let _ = copied
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing cloned array"))?
        .properties()
        .delete("self")?;
    Ok(())
}

#[test]
fn native_assignments_preserve_setter_receiver_and_original_failure_without_getters()
-> AuthResult<()> {
    for kind in ["object", "array", "date", "function"] {
        let observation = Arc::new(Observation::default());
        let message = "original native setter failure".to_owned();
        let allocation = message.as_ptr() as usize;
        let source = Arc::new(Properties {
            fields: FieldMap::new().into(),
            observation: observation.clone(),
            reads: AtomicUsize::new(0),
            write_failure: Mutex::new(Some(AuthError::Internal(message))),
        });
        let properties = FieldObject::from_source(source.clone());
        let value: FieldValue = match kind {
            "object" => properties.into(),
            "array" => FieldArray::with_length_and_properties(0, properties).into(),
            "date" => FieldDate::from_milliseconds_with_properties(0.0, properties).into(),
            _ => FieldFunction::contextual_with_properties(
                |_, _| Err(AuthError::internal("Assignment must not call the function")),
                properties,
            )
            .into(),
        };
        *lock(&observation.receiver)? = Some(value.clone());
        assert!(
            matches!(value.set_model_property("property", true.into()), Err(AuthError::Internal(message)) if message.as_ptr() as usize == allocation)
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(drain(&observation)?, ["set:true"]);
        assert!(!value.has_property("property")?);
        let _ = lock(&observation.receiver)?.take();
    }
    for value in [
        FieldValue::from(false),
        0.into(),
        f64::NAN.into(),
        "text".into(),
    ] {
        assert!(
            matches!(value.set_model_property("property", true.into()), Err(AuthError::TypeError(message)) if message == "Attempted to assign to readonly property.")
        );
    }
    for (value, kind) in [
        (FieldValue::Undefined, "undefined"),
        (FieldValue::Null, "null"),
    ] {
        assert!(
            matches!(value.model_property_at("property", "receiver.property"), Err(AuthError::TypeError(message)) if message == format!("{kind} is not an object (evaluating 'receiver.property')"))
        );
    }
    Ok(())
}

#[test]
fn array_named_sources_reject_reserved_names_without_reading_values() -> AuthResult<()> {
    for name in ["length", "0", "4294967294"] {
        let source = Arc::new(Properties {
            fields: FieldMap::from([(name.into(), "conflicting".into())]).into(),
            observation: Arc::new(Observation::default()),
            reads: AtomicUsize::new(0),
            write_failure: Mutex::new(None),
        });
        let value: FieldValue = FieldArray::from_values_with_properties(
            vec!["indexed".into()],
            FieldObject::from_source(source.clone()),
        )
        .into();
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert_eq!(value.model_property("0")?, "indexed".into());
        assert_eq!(value.model_property("length")?, 1.into());
        for result in [
            value.enumerable_fields().map(drop),
            StructuredCloneContext::new().clone_value(&value).map(drop),
        ] {
            assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == format!("Array named property source contains reserved property '{name}'"))
            );
        }
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    }
    let value: FieldValue = FieldArray::new().into();
    value.set_model_property("4294967295", "named".into())?;
    assert_eq!(value.model_property("length")?, 0.into());
    assert_eq!(
        value
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["4294967295"]
    );
    Ok(())
}
