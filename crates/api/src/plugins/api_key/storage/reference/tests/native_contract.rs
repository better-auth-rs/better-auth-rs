#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use better_auth_core::{
    FieldArray, FieldDate, FieldFunction, FieldObject, FromFieldMap,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};
use std::sync::{OnceLock, Weak};

use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};

type Observer = Arc<Mutex<NativeObservation>>;

#[derive(Clone, Default)]
struct Receiver(Arc<OnceLock<Weak<FieldValue>>>);

impl Receiver {
    fn bind(&self, value: FieldValue) -> Arc<FieldValue> {
        let value = Arc::new(value);
        self.0.set(Arc::downgrade(&value)).unwrap();
        value
    }

    fn get(&self) -> Arc<FieldValue> {
        self.0.get().unwrap().upgrade().unwrap()
    }
}

struct Properties {
    fields: FieldObject,
}

impl Properties {
    fn new(
        fields: FieldMap,
        observer: Observer,
        receiver: Receiver,
        failure: Option<FieldValue>,
    ) -> Self {
        let fields = fields
            .into_iter()
            .map(|(name, value)| {
                let observer = observer.clone();
                let receiver = receiver.clone();
                let failure = failure.clone();
                let phase = format!("get:{name}");
                let get = FieldFunction::contextual(move |this, _| {
                    observer
                        .lock()
                        .unwrap()
                        .call(&phase, this, &receiver.get(), &[])?;
                    if let Some(error) = &failure {
                        return Err(AuthError::from_thrown(error.clone()));
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
            .collect::<indexmap::IndexMap<_, _>>()
            .into();
        Self { fields }
    }
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

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("Contract accessor has no setter"))
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal("Contract accessor has no setter"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Contract does not delete named accessors",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native accessors must not be flattened",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

struct Storage {
    values: Mutex<Vec<(FieldValue, FieldValue)>>,
    observer: Observer,
}

impl Storage {
    fn snapshot(&self) -> FieldValue {
        self.values
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| vec![key.clone(), value.clone()].into())
            .collect::<Vec<FieldValue>>()
            .into()
    }

    fn value(&self, key: &FieldValue) -> Option<FieldValue> {
        self.values
            .lock()
            .unwrap()
            .iter()
            .find(|(stored, _)| stored.same_value_zero(key))
            .map(|(_, value)| value.clone())
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let mut observer = self.observer.lock().unwrap();
        let key_observation = observer.observe(key)?;
        observer.record("storage.get", [("key".into(), key_observation)]);
        Ok(self.value(key))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let key_observation = observer.observe(key)?;
        let value_observation = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map(FieldValue::from).unwrap_or_default())?;
        observer.record(
            "storage.set",
            [
                ("key".into(), key_observation),
                ("value".into(), value_observation),
                ("ttl".into(), ttl),
            ],
        );
        let mut values = self.values.lock().unwrap();
        if let Some((_, stored)) = values
            .iter_mut()
            .find(|(stored, _)| stored.same_value_zero(key))
        {
            *stored = value.clone();
        } else {
            values.push((key.clone(), value.clone()));
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.delete_native(&key.into()).await
    }

    async fn delete_native(&self, key: &FieldValue) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let key_observation = observer.observe(key)?;
        observer.record("storage.delete", [("key".into(), key_observation)]);
        self.values
            .lock()
            .unwrap()
            .retain(|(stored, _)| !stored.same_value_zero(key));
        Ok(())
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "API Key reference contract does not consume atomic cache values",
        ))
    }
}

fn dynamic_result(observer: &Observer) -> Arc<FieldValue> {
    let expected = Receiver::default();
    let receiver = expected.clone();
    let observed = observer.clone();
    let to_json = FieldFunction::contextual(move |this, arguments| {
        observed
            .lock()
            .unwrap()
            .call("call:toJSON", this, &receiver.get(), arguments)?;
        Ok("custom-reference".into())
    });
    expected.bind(
        FieldObject::from_source(Arc::new(Properties::new(
            FieldMap::from([
                ("length".into(), "0".into()),
                ("toJSON".into(), to_json.into()),
            ]),
            observer.clone(),
            expected.clone(),
            None,
        )))
        .into(),
    )
}

async fn run_case(scenario: &Value) -> AuthResult<Value> {
    let operation = scenario["operation"].as_str().unwrap();
    assert!(matches!(operation, "put" | "remove"));
    let insert = operation == "put";
    let failure = scenario.get("failure").and_then(Value::as_str);
    assert!(matches!(failure, None | Some("getter" | "method")));
    let getter_error = failure == Some("getter");
    let method_error = failure == Some("method");
    let truthy = scenario.get("result").and_then(Value::as_str) == Some("truthy");
    let observer = Observer::default();
    let id: FieldValue = vec!["key".into()].into();
    let key = ApiKey::from_field_values(FieldMap::from([
        ("id".into(), id.clone()),
        ("key".into(), "hash".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
        ),
        (
            "updatedAt".into(),
            FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
        ),
    ]))?;
    let original: FieldValue = FieldMap::from([
        ("nativeError".into(), operation.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
        (
            "detail".into(),
            FieldMap::from([(
                "stage".into(),
                failure.map(FieldValue::from).unwrap_or_default(),
            )])
            .into(),
        ),
    ])
    .into();
    let dynamic = dynamic_result(&observer);
    let expected = Receiver::default();
    let receiver = expected.clone();
    let observed = observer.clone();
    let error = original.clone();
    let method = if insert { "includes" } else { "filter" };
    let callback = FieldFunction::contextual(move |this, arguments| {
        observed.lock().unwrap().call(
            &format!("call:{method}"),
            this,
            &receiver.get(),
            arguments,
        )?;
        assert!(this.strict_equals(&receiver.get()));
        assert_eq!(arguments.len(), 1);
        if insert {
            let same_id = arguments.first().unwrap().strict_equals(&id);
            assert!(same_id);
            observed
                .lock()
                .unwrap()
                .record("includes:id", [("sameId".into(), same_id.into())]);
        } else {
            let [FieldValue::Function(predicate)] = arguments else {
                return Err(AuthError::internal(
                    "Filter must receive a native predicate",
                ));
            };
            let results: FieldValue = vec![
                predicate.call_with(
                    &"ignored receiver".into(),
                    &[id.clone(), 9.into(), this.clone()],
                )?,
                predicate.call_with(this, &[vec!["key".into()].into()])?,
                predicate.call()?,
            ]
            .into();
            let mut observer = observed.lock().unwrap();
            let results = observer.observe(&results)?;
            observer.record("filter:predicate", [("results".into(), results)]);
        }
        if method_error {
            return Err(AuthError::from_thrown(error.clone()));
        }
        this.set_model_property("0", "changed".into())?;
        Ok(if !insert {
            dynamic.as_ref().clone()
        } else if truthy {
            FieldMap::new().into()
        } else {
            "".into()
        })
    });
    let index = expected.bind(
        FieldArray::from_values_with_properties(
            vec!["before".into()],
            FieldObject::from_source(Arc::new(Properties::new(
                FieldMap::from([(method.into(), callback.into())]),
                observer.clone(),
                expected.clone(),
                getter_error.then(|| original.clone()),
            ))),
        )
        .into(),
    );
    let storage = Arc::new(Storage {
        values: Mutex::new(vec![
            ("api-key:hash".into(), "stored-hash".into()),
            ("api-key:by-id:key".into(), "stored-id".into()),
            (INDEX.into(), index.as_ref().clone()),
        ]),
        observer: observer.clone(),
    });
    let before = observer.lock().unwrap().observe(
        &FieldMap::from([
            ("record".into(), key.field_values()?.into()),
            ("cache".into(), storage.snapshot()),
        ])
        .into(),
    )?;
    let outcome = if insert {
        put(storage.clone(), &key, false).await
    } else {
        remove_cached(storage.clone(), &key, false).await
    };
    let mut observer = observer.lock().unwrap();
    let outcome = observer.outcome(outcome.map(|()| FieldValue::Undefined), &original)?;
    let after = observer.observe(
        &FieldMap::from([
            ("record".into(), key.field_values()?.into()),
            ("cache".into(), storage.snapshot()),
            ("originalIndex".into(), index.as_ref().clone()),
            (
                "indexSameOriginal".into(),
                storage
                    .value(&INDEX.into())
                    .is_some_and(|stored| stored.strict_equals(&index))
                    .into(),
            ),
        ])
        .into(),
    )?;
    Ok(json!({
        "before":before,
        "outcome":outcome,
        "events":observer.events,
        "after":after,
        "functionIds":observer.function_ids(),
    }))
}

#[tokio::test]
async fn native_reference_methods_match_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/api-key-reference-native-1.7.6.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let scenario = &case["scenario"];
        let name = scenario["name"].as_str().unwrap();
        let actual = run_case(scenario).await?;
        assert_replay(&actual, &case["runtime"], name);
    }
    Ok(())
}
