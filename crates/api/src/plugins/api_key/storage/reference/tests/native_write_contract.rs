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

const HASH: &str = "api-key:hash";
const ID: &str = "api-key:by-id:key";
const KEYS: [&str; 3] = [HASH, ID, INDEX];
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

struct Accessor {
    name: &'static str,
    getter: FieldFunction,
}

impl Accessor {
    fn new(
        name: &'static str,
        method: FieldFunction,
        observer: Observer,
        receiver: Receiver,
    ) -> Self {
        let getter = FieldFunction::contextual(move |this, _| {
            observer
                .lock()
                .unwrap()
                .call(&format!("get:{name}"), this, &receiver.get(), &[])?;
            Ok(method.clone().into())
        });
        Self { name, getter }
    }
}

impl FieldObjectSource for Accessor {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec![self.name.into()])
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok((name == self.name).then(|| FieldPropertyDescriptor {
            enumerable: false,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(self.getter.clone()),
                set: None,
            },
        }))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == self.name {
            self.getter.call_with(receiver, &[]).map(Some)
        } else {
            Ok(None)
        }
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
    reject_key: Option<FieldValue>,
    original: FieldValue,
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

    fn presence(&self) -> FieldValue {
        KEYS.into_iter()
            .map(|key| vec![key.into(), self.value(&key.into()).is_some().into()].into())
            .collect::<Vec<FieldValue>>()
            .into()
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
        let value = self
            .value(key)
            .filter(|value| !value.is_null() && !value.is_undefined())
            .unwrap_or(FieldValue::Null);
        let mut observer = self.observer.lock().unwrap();
        let observed_key = observer.observe(key)?;
        let observed_value = observer.observe(&value)?;
        observer.record(
            "storage.get",
            [
                ("key".into(), observed_key),
                ("value".into(), observed_value),
            ],
        );
        Ok(Some(value))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let observed_key = observer.observe(key)?;
        let observed_value = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map(FieldValue::from).unwrap_or_default())?;
        observer.record(
            "storage.set",
            [
                ("key".into(), observed_key.clone()),
                ("value".into(), observed_value),
                ("ttl".into(), ttl),
            ],
        );
        if value.is_undefined()
            && self
                .reject_key
                .as_ref()
                .is_some_and(|rejected| rejected.strict_equals(key))
        {
            let error = observer.observe(&self.original)?;
            observer.record(
                "storage.reject",
                [("key".into(), observed_key), ("error".into(), error)],
            );
            return Err(AuthError::from_thrown(self.original.clone()));
        }
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
            "API Key write contract does not consume atomic cache values",
        ))
    }
}

fn omitted_array(
    observer: &Observer,
    values: Vec<FieldValue>,
    result: FieldValue,
) -> Arc<FieldValue> {
    let expected = Receiver::default();
    let receiver = expected.clone();
    let observed = observer.clone();
    let method = FieldFunction::contextual(move |this, arguments| {
        let mut observer = observed.lock().unwrap();
        observer.call("call:toJSON", this, &receiver.get(), arguments)?;
        assert_eq!(arguments, &[FieldValue::from("")]);
        let value = observer.observe(&result)?;
        observer.record("toJSON:result", [("value".into(), value)]);
        Ok(result.clone())
    });
    expected.bind(
        FieldArray::from_values_with_properties(
            values,
            FieldObject::from_source(Arc::new(Accessor::new(
                "toJSON",
                method,
                observer.clone(),
                expected.clone(),
            ))),
        )
        .into(),
    )
}

fn reference_roots(
    observer: &Observer,
    id: &FieldValue,
    insert: bool,
    result: FieldValue,
) -> (Arc<FieldValue>, FieldMap) {
    if insert {
        let index = omitted_array(observer, vec![id.clone()], result.clone());
        let roots = FieldMap::from([
            ("index".into(), index.as_ref().clone()),
            ("toJSONResult".into(), result),
        ]);
        return (index, roots);
    }
    let output = omitted_array(observer, vec!["keep".into()], result.clone());
    let reference_result = output.as_ref().clone();
    let expected = Receiver::default();
    let receiver = expected.clone();
    let observed = observer.clone();
    let target = id.clone();
    let method = FieldFunction::contextual(move |this, arguments| {
        observed
            .lock()
            .unwrap()
            .call("call:filter", this, &receiver.get(), arguments)?;
        let [FieldValue::Function(predicate)] = arguments else {
            return Err(AuthError::internal(
                "Filter must receive a native predicate",
            ));
        };
        let values: FieldValue = vec![
            predicate.call_with(
                &"ignored receiver".into(),
                &["keep".into(), 0.into(), this.clone()],
            )?,
            predicate.call_with(this, &[target.clone(), 1.into(), this.clone()])?,
        ]
        .into();
        let mut observer = observed.lock().unwrap();
        let results = observer.observe(&values)?;
        observer.record("filter:predicate", [("results".into(), results)]);
        Ok(output.as_ref().clone())
    });
    let index = expected.bind(
        FieldArray::from_values_with_properties(
            vec!["keep".into(), id.clone()],
            FieldObject::from_source(Arc::new(Accessor::new(
                "filter",
                method,
                observer.clone(),
                expected.clone(),
            ))),
        )
        .into(),
    );
    let roots = FieldMap::from([
        ("index".into(), index.as_ref().clone()),
        ("referenceResult".into(), reference_result),
        ("toJSONResult".into(), result),
    ]);
    (index, roots)
}

async fn run_case(scenario: &Value) -> AuthResult<Value> {
    let name = scenario["name"].as_str().unwrap();
    let insert = scenario["operation"] == "put";
    let record_case = scenario["target"] == "record";
    let observer = Observer::default();
    let id: FieldValue = vec!["key".into()].into();
    let mut fields = FieldMap::from([
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
    ]);
    let expected = Receiver::default();
    if record_case {
        let receiver = expected.clone();
        let observed = observer.clone();
        let target = id.clone();
        let _ = fields.insert(
            "toJSON".into(),
            FieldFunction::contextual(move |this, arguments| {
                let mut observer = observed.lock().unwrap();
                observer.call("record:toJSON", this, &receiver.get(), arguments)?;
                assert!(!this.strict_equals(&receiver.get()));
                assert_eq!(arguments, &[FieldValue::from("")]);
                let value = observer.observe(this)?;
                let same_id = this.model_property("id")?.strict_equals(&target);
                observer.record(
                    "record:receiver",
                    [("value".into(), value), ("sameId".into(), same_id.into())],
                );
                Ok(FieldValue::Undefined)
            })
            .into(),
        );
    }
    let record = expected.bind(fields.clone().into());
    let key = ApiKey::from_field_values(fields)?;
    let (index, roots) = if record_case {
        let index: Arc<FieldValue> = Arc::new(vec![FieldValue::from("before")].into());
        let roots = FieldMap::from([("index".into(), index.as_ref().clone())]);
        (index, roots)
    } else {
        let result = match scenario["result"].as_str().unwrap() {
            "undefined" => FieldValue::Undefined,
            "function" => FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
            other => {
                return Err(AuthError::internal(format!(
                    "Unexpected JSON result: {other}"
                )));
            }
        };
        reference_roots(&observer, &id, insert, result)
    };
    let original: FieldValue = FieldMap::from([
        ("rejected".into(), name.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    let reject_key = match scenario["reject"].as_str().unwrap() {
        "none" => None,
        "hash" => Some(HASH.into()),
        "id" => Some(ID.into()),
        "index" => Some(INDEX.into()),
        other => {
            return Err(AuthError::internal(format!(
                "Unexpected rejected write: {other}"
            )));
        }
    };
    let storage = Arc::new(Storage {
        values: Mutex::new(vec![
            (HASH.into(), "stored-hash".into()),
            (ID.into(), "stored-id".into()),
            (INDEX.into(), index.as_ref().clone()),
        ]),
        observer: observer.clone(),
        reject_key,
        original: original.clone(),
    });
    let state = || {
        FieldMap::from([
            ("record".into(), record.as_ref().clone()),
            ("cache".into(), storage.snapshot()),
            ("roots".into(), roots.clone().into()),
            ("storageHas".into(), storage.presence()),
        ])
    };
    let before = observer.lock().unwrap().observe(&state().into())?;
    let outcome = if insert {
        put(storage.clone(), &key, false).await
    } else {
        remove_cached(storage.clone(), &key, false).await
    };
    let mut observer = observer.lock().unwrap();
    let outcome = observer.outcome(outcome.map(|()| FieldValue::Undefined), &original)?;
    let mut after = state();
    let _ = after.insert(
        "indexSameOriginal".into(),
        storage
            .value(&INDEX.into())
            .is_some_and(|stored| stored.strict_equals(&index))
            .into(),
    );
    let after = observer.observe(&after.into())?;
    let input =
        observer.observe(&FieldMap::from([("record".into(), record.as_ref().clone())]).into())?;
    Ok(json!({
        "input":input,
        "before":before,
        "outcome":outcome,
        "events":observer.events,
        "after":after,
        "functionIds":observer.function_ids(),
    }))
}

#[tokio::test]
async fn native_undefined_writes_match_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/secondary-native-write-undefined-1.7.6.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["scenario"]["domain"] == "api-key")
        .collect::<Vec<_>>();
    let names = [
        "api-key-record-undefined-reject-none",
        "api-key-record-undefined-reject-hash",
        "api-key-record-undefined-reject-id",
        "api-key-put-reference-undefined-reject-none",
        "api-key-put-reference-undefined-reject-index",
        "api-key-put-reference-function-reject-none",
        "api-key-put-reference-function-reject-index",
        "api-key-remove-reference-undefined-reject-none",
        "api-key-remove-reference-undefined-reject-index",
        "api-key-remove-reference-function-reject-none",
        "api-key-remove-reference-function-reject-index",
    ];
    assert_eq!(cases.len(), names.len());
    for (case, name) in cases.into_iter().zip(names) {
        let scenario = &case["scenario"];
        assert_eq!(scenario["name"], name);
        let actual = run_case(scenario).await?;
        assert_replay(&actual, &case["runtime"], name);
    }
    Ok(())
}
