use super::*;
use better_auth_core::{
    FieldArray, FieldFunction, FieldObject,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};

#[derive(Debug)]
struct Call {
    name: String,
    receiver: FieldValue,
    arguments: Vec<FieldValue>,
}

#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Vec<Call>>>);

impl Calls {
    fn record(&self, name: impl Into<String>, receiver: &FieldValue, arguments: &[FieldValue]) {
        self.0.lock().unwrap().push(Call {
            name: name.into(),
            receiver: receiver.clone(),
            arguments: arguments.to_vec(),
        });
    }

    fn drain(&self) -> Vec<Call> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct Properties {
    fields: FieldObject,
}

impl Properties {
    fn new(fields: FieldMap, calls: Calls, failure: Option<(&'static str, FieldValue)>) -> Self {
        let fields = fields
            .into_iter()
            .map(|(name, value)| {
                let calls = calls.clone();
                let error = failure
                    .as_ref()
                    .filter(|(failed, _)| name == *failed)
                    .map(|(_, error)| error.clone());
                let phase = format!("get:{name}");
                let getter = FieldFunction::contextual(move |receiver, _| {
                    calls.record(&phase, receiver, &[]);
                    if let Some(error) = &error {
                        return Err(AuthError::from_thrown(error.clone()));
                    }
                    Ok(value.clone())
                });
                (
                    name,
                    FieldPropertyDescriptor {
                        enumerable: true,
                        configurable: true,
                        property: FieldProperty::Accessor {
                            get: Some(getter),
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

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Method calls must not snapshot native properties",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn properties(fields: FieldMap, calls: &Calls) -> FieldObject {
    FieldObject::from_source(Arc::new(Properties::new(fields, calls.clone(), None)))
}

#[tokio::test]
async fn put_invokes_the_original_includes_and_consumes_its_native_truthiness() {
    for (result, expected) in [
        (FieldValue::from(FieldMap::new()), r#"["changed"]"#),
        (FieldValue::from(""), r#"["changed",["key"]]"#),
    ] {
        let cache = Arc::new(Cache::default());
        let id: FieldValue = vec!["key".into()].into();
        let key = record(id.clone());
        let calls = Calls::default();
        let observed = calls.clone();
        let includes = FieldFunction::contextual(move |receiver, arguments| {
            observed.record("call:includes", receiver, arguments);
            receiver.set_model_property("0", "changed".into())?;
            Ok(result.clone())
        });
        let index: FieldValue = FieldArray::from_values_with_properties(
            vec!["before".into()],
            properties(
                FieldMap::from([("includes".into(), includes.into())]),
                &calls,
            ),
        )
        .into();
        cache.seed(INDEX, index.clone());
        put(cache.clone(), &key, false).await.unwrap();
        let observations = calls.drain();
        assert_eq!(
            observations
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>(),
            ["get:includes", "call:includes"]
        );
        assert!(
            observations
                .iter()
                .all(|call| call.receiver.strict_equals(&index))
        );
        assert!(observations.first().unwrap().arguments.is_empty());
        let arguments = &observations.get(1).unwrap().arguments;
        assert_eq!(arguments.len(), 1);
        assert!(arguments.first().unwrap().strict_equals(&id));
        assert_eq!(cache.value(INDEX), Some(expected.into()));
        let serialized = super::super::super::serialize(&key).unwrap();
        assert_eq!(
            *cache.writes.lock().unwrap(),
            [
                Write::Set("api-key:hash".into(), serialized.clone()),
                Write::Set("api-key:by-id:key".into(), serialized),
                Write::Set(INDEX.into(), expected.into()),
            ]
        );
    }
}

#[tokio::test]
async fn remove_passes_the_native_predicate_and_keeps_the_custom_filter_result_until_serialization()
{
    let cache = Arc::new(Cache::default());
    let id: FieldValue = vec!["key".into()].into();
    let key = record(id.clone());
    let calls = Calls::default();
    let observed = calls.clone();
    let to_json = FieldFunction::contextual(move |receiver, arguments| {
        observed.record("call:toJSON", receiver, arguments);
        Ok("custom-reference".into())
    });
    let result: FieldValue = properties(
        FieldMap::from([
            ("length".into(), "0".into()),
            ("toJSON".into(), to_json.into()),
        ]),
        &calls,
    )
    .into();
    let returned = result.clone();
    let observed = calls.clone();
    let predicate_results = Arc::new(Mutex::new(Vec::new()));
    let compared = predicate_results.clone();
    let filter = FieldFunction::contextual(move |receiver, arguments| {
        observed.record("call:filter", receiver, arguments);
        let [FieldValue::Function(predicate)] = arguments else {
            return Err(AuthError::internal(
                "Filter argument must remain a native function",
            ));
        };
        *compared
            .lock()
            .map_err(|_| AuthError::internal("Predicate observation lock poisoned"))? = vec![
            predicate.call_with(
                &"ignored receiver".into(),
                &[id.clone(), 9.into(), receiver.clone()],
            )?,
            predicate.call_with(receiver, &[vec!["key".into()].into()])?,
            predicate.call()?,
        ];
        receiver.set_model_property("0", "changed".into())?;
        Ok(returned.clone())
    });
    let index: FieldValue = FieldArray::from_values_with_properties(
        vec!["before".into()],
        properties(FieldMap::from([("filter".into(), filter.into())]), &calls),
    )
    .into();
    cache.seed("api-key:hash", "stored-hash".into());
    cache.seed("api-key:by-id:key", "stored-id".into());
    cache.seed(INDEX, index.clone());
    remove_cached(cache.clone(), &key, false).await.unwrap();
    let observations = calls.drain();
    assert_eq!(
        observations
            .iter()
            .map(|call| call.name.as_str())
            .collect::<Vec<_>>(),
        [
            "get:filter",
            "call:filter",
            "get:length",
            "get:toJSON",
            "call:toJSON"
        ]
    );
    assert!(
        observations
            .iter()
            .take(2)
            .all(|call| call.receiver.strict_equals(&index))
    );
    assert!(
        observations
            .iter()
            .skip(2)
            .all(|call| call.receiver.strict_equals(&result))
    );
    assert_eq!(
        observations.last().unwrap().arguments,
        [FieldValue::from("")]
    );
    assert_eq!(
        *predicate_results.lock().unwrap(),
        [false.into(), true.into(), true.into()]
    );
    assert_eq!(index.model_property("0").unwrap(), "changed".into());
    assert_eq!(cache.value("api-key:hash"), None);
    assert_eq!(cache.value("api-key:by-id:key"), None);
    assert_eq!(cache.value(INDEX), Some(r#""custom-reference""#.into()));
    assert_eq!(
        *cache.writes.lock().unwrap(),
        [
            Write::Delete("api-key:hash".into()),
            Write::Delete("api-key:by-id:key".into()),
            Write::Set(INDEX.into(), r#""custom-reference""#.into()),
        ]
    );
}

#[tokio::test]
async fn original_getter_and_method_errors_preserve_completed_cache_writes_and_deletes() {
    for insert in [true, false] {
        for getter in [true, false] {
            let cache = Arc::new(Cache::default());
            let key = record("key".into());
            let method = if insert { "includes" } else { "filter" };
            let original: FieldValue =
                FieldMap::from([("nativeError".into(), method.into())]).into();
            let error = original.clone();
            let calls = Calls::default();
            let observed = calls.clone();
            let callback = FieldFunction::contextual(move |receiver, arguments| {
                observed.record(format!("call:{method}"), receiver, arguments);
                Err(AuthError::from_thrown(error.clone()))
            });
            let index: FieldValue = FieldArray::from_values_with_properties(
                vec!["key".into()],
                FieldObject::from_source(Arc::new(Properties::new(
                    FieldMap::from([(method.into(), callback.into())]),
                    calls.clone(),
                    getter.then(|| (method, original.clone())),
                ))),
            )
            .into();
            cache.seed("api-key:hash", "stored-hash".into());
            cache.seed("api-key:by-id:key", "stored-id".into());
            cache.seed(INDEX, index.clone());
            let error = if insert {
                put(cache.clone(), &key, false).await.unwrap_err()
            } else {
                remove_cached(cache.clone(), &key, false).await.unwrap_err()
            };
            let observations = calls.drain();
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(&original))
            );
            assert_eq!(observations.len(), if getter { 1 } else { 2 });
            assert_eq!(observations.first().unwrap().name, format!("get:{method}"));
            assert!(
                observations
                    .iter()
                    .all(|call| call.receiver.strict_equals(&index))
            );
            if !getter {
                let call = observations.get(1).unwrap();
                assert_eq!(call.name, format!("call:{method}"));
                assert_eq!(call.arguments.len(), 1);
            }
            assert!(cache.value(INDEX).unwrap().strict_equals(&index));
            let expected = if insert {
                let serialized = super::super::super::serialize(&key).unwrap();
                assert_eq!(cache.value("api-key:hash"), Some(serialized.clone()));
                assert_eq!(cache.value("api-key:by-id:key"), Some(serialized.clone()));
                vec![
                    Write::Set("api-key:hash".into(), serialized.clone()),
                    Write::Set("api-key:by-id:key".into(), serialized),
                ]
            } else {
                assert_eq!(cache.value("api-key:hash"), None);
                assert_eq!(cache.value("api-key:by-id:key"), None);
                vec![
                    Write::Delete("api-key:hash".into()),
                    Write::Delete("api-key:by-id:key".into()),
                ]
            };
            assert_eq!(*cache.writes.lock().unwrap(), expected);
        }
    }
}
