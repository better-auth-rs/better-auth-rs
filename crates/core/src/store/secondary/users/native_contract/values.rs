#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use std::sync::{OnceLock, Weak};

type Receiver = Weak<OnceLock<FieldValue>>;

pub(super) struct Values {
    pub(super) roots: FieldMap,
    pub(super) original: FieldValue,
    pub(super) references: Vec<FieldValue>,
    pub(super) concurrent: FieldValue,
    pub(super) initial_index: String,
    held_roots: Vec<Root>,
    refreshed: FieldValue,
}

pub(super) fn patch() -> FieldMap {
    FieldMap::from([
        ("ipAddress".into(), "updated-ip".into()),
        ("expiresAt".into(), date(120_000)),
        ("updatedAt".into(), date(1_000)),
    ])
}

fn empty_function() -> FieldValue {
    FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into()
}

impl Values {
    pub(super) fn new(scenario: &Json, observer: Observer) -> AuthResult<Self> {
        let retained: FieldValue = FieldMap::from([
            ("7".into(), "integer-key".into()),
            ("before".into(), "keep".into()),
            ("token".into(), "retained".into()),
            ("expiresAt".into(), (NOW + 90_000).into()),
            (
                "extra".into(),
                FieldMap::from([(
                    "nested".into(),
                    vec![
                        1.into(),
                        FieldMap::from([("own".into(), FieldValue::Null)]).into(),
                    ]
                    .into(),
                )])
                .into(),
            ),
            ("after".into(), "tail".into()),
        ])
        .into();
        let references = vec![
            retained.clone(),
            FieldMap::from([
                ("token".into(), "expired".into()),
                ("expiresAt".into(), (NOW - 1_000).into()),
                ("extra".into(), "expired".into()),
            ])
            .into(),
            FieldMap::from([
                ("token".into(), "target".into()),
                ("expiresAt".into(), (NOW + 60_000).into()),
                ("extra".into(), "target-replaced".into()),
            ])
            .into(),
        ];
        let initial_index = FieldValue::from(references.clone()).stringify()?.unwrap();
        let concurrent = FieldMap::from([
            ("before".into(), "new".into()),
            ("token".into(), "concurrent".into()),
            ("expiresAt".into(), (NOW + 180_000).into()),
            (
                "extra".into(),
                FieldMap::from([(
                    "pending".into(),
                    vec!["entire".into(), "record".into()].into(),
                )])
                .into(),
            ),
            ("after".into(), "new-tail".into()),
        ])
        .into();
        let original: FieldValue = FieldMap::from([
            (
                "nativeError".into(),
                scenario["name"].as_str().unwrap().into(),
            ),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let mut refreshed = user();
        let _ = refreshed.insert("name".into(), "Refreshed".into());
        let _ = refreshed.insert("native".into(), empty_function());
        let _ = refreshed.insert("seenAt".into(), date(-8_000));
        let mut values = Self {
            roots: FieldMap::new(),
            original,
            references,
            concurrent,
            initial_index,
            held_roots: Vec::new(),
            refreshed: refreshed.into(),
        };
        if let Some(kind) = scenario["root"].as_str() {
            let extra = retained.model_property("extra")?;
            let extra = extra.as_object().unwrap();
            extra.set("native", empty_function())?;
            extra.set("date", date(-5_000))?;
            values.update_chain(kind, observer)?;
        } else if scenario["operation"] == "update" && scenario["failure"].is_string() {
            values.update_failure(scenario, observer)?;
        } else if scenario["operation"] == "refresh" {
            values.refresh(scenario, observer)?;
        }
        Ok(values)
    }

    pub(super) fn input(&self, scenario: &Json) -> FieldValue {
        let fields = match scenario["operation"].as_str().unwrap() {
            "create" => FieldMap::from([
                ("userId".into(), "owner".into()),
                ("dontRememberMe".into(), false.into()),
                ("override".into(), session("created", 30_000).into()),
                ("overrideAll".into(), true.into()),
            ]),
            "update" => FieldMap::from([
                ("token".into(), "target".into()),
                ("data".into(), patch().into()),
            ]),
            "refresh" => FieldMap::from([("user".into(), self.refreshed.clone())]),
            "delete" => FieldMap::from([("token".into(), "target".into())]),
            _ => FieldMap::from([("userId".into(), "owner".into())]),
        };
        fields.into()
    }

    fn keep(&mut self, name: &str, root: Root) {
        let _ = self.roots.insert(name.into(), root.value.clone());
        self.held_roots.push(root);
    }

    fn update_chain(&mut self, kind: &str, observer: Observer) -> AuthResult<()> {
        let root = Root::new(kind, -3_000, observer.clone());
        let filtered = Root::new("date", -4_000, observer.clone());
        let concatenated = Root::new("function", 0, observer.clone());
        let sorted = Root::new("array", 0, observer.clone());
        let retained = self.references[0].clone();
        let references = self.references.clone();
        let predicate_root = Arc::downgrade(&root.expected);
        let returned = filtered.value.clone();
        let events = observer.clone();
        root.method("filter", move |arguments| {
            let FieldValue::Function(predicate) = &arguments[0] else {
                return Err(AuthError::internal("Missing filter predicate"));
            };
            let predicate_root = predicate_root.upgrade().unwrap();
            let results = references
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    predicate.call_with(
                        &"ignored receiver".into(),
                        &[
                            value.clone(),
                            index.into(),
                            predicate_root.get().unwrap().clone(),
                        ],
                    )
                })
                .collect::<AuthResult<Vec<_>>>()?;
            let mut events = events.lock().unwrap();
            let results = events.observe(&results.into())?;
            events.record("filter:predicate", [("results".into(), results)]);
            Ok(returned.clone())
        });
        let sorted_array = sorted.value.as_array().unwrap().clone();
        let returned = concatenated.value.clone();
        filtered.method("concat", move |arguments| {
            sorted_array.set(0, retained.clone())?;
            let additions = arguments[0].as_array().unwrap();
            for (index, value) in additions.iter()?.enumerate() {
                sorted_array.set(index + 1, value?)?;
            }
            Ok(returned.clone())
        });
        let returned = sorted.value.clone();
        let events = observer;
        concatenated.method("sort", move |arguments| {
            let FieldValue::Function(compare) = &arguments[0] else {
                return Err(AuthError::internal("Missing sort comparator"));
            };
            let result = compare.call_with(
                &"ignored receiver".into(),
                &returned.as_array().unwrap().snapshot()?,
            )?;
            let mut events = events.lock().unwrap();
            let result = events.observe(&result)?;
            events.record("sort:compare", [("result".into(), result)]);
            Ok(returned.clone())
        });
        let receiver = sorted.receiver();
        sorted.method("at", move |arguments| {
            assert_eq!(arguments, &[FieldValue::from(-1)]);
            let receiver = receiver.upgrade().unwrap();
            let entries = receiver.get().unwrap().as_array().unwrap();
            Ok(entries.get(entries.len()? - 1)?.unwrap_or_default())
        });
        self.keep("root", root);
        self.keep("filtered", filtered);
        self.keep("concatenated", concatenated);
        self.keep("sorted", sorted);
        Ok(())
    }

    fn update_failure(&mut self, scenario: &Json, observer: Observer) -> AuthResult<()> {
        let envelope = Root::new("function", 0, observer.clone());
        envelope.data(FieldMap::from([
            ("session".into(), session("target", 60_000).into()),
            ("user".into(), user().into()),
            ("discardedEnvelopeField".into(), "native-before".into()),
        ]));
        let root = Root::new("function", 0, observer);
        let original = self.original.clone();
        if scenario["failure"] == "getter" {
            root.failing_getter("filter", original);
        } else {
            root.method("filter", move |_| {
                Err(AuthError::from_thrown(original.clone()))
            });
        }
        self.keep("envelope", envelope);
        self.keep("root", root);
        Ok(())
    }

    fn refresh(&mut self, scenario: &Json, observer: Observer) -> AuthResult<()> {
        let reference = Root::new("date", -6_000, observer.clone());
        reference.data(FieldMap::from([
            ("token".into(), "target".into()),
            ("expiresAt".into(), (NOW + 60_000).into()),
            ("extra".into(), self.references[0].model_property("extra")?),
        ]));
        let expiry = Root::new(
            scenario["expiry"].as_str().unwrap(),
            60_000,
            observer.clone(),
        );
        let native_session = Root::new("date", -7_000, observer.clone());
        native_session.data(FieldMap::from([
            ("expiresAt".into(), expiry.value.clone()),
            ("token".into(), "target".into()),
            ("marker".into(), "preserved-date-root".into()),
        ]));
        let envelope = Root::new("function", 0, observer.clone());
        envelope.data(FieldMap::from([
            ("session".into(), native_session.value.clone()),
            ("user".into(), user().into()),
            ("discardedEnvelopeField".into(), "native".into()),
        ]));
        let milliseconds = Root::new("object", 0, observer);
        milliseconds.method("valueOf", |arguments| {
            assert!(arguments.is_empty());
            Ok((NOW + 59_999).into())
        });
        let original = self.original.clone();
        if scenario["failure"] == "getter" {
            expiry.failing_getter("getTime", original);
        } else {
            let failure = scenario["failure"] == "method";
            let returned = milliseconds.value.clone();
            expiry.method("getTime", move |arguments| {
                assert!(arguments.is_empty());
                if failure {
                    Err(AuthError::from_thrown(original.clone()))
                } else {
                    Ok(returned.clone())
                }
            });
        }
        self.keep("reference", reference);
        self.keep("expiry", expiry);
        self.keep("nativeSession", native_session);
        self.keep("envelope", envelope);
        self.keep("milliseconds", milliseconds);
        Ok(())
    }
}

pub(super) struct Root {
    pub(super) value: FieldValue,
    expected: Arc<OnceLock<FieldValue>>,
    properties: Arc<Properties>,
}

impl Root {
    pub(super) fn new(kind: &str, offset: i64, observer: Observer) -> Self {
        let expected = Arc::new(OnceLock::new());
        let properties = Arc::new(Properties {
            fields: FieldMap::new().into(),
            observer,
            expected: Arc::downgrade(&expected),
        });
        let fields = FieldObject::from_source(properties.clone());
        let value: FieldValue = match kind {
            "date" => {
                FieldDate::from_milliseconds_with_properties((NOW + offset) as f64, fields).into()
            }
            "function" => {
                FieldFunction::contextual_with_properties(|_, _| Ok(FieldValue::Undefined), fields)
                    .into()
            }
            "array" => FieldArray::from_values_with_properties(Vec::new(), fields).into(),
            _ => fields.into(),
        };
        expected.set(value.clone()).unwrap();
        Self {
            value,
            expected,
            properties,
        }
    }

    fn data(&self, data: FieldMap) {
        for (name, value) in data {
            self.properties
                .fields
                .define_own_property(name, crate::FieldPropertyDescriptor::data(value).into())
                .unwrap();
        }
    }

    pub(super) fn receiver(&self) -> Weak<OnceLock<FieldValue>> {
        Arc::downgrade(&self.expected)
    }

    pub(super) fn method(
        &self,
        name: &str,
        callback: impl Fn(&[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) {
        let events = self.properties.observer.clone();
        let expected = Arc::downgrade(&self.expected);
        let phase = format!("call:{name}");
        let method = FieldFunction::contextual(move |receiver, arguments| {
            call(&events, &phase, receiver, &expected, arguments)?;
            callback(arguments)
        });
        self.properties.method(name, Ok(method.into()));
    }

    fn failing_getter(&self, name: &str, error: FieldValue) {
        self.properties.method(name, Err(error));
    }
}

fn call(
    observer: &Observer,
    phase: &str,
    receiver: &FieldValue,
    expected: &Receiver,
    arguments: &[FieldValue],
) -> AuthResult<()> {
    let expected = expected
        .upgrade()
        .ok_or_else(|| AuthError::internal("Native contract receiver was released"))?;
    observer
        .lock()
        .unwrap()
        .call(phase, receiver, expected.get().unwrap(), arguments)
}

struct Properties {
    fields: FieldObject,
    observer: Observer,
    expected: Receiver,
}

impl Properties {
    fn method(&self, name: &str, value: Result<FieldValue, FieldValue>) {
        let observer = self.observer.clone();
        let expected = self.expected.clone();
        let phase = format!("get:{name}");
        let getter = FieldFunction::contextual(move |receiver, _| {
            call(&observer, &phase, receiver, &expected, &[])?;
            value.clone().map_err(AuthError::from_thrown)
        });
        self.fields
            .define_own_property(
                name,
                crate::FieldPropertyDescriptor {
                    enumerable: false,
                    configurable: true,
                    property: crate::FieldProperty::Accessor {
                        get: Some(getter),
                        set: None,
                    },
                }
                .into(),
            )
            .unwrap();
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
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        FieldValue::Object(self.fields.clone()).enumerable_fields()
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
