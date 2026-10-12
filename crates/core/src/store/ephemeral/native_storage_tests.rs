#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The tests assert native receiver identity, exact getter traces, and persisted effects across clone and setter failures."
)]

use super::*;
use crate::{
    FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
    store::schema::EntityRole,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Probe {
    fields: FieldObject,
    receiver: Mutex<Weak<FieldObject>>,
    store: Mutex<Weak<EphemeralStore>>,
    property: &'static str,
    reads: AtomicUsize,
    values: Vec<Value>,
    failure_at: Option<usize>,
    stop_at: Option<&'static str>,
    failure: Value,
    events: Mutex<Vec<String>>,
}

impl Probe {
    fn check_receiver(&self, receiver: &Value) {
        let expected = self.receiver.lock().unwrap().upgrade().unwrap();
        assert!(receiver.strict_equals(&Value::Object((*expected).clone())));
    }

    fn reenter(&self, value: usize) -> AuthResult<()> {
        let store = self.store.lock().unwrap().upgrade();
        if let Some(store) = store {
            store.operation(|operation| {
                let table = operation.capture_table(EntityRole::DeviceCode)?;
                assert_eq!(table.len()?, 2);
                let peer = operation
                    .capture_table(EntityRole::Account)?
                    .row_at(0)?
                    .unwrap();
                peer.apply_patch([("effect".into(), (value as f64).into())].into())
            })?;
        }
        Ok(())
    }
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn get_with_receiver(&self, name: &str, receiver: &Value) -> AuthResult<Option<Value>> {
        self.check_receiver(receiver);
        if name != self.property {
            return self.fields.get(name);
        }
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        self.events
            .lock()
            .unwrap()
            .push(format!("get:{name}:{read}"));
        self.reenter(read)?;
        if self.failure_at == Some(read) {
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        match self.values.get(read - 1) {
            Some(value) => Ok(Some(value.clone())),
            None => self.fields.get(name),
        }
    }

    fn set_with_receiver(&self, name: String, value: Value, receiver: &Value) -> AuthResult<bool> {
        self.check_receiver(receiver);
        self.events.lock().unwrap().push(format!("set:{name}"));
        if self.stop_at == Some(name.as_str()) {
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        self.fields.set(name, value)?;
        Ok(true)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native rows must read properties at the operation boundary",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

#[derive(Default)]
struct ProbeOptions {
    property: &'static str,
    values: Vec<Value>,
    failure_at: Option<usize>,
    stop_at: Option<&'static str>,
}

fn probe(fields: FieldMap, options: ProbeOptions) -> (Arc<Probe>, Arc<FieldObject>) {
    let source = Arc::new(Probe {
        fields: fields.into(),
        receiver: Mutex::default(),
        store: Mutex::default(),
        property: options.property,
        reads: AtomicUsize::new(0),
        values: options.values,
        failure_at: options.failure_at,
        stop_at: options.stop_at,
        failure: FieldMap::from([("failure".into(), "original native storage failure".into())])
            .into(),
        events: Mutex::default(),
    });
    let object = Arc::new(FieldObject::from_source(source.clone()));
    *source.receiver.lock().unwrap() = Arc::downgrade(&object);
    (source, object)
}

#[test]
fn native_storage_clones_shared_rows_once_per_graph_and_retains_getter_effects() -> AuthResult<()> {
    for failure_at in [None, Some(1), Some(2)] {
        let child: Value = FieldMap::from([("payload".into(), true.into())]).into();
        let (source, object) = probe(
            FieldMap::from([
                ("id".into(), "device".into()),
                ("deviceCode".into(), child.clone()),
                ("alias".into(), child.clone()),
            ]),
            ProbeOptions {
                property: "deviceCode",
                failure_at,
                ..Default::default()
            },
        );
        let peer = FieldObject::from(FieldMap::from([
            ("id".into(), "peer".into()),
            ("effect".into(), 0.into()),
        ]));
        let store = Arc::new(EphemeralStore::from_storage_objects(
            Arc::default(),
            [
                (
                    "deviceCode".into(),
                    vec![(*object).clone(), (*object).clone()],
                ),
                ("account".into(), vec![peer.clone()]),
            ],
        )?);
        *source.store.lock().unwrap() = Arc::downgrade(&store);
        assert!(source.events.lock().unwrap().is_empty());
        let table = store.operation(|operation| operation.capture_table(EntityRole::DeviceCode))?;
        let first = table.row_at(0)?.unwrap();
        assert!(first.same_row(&table.row_at(1)?.unwrap()));
        assert!(
            first
                .field_value()
                .strict_equals(&Value::Object((*object).clone()))
        );
        let result = store.begin_transaction();
        assert_eq!(source.reads.load(Ordering::SeqCst), failure_at.unwrap_or(2));
        assert_eq!(
            peer.get("effect")?,
            Some((failure_at.unwrap_or(2) as f64).into())
        );
        match (failure_at, result) {
            (Some(_), Err(error)) => {
                assert!(error.into_thrown_value()?.strict_equals(&source.failure))
            }
            (None, Ok((base, isolated, _))) => {
                let base_row = base.table("deviceCode")?.row_at(0)?.unwrap();
                let isolated_table = isolated
                    .operation(|operation| operation.capture_table(EntityRole::DeviceCode))?;
                let copied = isolated_table.row_at(0)?.unwrap();
                assert!(copied.same_row(&isolated_table.row_at(1)?.unwrap()));
                assert!(!copied.same_row(&first));
                assert!(!copied.same_row(&base_row));
                let copied_child = copied.field("deviceCode")?.unwrap();
                assert!(copied_child.strict_equals(&copied.field("alias")?.unwrap()));
                assert!(!copied_child.strict_equals(&child));
                assert_eq!(
                    base.table("account")?.row_at(0)?.unwrap().field("effect")?,
                    Some(1.into())
                );
                assert_eq!(
                    isolated.storage_rows(EntityRole::Account)?[0].get("effect"),
                    Some(&2.into())
                );
                copied.apply_patch([("deviceCode".into(), "isolated".into())].into())?;
                assert_eq!(
                    isolated_table.row_at(1)?.unwrap().field("deviceCode")?,
                    Some("isolated".into())
                );
                assert!(
                    source
                        .fields
                        .get("deviceCode")?
                        .unwrap()
                        .strict_equals(&child)
                );
                assert_eq!(source.reads.load(Ordering::SeqCst), 2);
            }
            _ => {
                return Err(AuthError::internal(
                    "Native clone outcome differs from the selected source failure",
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn native_patch_preserves_receiver_and_partial_writes_without_reading_unrelated_getters()
-> AuthResult<()> {
    let (source, object) = probe(
        FieldMap::from([
            ("id".into(), "key".into()),
            ("unrelated".into(), "must not read".into()),
        ]),
        ProbeOptions {
            property: "unrelated",
            failure_at: Some(1),
            stop_at: Some("stop"),
            ..Default::default()
        },
    );
    let store = EphemeralStore::from_storage_objects(
        Arc::default(),
        [("apikey".into(), vec![(*object).clone()])],
    )?;
    let result = store.operation(|operation| {
        operation
            .capture_table(EntityRole::ApiKey)?
            .row_at(0)?
            .unwrap()
            .apply_patch(
                [
                    ("first".into(), 1.into()),
                    ("stop".into(), 2.into()),
                    ("late".into(), 3.into()),
                ]
                .into(),
            )
    });
    assert!(
        result
            .unwrap_err()
            .into_thrown_value()?
            .strict_equals(&source.failure)
    );
    assert_eq!(*source.events.lock().unwrap(), ["set:first", "set:stop"]);
    assert_eq!(
        source.fields.snapshot_fields()?,
        FieldMap::from([
            ("id".into(), "key".into()),
            ("unrelated".into(), "must not read".into()),
            ("first".into(), 1.into()),
        ])
    );
    Ok(())
}

#[test]
fn native_increment_rereads_numeric_getters_and_retains_completed_writes() -> AuthResult<()> {
    let (source, object) = probe(
        FieldMap::from([
            ("id".into(), "key".into()),
            ("remaining".into(), 5.into()),
            ("requestCount".into(), 0.into()),
        ]),
        ProbeOptions {
            property: "remaining",
            values: vec![5.into(), "7".into()],
            stop_at: Some("requestCount"),
            ..Default::default()
        },
    );
    let store = EphemeralStore::from_storage_objects(
        Arc::default(),
        [("apikey".into(), vec![(*object).clone()])],
    )?;
    let result = store.operation(|operation| {
        operation
            .capture_table(EntityRole::ApiKey)?
            .row_at(0)?
            .unwrap()
            .increment_number_fields(&[("remaining".into(), -1.0), ("requestCount".into(), 1.0)])
    });
    assert!(
        result
            .unwrap_err()
            .into_thrown_value()?
            .strict_equals(&source.failure)
    );
    assert_eq!(
        *source.events.lock().unwrap(),
        [
            "get:remaining:1",
            "get:remaining:2",
            "set:remaining",
            "set:requestCount"
        ]
    );
    assert_eq!(source.fields.get("remaining")?, Some("7-1".into()));
    assert_eq!(source.fields.get("requestCount")?, Some(0.into()));
    Ok(())
}

#[test]
fn native_patch_assigns_numeric_storage_keys_before_later_setter_failure() -> AuthResult<()> {
    let (source, object) = probe(
        FieldMap::from([("id".into(), "key".into())]),
        ProbeOptions {
            property: "unrelated",
            stop_at: Some("2"),
            ..Default::default()
        },
    );
    let store = EphemeralStore::from_storage_objects(
        Arc::default(),
        [("apikey".into(), vec![(*object).clone()])],
    )?;
    let result = store.operation(|operation| {
        operation
            .capture_table(EntityRole::ApiKey)?
            .row_at(0)?
            .unwrap()
            .apply_patch(
                [
                    ("2".into(), 2.into()),
                    ("1".into(), 1.into()),
                    ("late".into(), 3.into()),
                ]
                .into(),
            )
    });
    assert!(
        result
            .unwrap_err()
            .into_thrown_value()?
            .strict_equals(&source.failure)
    );
    assert_eq!(*source.events.lock().unwrap(), ["set:1", "set:2"]);
    assert_eq!(
        source.fields.snapshot_fields()?,
        FieldMap::from([("1".into(), 1.into()), ("id".into(), "key".into()),])
    );
    Ok(())
}

#[test]
fn mixed_owned_and_native_rows_keep_the_same_identity_during_clone_origin_tracking()
-> AuthResult<()> {
    let store = EphemeralStore::default();
    store.operation(|operation| {
        let table = operation.capture_table(EntityRole::DeviceCode)?;
        let owned = table.push([("id".into(), "same".into())].into())?;
        let Value::Object(object) = owned.field_value() else {
            return Err(AuthError::internal(
                "The owned row must expose an object handle",
            ));
        };
        let native = table.push_object(object)?;
        assert!(owned.same_row(&native));
        let mut context = crate::StructuredCloneContext::new();
        let cloned = table.deep_clone_with(&mut context, |source, _, _| {
            assert!(source.same_row(&owned));
        })?;
        assert!(
            cloned
                .row_at(0)?
                .unwrap()
                .same_row(&cloned.row_at(1)?.unwrap())
        );
        assert!(table.contains_ref(&owned)?);
        assert!(table.contains_ref(&native)?);
        Ok(())
    })
}

#[tokio::test]
async fn native_transaction_commit_reads_only_the_live_id_without_repeating_other_getters()
-> AuthResult<()> {
    let (source, object) = probe(
        FieldMap::from([
            ("id".into(), "user".into()),
            ("name".into(), "Original".into()),
        ]),
        ProbeOptions {
            property: "name",
            failure_at: Some(3),
            ..Default::default()
        },
    );
    let store = EphemeralStore::from_storage_objects(
        Arc::default(),
        [("user".into(), vec![(*object).clone()])],
    )?;
    let (base, isolated, queue) = store.begin_adapter_transaction()?;
    store
        .commit_adapter_transaction(base, isolated, queue)
        .await?;
    assert_eq!(*source.events.lock().unwrap(), ["get:name:1", "get:name:2"]);
    let retained = store.operation(|operation| {
        Ok(operation
            .capture_table(EntityRole::User)?
            .row_at(0)?
            .unwrap()
            .field_value())
    })?;
    assert!(retained.strict_equals(&Value::Object((*object).clone())));
    Ok(())
}
