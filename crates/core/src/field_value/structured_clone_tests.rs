#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify graph ownership, getter order, and failure atomicity; source errors propagate."
)]

use super::*;
use crate::AuthRecordFields;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use std::sync::Mutex;

#[path = "structured_clone_tests/native_records.rs"]
mod native_records;
#[path = "structured_clone_tests/restoration.rs"]
mod restoration;

type Events = Arc<Mutex<Vec<String>>>;
type OnRead = Box<dyn Fn(&str) -> AuthResult<()> + Send + Sync>;

struct Source {
    name: &'static str,
    fields: Mutex<FieldMap>,
    events: Events,
    on_read: OnRead,
    target: Option<Arc<Mutex<Option<FieldObject>>>>,
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.events
            .lock()
            .map_err(poisoned)?
            .push(format!("keys:{}", self.name));
        FieldObject::from(self.fields.lock().map_err(poisoned)?.clone()).own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .lock()
            .map_err(poisoned)?
            .get(name)
            .cloned()
            .map(FieldPropertyDescriptor::data))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.events
            .lock()
            .map_err(poisoned)?
            .push(format!("get:{}.{name}", self.name));
        (self.on_read)(name)?;
        Ok(self.fields.lock().map_err(poisoned)?.get(name).cloned())
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        let _ = self.fields.lock().map_err(poisoned)?.insert(name, value);
        Ok(true)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        let _ = self.fields.lock().map_err(poisoned)?.remove(name);
        Ok(true)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Graph traversal must read each property before the next getter",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn clone_seed(&self) -> AuthResult<Option<ObjectCloneSeed>> {
        let Some(target) = &self.target else {
            return Ok(None);
        };
        let seed = FieldObject::from(FieldMap::new()).clone_seed()?;
        *target.lock().map_err(poisoned)? = Some(seed.object.clone());
        Ok(Some(seed))
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> AuthError {
    AuthError::internal("Graph contract lock poisoned")
}

#[test]
fn getters_follow_depth_first_property_order_and_keep_undefined_distinct_from_deletion()
-> AuthResult<()> {
    let events = Events::default();
    let root = Arc::new(Source {
        name: "root",
        fields: Mutex::new(FieldMap::from([
            ("child".into(), FieldValue::Undefined),
            ("2".into(), "two".into()),
            ("1".into(), "one".into()),
            ("later".into(), 1.into()),
            ("removed".into(), "delete-before-read".into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])),
        events: events.clone(),
        on_read: Box::new(|_| Ok(())),
        target: None,
    });
    let weak = Arc::downgrade(&root);
    let child = FieldObject::from_source(Arc::new(Source {
        name: "child",
        fields: Mutex::new([("value".into(), "child-value".into())].into()),
        events: events.clone(),
        on_read: Box::new(move |_| {
            let root = weak
                .upgrade()
                .ok_or_else(|| AuthError::internal("Missing root source"))?;
            FieldObject::from_source(root.clone()).set("later", 2.into())?;
            let _ = root.delete("removed")?;
            FieldObject::from_source(root).set("appended", "not-enumerated".into())?;
            Ok(())
        }),
        target: None,
    }));
    FieldObject::from_source(root.clone()).set("child", FieldValue::Object(child))?;
    let value = FieldValue::Object(FieldObject::from_source(root.clone()));
    let cloned = StructuredCloneContext::new().clone_value(&value)?;
    assert_eq!(
        *events.lock().map_err(poisoned)?,
        [
            "keys:root",
            "get:root.1",
            "get:root.2",
            "get:root.child",
            "keys:child",
            "get:child.value",
            "get:root.later",
            "get:root.ownUndefined",
        ]
    );
    assert_eq!(
        cloned.enumerable_fields()?,
        FieldMap::from([
            ("1".into(), "one".into()),
            ("2".into(), "two".into()),
            (
                "child".into(),
                FieldMap::from([("value".into(), "child-value".into())]).into()
            ),
            ("later".into(), 2.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
    );
    assert_eq!(
        cloned
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["1", "2", "child", "later", "ownUndefined"]
    );
    assert!(
        root.fields
            .lock()
            .map_err(poisoned)?
            .contains_key("appended")
    );
    assert!(
        !root
            .fields
            .lock()
            .map_err(poisoned)?
            .contains_key("removed")
    );
    Ok(())
}

#[test]
fn failed_traversal_does_not_publish_partial_aliases_and_retry_observes_fresh_values()
-> AuthResult<()> {
    let mut context = StructuredCloneContext::new();
    let date = FieldValue::from(FieldDate::from_milliseconds(42.0));
    let existing = context.clone_value(&date)?;
    let cycle = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
    cycle.set("self", FieldValue::Object(cycle.clone()))?;
    let fields = FieldMap::from([
        ("date".into(), date.clone()),
        ("cycle".into(), FieldValue::Object(cycle.clone())),
        (
            "failure".into(),
            crate::FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
        ),
    ]);
    assert!(matches!(
        context.clone_map(&fields),
        Err(AuthError::DataClone)
    ));
    assert_eq!(context.copies.len(), 1);
    cycle.set("value", 2.into())?;
    let mut retry = fields;
    let _ = retry.remove("failure");
    let copied = context.clone_map(&retry)?;
    let copied_cycle = copied
        .get("cycle")
        .ok_or_else(|| AuthError::internal("Missing copied cycle"))?;
    assert!(
        copied_cycle
            .model_property("self")?
            .strict_equals(copied_cycle)
    );
    assert_eq!(copied_cycle.model_property("value")?, 2.into());
    assert!(
        copied
            .get("date")
            .is_some_and(|value| value.strict_equals(&existing))
    );
    let _ = cycle.delete("self")?;
    let _ = copied_cycle
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected copied cycle"))?
        .delete("self")?;
    Ok(())
}

struct RejectedRecord {
    target: Arc<Mutex<Option<FieldObject>>>,
    error: Mutex<Option<AuthError>>,
}

impl FieldObjectSource for RejectedRecord {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(None)
    }
    fn get_with_receiver(&self, _: &str, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(None)
    }
    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Ok(true)
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Ok(FieldMap::new())
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn clone_seed(&self) -> AuthResult<Option<ObjectCloneSeed>> {
        let object = FieldObject::from(FieldMap::new());
        *self.target.lock().map_err(poisoned)? = Some(object.clone());
        let error = self
            .error
            .lock()
            .map_err(poisoned)?
            .take()
            .ok_or_else(|| AuthError::internal("Repeated rejected record conversion"))?;
        Ok(Some(ObjectCloneSeed {
            object,
            state: Vec::new(),
            original_record: None,
            prepare: Box::new(move |_, _, _| Err(error)),
        }))
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

#[test]
fn failed_native_preparation_fills_no_objects_and_retains_the_original_error() -> AuthResult<()> {
    let target = Arc::new(Mutex::new(None));
    let cycle_target = Arc::new(Mutex::new(None));
    let message = "Native record conversion failed".to_owned();
    let allocation = message.as_ptr();
    let rejection = FieldObject::from_source(Arc::new(RejectedRecord {
        target: target.clone(),
        error: Mutex::new(Some(AuthError::Internal(message))),
    }));
    let cycle = FieldObject::from_source(Arc::new(Source {
        name: "cycle",
        fields: Mutex::new(FieldMap::new()),
        events: Events::default(),
        on_read: Box::new(|_| Ok(())),
        target: Some(cycle_target.clone()),
    }));
    cycle.set("self", FieldValue::Object(cycle.clone()))?;
    cycle.set("rejection", FieldValue::Object(rejection))?;
    let mut context = StructuredCloneContext::new();
    let result = context.clone_value(&FieldValue::Object(cycle.clone()));
    let _ = cycle.delete("self")?;
    assert!(matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() == allocation));
    assert!(context.copies.is_empty());
    assert!(
        target
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| AuthError::internal("Missing rejected clone target"))?
            .snapshot_fields()?
            .is_empty()
    );
    assert!(
        cycle_target
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| AuthError::internal("Missing cyclic clone target"))?
            .snapshot_fields()?
            .is_empty()
    );
    Ok(())
}

#[test]
fn deferred_snapshot_failure_does_not_publish_an_earlier_cyclic_graph() -> AuthResult<()> {
    let observed = Arc::new(Mutex::new(None));
    let source = FieldObject::from_source(Arc::new(Source {
        name: "cycle",
        fields: Mutex::new(FieldMap::new()),
        events: Events::default(),
        on_read: Box::new(|_| Ok(())),
        target: Some(observed.clone()),
    }));
    source.set("self", FieldValue::Object(source.clone()))?;
    let mut base = StructuredCloneContext::deferred();
    let first = base.clone_value(&FieldValue::Object(source.clone()))?;
    let first_target = observed
        .lock()
        .map_err(poisoned)?
        .clone()
        .ok_or_else(|| AuthError::internal("Missing first clone target"))?;
    source.set(
        "failure",
        crate::FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
    )?;
    let mut working = StructuredCloneContext::deferred();
    let failed = working.clone_value(&FieldValue::Object(source.clone()));
    assert!(matches!(failed, Err(AuthError::DataClone)));
    drop((base, working));
    assert!(first_target.snapshot_fields()?.is_empty());
    assert!(first.enumerable_fields()?.is_empty());
    assert!(
        observed
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| AuthError::internal("Missing second clone target"))?
            .snapshot_fields()?
            .is_empty()
    );
    let _ = source.delete("self")?;
    Ok(())
}

#[test]
fn user_view_clone_follows_own_order_and_keeps_hidden_aliases_and_original_errors() -> AuthResult<()>
{
    for (unconfigured, throws) in [(false, false), (true, false), (false, true)] {
        let events = Events::default();
        let message = "public-user-clone-original".to_owned();
        let allocation = message.as_ptr() as usize;
        let failure = Arc::new(Mutex::new(Some(AuthError::Internal(message))));
        let source =
            |name: &'static str, fields: FieldMap| {
                let failure = failure.clone();
                FieldValue::Object(FieldObject::from_source(Arc::new(Source {
                    name,
                    fields: Mutex::new(fields),
                    events: events.clone(),
                    on_read: Box::new(move |_| {
                        if throws && name == "extra" {
                            return Err(failure.lock().map_err(poisoned)?.take().ok_or_else(
                                || AuthError::internal("Repeated User clone failure"),
                            )?);
                        }
                        Ok(())
                    }),
                    target: None,
                })))
            };
        let date = FieldValue::from(FieldDate::from_milliseconds(42.0));
        let extra = source("extra", [("value".into(), "extra".into())].into());
        let mut user = crate::UserView::try_from(FieldMap::from([
            ("extra".into(), extra.clone()),
            (
                "10".into(),
                source("10", [("value".into(), "ten".into())].into()),
            ),
            (
                "2".into(),
                source("2", [("value".into(), "two".into())].into()),
            ),
            (
                "name".into(),
                source("native", [("value".into(), "native".into())].into()),
            ),
            ("createdAt".into(), date.clone()),
            ("id".into(), "owner".into()),
        ]))?;
        user.metadata = source(
            "hidden",
            [
                ("date".into(), date.clone()),
                ("alias".into(), extra.clone()),
            ]
            .into(),
        );
        if unconfigured {
            user.visible_fields = None;
        }
        let visible = user.visible_fields.clone();
        let result = user.structured_clone(&mut StructuredCloneContext::new());
        let mut expected_events = vec![
            "keys:2",
            "get:2.value",
            "keys:10",
            "get:10.value",
            "keys:extra",
            "get:extra.value",
        ];
        if throws {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "public-user-clone-original" && message.as_ptr() as usize == allocation)
            );
        } else {
            expected_events.extend([
                "keys:native",
                "get:native.value",
                "keys:hidden",
                "get:hidden.date",
                "get:hidden.alias",
            ]);
            let cloned = result?;
            let fields = cloned.field_values()?;
            assert_eq!(cloned.visible_fields, visible);
            assert_eq!(
                fields.keys().map(String::as_str).collect::<Vec<_>>(),
                ["2", "10", "extra", "name", "createdAt", "id"]
            );
            assert_eq!(
                cloned.field_order,
                ["2", "10", "extra", "name", "createdAt", "id"]
            );
            let copied_date = cloned.created_at.field_value();
            assert!(!copied_date.strict_equals(&date));
            assert!(
                cloned
                    .metadata
                    .model_property("date")?
                    .strict_equals(&copied_date)
            );
            let copied_extra = fields
                .get("extra")
                .ok_or_else(|| AuthError::internal("Missing cloned extra field"))?;
            assert!(!copied_extra.strict_equals(&extra));
            assert!(
                cloned
                    .metadata
                    .model_property("alias")?
                    .strict_equals(copied_extra)
            );
            assert_eq!(
                fields,
                FieldMap::from([
                    (
                        "2".into(),
                        FieldMap::from([("value".into(), "two".into())]).into(),
                    ),
                    (
                        "10".into(),
                        FieldMap::from([("value".into(), "ten".into())]).into(),
                    ),
                    (
                        "extra".into(),
                        FieldMap::from([("value".into(), "extra".into())]).into(),
                    ),
                    (
                        "name".into(),
                        FieldMap::from([("value".into(), "native".into())]).into(),
                    ),
                    ("createdAt".into(), copied_date),
                    ("id".into(), "owner".into()),
                ])
            );
        }
        assert_eq!(*events.lock().map_err(poisoned)?, expected_events);
        assert_eq!(user.visible_fields, visible);
        assert_eq!(
            user.field_order,
            ["extra", "10", "2", "name", "createdAt", "id"]
        );
    }
    Ok(())
}
