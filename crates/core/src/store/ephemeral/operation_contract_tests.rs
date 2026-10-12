#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contracts assert original errors, complete records, callback order, and retained identities."
)]

use super::EphemeralStore;
use crate::field_value::FieldObjectSource;
use crate::plugin_runtime::ModelFields;
use crate::store::{
    ApiKeyUsageWrite, AuthStore, RuntimeStore, StatelessSchema, schema::EntityRole,
};
use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
use crate::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldValue,
};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;
type Action = Box<dyn FnOnce() -> AuthResult<()> + Send>;

fn record(events: &Events, event: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Reentry events poisoned"))?
        .push(event.into());
    Ok(())
}

fn run_once(action: &Mutex<Option<Action>>) -> AuthResult<()> {
    let action = action
        .lock()
        .map_err(|_| AuthError::internal("Reentry action poisoned"))?
        .take();
    if let Some(action) = action {
        action()?;
    }
    Ok(())
}

struct Operand {
    tag: &'static str,
    getter: FieldFunction,
}

impl FieldObjectSource for Operand {
    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(match name {
            "tag" => Some(crate::field_value::FieldPropertyDescriptor::data(
                self.tag.into(),
            )),
            "valueOf" => Some(crate::field_value::FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: crate::field_value::FieldProperty::Accessor {
                    get: Some(self.getter.clone()),
                    set: None,
                },
            }),
            _ => None,
        })
    }

    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Err(AuthError::internal(
            "The predicate must read individual properties",
        ))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        match name {
            "tag" => Ok(Some(self.tag.into())),
            "valueOf" => self.getter.call_with(receiver, &[]).map(Some),
            _ => Ok(None),
        }
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("The predicate operand is immutable"))
    }

    fn define_own_property(
        &self,
        _: String,
        _: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("The predicate operand is immutable"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("The predicate operand is immutable"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "The predicate must read individual properties",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn operand(
    events: &Events,
    tag: &'static str,
    number: f64,
    on_read: Option<Action>,
    on_call: Option<Action>,
) -> FieldValue {
    let calls = events.clone();
    let on_call = Mutex::new(on_call);
    let method = FieldFunction::contextual(move |receiver, arguments| {
        record(&calls, format!("call:{tag}.valueOf"))?;
        assert!(arguments.is_empty());
        assert_eq!(
            receiver.as_object().expect("object receiver").get("tag")?,
            Some(tag.into())
        );
        run_once(&on_call)?;
        Ok(number.into())
    });
    let reads = events.clone();
    let on_read = Mutex::new(on_read);
    let getter = FieldFunction::contextual(move |_, _| {
        record(&reads, format!("get:{tag}.valueOf"))?;
        run_once(&on_read)?;
        Ok(method.clone().into())
    });
    FieldValue::Object(FieldObject::from_source(Arc::new(Operand { tag, getter })))
}

fn key(id: &str, remaining: f64) -> FieldMap {
    let date = || FieldDate::from_milliseconds(1_893_456_000_000.0).into();
    [
        ("id".into(), id.into()),
        ("name".into(), "Before".into()),
        ("start".into(), FieldValue::Null),
        ("prefix".into(), FieldValue::Null),
        ("key".into(), "stored-hash".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        ("refillInterval".into(), FieldValue::Null),
        ("refillAmount".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("enabled".into(), true.into()),
        ("rateLimitEnabled".into(), true.into()),
        ("rateLimitTimeWindow".into(), 60_000.0.into()),
        ("rateLimitMax".into(), 3.0.into()),
        ("requestCount".into(), 0.0.into()),
        ("remaining".into(), remaining.into()),
        ("lastRequest".into(), FieldValue::Null),
        ("expiresAt".into(), FieldValue::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("permissions".into(), FieldValue::Null),
        ("metadata".into(), FieldValue::Null),
    ]
    .into()
}

fn runtime(
    writer: &EphemeralStore,
    events: &Events,
) -> AuthResult<Arc<dyn AuthStore<StatelessSchema>>> {
    let input = events.clone();
    let output = events.clone();
    let mut fields = ModelFields::default();
    fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [(
                    "name".into(),
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                record(&input, "input:name")?;
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                record(&output, "output:name")?;
                                Ok(value)
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    );
    writer.with_runtime(Arc::new(AuthConfig::default()), Vec::new(), fields)
}

fn raw(writer: &EphemeralStore) -> AuthResult<Vec<FieldMap>> {
    writer.operation(|op| op.capture_table(EntityRole::ApiKey)?.snapshot())
}

#[tokio::test]
async fn memory_api_key_increment_updates_the_detached_selected_row() -> AuthResult<()> {
    let writer = EphemeralStore::default();
    let events = Events::default();
    let runtime = runtime(&writer, &events)?;
    let table = writer.operation(|op| op.capture_table(EntityRole::ApiKey))?;
    let target = table.push(key("target", 5.0))?;
    let other = table.push(key("other", 4.0))?;
    let retained = target.field_value();
    let marker: FieldValue = FieldMap::from([("nested".into(), true.into())]).into();
    let reader = writer.clone();
    let getter_events = events.clone();
    let getter_row = target.clone();
    let updater = writer.clone();
    let call_events = events.clone();
    let call_row = target.clone();
    let live = retained.clone();
    let named = marker.clone();
    let probe = operand(
        &events,
        "first",
        5.0,
        Some(Box::new(move || {
            reader.operation(|op| {
                assert!(
                    op.capture_table(EntityRole::ApiKey)?
                        .contains_ref(&getter_row)?
                );
                assert_eq!(getter_row.field("name")?, Some("Before".into()));
                record(&getter_events, "get:first.reentry")
            })
        })),
        Some(Box::new(move || {
            updater.operation(|op| {
                let object = live.as_object().expect("retained row");
                object.set("name", named)?;
                object.set("remaining", 7.0.into())?;
                record(&call_events, "nested:mutate-retained")?;
                let active = op.capture_table(EntityRole::ApiKey)?;
                op.replace_table(EntityRole::ApiKey, active.without_refs(&[call_row])?)?;
                record(&call_events, "nested:rebind")?;
                let _ = op
                    .capture_table(EntityRole::ApiKey)?
                    .push(key("target", 10.0))?;
                record(&call_events, "nested:append-active")
            })
        })),
    );
    target.set_field("remaining".into(), probe)?;
    let result = runtime
        .write_api_key_usage(&"target".to_owned().into(), ApiKeyUsageWrite::Decrement)
        .await?;
    let result = result.expect("detached selected key");
    assert_eq!(
        *events.lock().unwrap(),
        [
            "get:first.valueOf",
            "get:first.reentry",
            "call:first.valueOf",
            "nested:mutate-retained",
            "nested:rebind",
            "nested:append-active",
            "output:name",
        ]
    );
    let mut detached = key("target", 6.0);
    let _ = detached.insert("name".into(), marker.clone());
    assert_eq!(result.field_values()?, detached);
    assert!(result.name.field_value().strict_equals(&marker));
    assert_eq!(target.snapshot()?, detached);
    assert!(retained.strict_equals(&target.field_value()));
    assert_eq!(table.snapshot()?, [detached, key("other", 4.0)]);
    assert_eq!(raw(&writer)?, [key("other", 4.0), key("target", 10.0)]);
    writer.operation(|op| {
        let current = op.capture_table(EntityRole::ApiKey)?;
        assert!(!current.contains_ref(&target)?);
        assert!(current.contains_ref(&other)?);
        Ok(())
    })
}

#[tokio::test]
async fn memory_api_key_later_predicate_error_keeps_nested_writes_without_decrement()
-> AuthResult<()> {
    let writer = EphemeralStore::default();
    let events = Events::default();
    let runtime = runtime(&writer, &events)?;
    let table = writer.operation(|op| op.capture_table(EntityRole::ApiKey))?;
    let target = table.push(key("target", 5.0))?;
    let later = table.push(key("other", 4.0))?;
    let marker: FieldValue = FieldMap::from([("nested".into(), true.into())]).into();
    let updater = writer.clone();
    let live = target.field_value();
    let named = marker.clone();
    let call_events = events.clone();
    let first = operand(
        &events,
        "first",
        5.0,
        None,
        Some(Box::new(move || {
            updater.operation(|_| {
                let object = live.as_object().expect("retained row");
                object.set("name", named)?;
                object.set("remaining", 7.0.into())?;
                record(&call_events, "nested:mutate-retained")
            })
        })),
    );
    let message = "later-memory-predicate-original".to_owned();
    let allocation = message.as_ptr();
    let rejecting = operand(
        &events,
        "later",
        0.0,
        None,
        Some(Box::new(move || Err(AuthError::Internal(message)))),
    );
    target.set_field("remaining".into(), first)?;
    later.set_field("remaining".into(), rejecting.clone())?;
    let result = runtime
        .write_api_key_usage(&"target".to_owned().into(), ApiKeyUsageWrite::Decrement)
        .await;
    assert!(result.as_ref().ok().is_none());
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message == "later-memory-predicate-original" && message.as_ptr() == allocation)
    );
    assert_eq!(
        *events.lock().unwrap(),
        [
            "get:first.valueOf",
            "call:first.valueOf",
            "nested:mutate-retained",
            "get:later.valueOf",
            "call:later.valueOf",
        ]
    );
    let mut first = key("target", 7.0);
    let _ = first.insert("name".into(), marker.clone());
    let mut second = key("other", 4.0);
    let _ = second.insert("remaining".into(), rejecting.clone());
    assert_eq!(raw(&writer)?, [first.clone(), second.clone()]);
    assert_eq!(target.snapshot()?, first);
    assert_eq!(later.snapshot()?, second);
    assert!(
        target
            .field("name")?
            .expect("retained name")
            .strict_equals(&marker)
    );
    assert!(
        later
            .field("remaining")?
            .expect("retained operand")
            .strict_equals(&rejecting)
    );
    Ok(())
}

#[tokio::test]
async fn memory_api_key_expiry_delete_publishes_the_captured_array() -> AuthResult<()> {
    let writer = EphemeralStore::default();
    let events = Events::default();
    let runtime = runtime(&writer, &events)?;
    let table = writer.operation(|op| op.capture_table(EntityRole::ApiKey))?;
    let expired = |id| {
        let mut fields = key(id, 5.0);
        let _ = fields.insert("expiresAt".into(), FieldDate::from_milliseconds(0.0).into());
        fields
    };
    let target = table.push(expired("target"))?;
    let second = table.push(expired("second"))?;
    let marker: FieldValue = FieldMap::from([("nested".into(), true.into())]).into();
    let updater = writer.clone();
    let live = target.field_value();
    let named = marker.clone();
    let captured = table.clone();
    let removed = second.clone();
    let rebound = Arc::new(Mutex::new(None));
    let remembered = rebound.clone();
    let call_events = events.clone();
    let probe = operand(
        &events,
        "expiry",
        0.0,
        None,
        Some(Box::new(move || {
            updater.operation(|op| {
                live.as_object().expect("retained row").set("name", named)?;
                record(&call_events, "nested:mutate-retained")?;
                let active = op.capture_table(EntityRole::ApiKey)?;
                op.replace_table(EntityRole::ApiKey, active.without_refs(&[removed])?)?;
                record(&call_events, "nested:rebind")?;
                let active = op.capture_table(EntityRole::ApiKey)?;
                let _ = active.push(expired("active-append"))?;
                *remembered.lock().unwrap() = Some(active);
                record(&call_events, "nested:append-active")?;
                let _ = captured.push(expired("captured-append"))?;
                record(&call_events, "nested:append-captured")
            })
        })),
    );
    target.set_field("expiresAt".into(), probe.clone())?;
    let deleted = runtime.delete_expired_api_keys().await?;
    assert_eq!(deleted, 2);
    assert_eq!(
        *events.lock().unwrap(),
        [
            "get:expiry.valueOf",
            "call:expiry.valueOf",
            "nested:mutate-retained",
            "nested:rebind",
            "nested:append-active",
            "nested:append-captured",
            "get:expiry.valueOf",
            "call:expiry.valueOf",
        ]
    );
    let mut detached = expired("target");
    detached.extend([("name".into(), marker.clone()), ("expiresAt".into(), probe)]);
    assert_eq!(target.snapshot()?, detached);
    assert!(
        target
            .field("name")?
            .expect("retained name")
            .strict_equals(&marker)
    );
    assert_eq!(
        table.snapshot()?,
        [
            detached.clone(),
            expired("second"),
            expired("captured-append")
        ]
    );
    let active = rebound.lock().unwrap().take().expect("nested active table");
    assert_eq!(active.snapshot()?, [detached, expired("active-append")]);
    assert_eq!(raw(&writer)?, [expired("captured-append")]);
    assert!(table.contains_ref(&target)?);
    assert!(table.contains_ref(&second)?);
    Ok(())
}
