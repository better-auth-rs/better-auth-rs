use super::*;
use crate::{
    FieldFunction, FieldObject, FieldPropertyDefinition, FieldPropertyDescriptor,
    FieldPropertyUpdate,
    field_value::FieldObjectSource,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

struct ObservedInput {
    fields: FieldObject,
    events: Events,
}

impl FieldObjectSource for ObservedInput {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        event(&self.events, "ownKeys")?;
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
        event(&self.events, "snapshot")?;
        self.fields.snapshot_fields()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn event(events: &Events, name: &str) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?
        .push(name.to_owned());
    Ok(())
}

fn getter(input: &FieldValue, name: &str, source: &'static str, events: Events) -> AuthResult<()> {
    let label = name.to_owned();
    input.define_model_property(
        name,
        FieldPropertyDefinition {
            enumerable: Some(true),
            configurable: Some(true),
            property: FieldPropertyUpdate::Accessor {
                get: Some(Some(FieldFunction::contextual(move |receiver, _| {
                    event(&events, &format!("read:{label}"))?;
                    receiver.model_property(source)
                }))),
                set: None,
            },
        },
    )
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression compares declaration order, native identity, and persisted CRUD results."
)]
async fn native_input_reads_follow_prior_callbacks_through_create_and_update() -> AuthResult<()> {
    for (asynchronous, custom) in [(false, false), (true, false), (false, true), (true, true)] {
        let events = Events::default();
        let original: FieldValue = FieldMap::from([("before".into(), true.into())]).into();
        let replacement: FieldValue = FieldMap::from([("after".into(), true.into())]).into();
        let fields = FieldMap::from([
            ("trigger".into(), true.into()),
            ("currentPayload".into(), original),
            ("currentId".into(), "before".into()),
        ])
        .into();
        let input: FieldValue = FieldObject::from_source(Arc::new(ObservedInput {
            fields,
            events: events.clone(),
        }))
        .into();
        getter(&input, "payload", "currentPayload", events.clone())?;
        getter(&input, "id", "currentId", events.clone())?;
        let mutate = {
            let input = input.clone();
            let replacement = replacement.clone();
            let events = events.clone();
            move |value: FieldValue| {
                event(&events, "transform:trigger")?;
                input.set_model_property("currentPayload", replacement.clone())?;
                input.set_model_property("currentId", "after".into())?;
                Ok(value)
            }
        };
        let transform = if asynchronous {
            UserFieldTransform::new_async(move |value| {
                let mutate = mutate.clone();
                async move {
                    tokio::task::yield_now().await;
                    mutate(value)
                }
            })
        } else {
            UserFieldTransform::new(mutate)
        };
        let fields = UserConfig {
            additional_fields: Some(
                [
                    (
                        "trigger".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                input: Some(transform),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "payload".into(),
                        UserFieldConfig {
                            field_name: Some("storedPayload".into()),
                            ..Default::default()
                        },
                    ),
                    ("id".into(), UserFieldConfig::default()),
                ]
                .into(),
            ),
        };
        let mut store = EphemeralStore::default();
        let (model, fields) = if custom {
            store
                .model_fields
                .register_custom_model("badge", Some("badges"), fields)?;
            let model = store
                .model_fields
                .resolve_model_key("badges", &|_, _| false)?;
            let fields = store
                .field_policy()
                .fields(&model, || store.organization_fields())?;
            (model, fields)
        } else {
            (ModelKey::Native(EntityRole::Jwk), fields)
        };
        let records = MemoryRecordModel::new(&store, &model, fields);
        let created = records.create(input.clone(), FieldMap::new(), true).await?;
        assert_eq!(created.get("id"), Some(&FieldValue::from("after")));
        assert!(
            created
                .get("payload")
                .is_some_and(|value| value.strict_equals(&replacement))
        );
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?,
            ["transform:trigger", "read:payload", "read:id"]
        );
        events
            .lock()
            .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?
            .clear();
        input.set_model_property("currentPayload", FieldValue::Null)?;
        input.set_model_property("currentId", "stale".into())?;
        let updated = records
            .update_by_id("after".into(), input.clone(), FieldMap::new())
            .await?
            .ok_or_else(|| AuthError::internal("The created raw record must remain present"))?;
        assert_eq!(updated, created);
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?,
            ["transform:trigger", "read:payload", "read:id"]
        );
        let stored = store.operation(|op| op.capture_table(&model)?.snapshot())?;
        assert_eq!(stored.len(), 1);
        let row = stored
            .first()
            .ok_or_else(|| AuthError::internal("Missing raw record"))?;
        assert_eq!(
            row.keys().map(String::as_str).collect::<Vec<_>>(),
            ["trigger", "storedPayload", "id"]
        );
        assert!(
            row.get("storedPayload")
                .is_some_and(|value| value.strict_equals(&replacement))
        );
        events
            .lock()
            .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?
            .clear();
        let thrown: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        input.define_model_property(
            "payload",
            FieldPropertyDefinition {
                property: FieldPropertyUpdate::Accessor {
                    get: Some(Some(FieldFunction::contextual({
                        let events = events.clone();
                        let thrown = thrown.clone();
                        move |_, _| {
                            event(&events, "read:payload")?;
                            Err(AuthError::from_thrown(thrown.clone()))
                        }
                    }))),
                    set: None,
                },
                ..Default::default()
            },
        )?;
        let failed = records
            .update_by_id("after".into(), input, FieldMap::new())
            .await;
        assert!(
            matches!(failed, Err(error) if error.raw_value().is_some_and(|value| value.strict_equals(&thrown)))
        );
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?,
            ["transform:trigger", "read:payload"]
        );
        assert_eq!(
            store.operation(|op| op.capture_table(&model)?.snapshot())?,
            stored
        );
        assert_eq!(records.find_by_id("after".into()).await?, Some(created));
        records.delete_by_id("after".into()).await?;
        assert!(
            store
                .operation(|op| op.capture_table(&model)?.snapshot())?
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression compares serial root failure, physical rows, and logical generator names."
)]
async fn custom_alias_preserves_serial_root_failure_and_logical_generator_name() -> AuthResult<()> {
    for serial in [false, true] {
        let events = Events::default();
        let mut config = crate::AuthConfig::default();
        config.advanced.database.generate_id = Some(if serial {
            crate::id::IdGeneration::Serial
        } else {
            crate::id::IdGeneration::Custom(crate::id::IdGenerator::new({
                let events = events.clone();
                move |request| {
                    event(&events, request.model)?;
                    Ok(Some("generated".into()))
                }
            }))
        });
        let mut runtime = crate::plugin_runtime::ModelFields::default();
        runtime.register_custom_model("badge", Some("badges"), UserConfig::default())?;
        let model = runtime.resolve_model_key("badges", &|_, _| false)?;
        let store = EphemeralStore::from_schema(Arc::new(config), &runtime);
        let records = MemoryRecordModel::new(
            &store,
            &model,
            store
                .field_policy()
                .fields(&model, || store.organization_fields())?,
        );
        let before = store.operation(|op| op.root_keys())?;
        assert!(before.iter().any(|key| key == "badge"));
        assert!(!before.iter().any(|key| key == "badges"));
        if serial {
            let error = records
                .create(FieldMap::new().into(), FieldMap::new(), false)
                .await
                .err()
                .ok_or_else(|| {
                    AuthError::internal("Serial creation requires the physical table")
                })?;
            assert_eq!(
                error.instrumentation_message()?,
                "Cannot read properties of undefined (reading 'length')"
            );
            assert_eq!(store.operation(|op| op.root_keys())?, before);
            store.operation(|op| {
                op.replace_physical_table("badges".into(), Some(op.table_or_empty("badges")?))
            })?;
        }
        let created = records
            .create(FieldMap::new().into(), FieldMap::new(), false)
            .await?;
        let id = if serial { "1" } else { "generated" };
        assert_eq!(created, FieldMap::from([("id".into(), id.into())]));
        let stored = store.operation(|op| op.capture_table(&model)?.snapshot())?;
        let stored_id = if serial {
            FieldValue::Number(1.0)
        } else {
            "generated".into()
        };
        assert_eq!(stored, [FieldMap::from([("id".into(), stored_id)])]);
        assert_eq!(
            store.operation(|op| op
                .capture_physical_table("badge")?
                .ok_or_else(|| AuthError::internal("Logical table must remain present"))?
                .snapshot())?,
            Vec::<FieldMap>::new()
        );
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Raw record event lock poisoned"))?,
            if serial {
                Vec::<String>::new()
            } else {
                vec!["badge".to_owned()]
            }
        );
    }
    Ok(())
}
