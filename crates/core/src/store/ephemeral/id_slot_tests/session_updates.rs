use super::*;
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, SessionUpdate};
use crate::store::{MemoryCacheAdapter, SecondaryStorage, secondary::SecondaryStore};
use crate::user_fields::UserFieldType;

pub(super) fn seed() -> AuthResult<SessionView> {
    Ok(SessionView {
        field_order: Default::default(),
        visible_fields: Some(Default::default()),
        id: crate::SchemaValue::from_field(Value::Number(1.0)),
        expires_at: date(EXPIRES_AT)?.into(),
        token: "id-update-token".into(),
        created_at: date(CREATED_AT)?.into(),
        updated_at: date(CREATED_AT)?.into(),
        ip_address: Some("198.51.100.4".into()).into(),
        user_agent: Some("id-update-test".into()).into(),
        user_id: crate::SchemaValue::from_field(Value::Number(1.0)),
        impersonated_by: None.into(),
        active_organization_id: None.into(),
        active_team_id: None.into(),
        active: true,
        additional_fields: Default::default(),
    })
}

#[tokio::test]
async fn memory_session_updates_bind_native_id_values_at_the_adapter_slot() -> AuthResult<()> {
    for (supplied, expected_id, public_id) in [
        (None, 300.0, "300"),
        (Some(Value::Undefined), 1.0, "1"),
        (Some(Value::Null), 1.0, "1"),
        (Some(Value::Bool(false)), 1.0, "1"),
        (Some(Value::Number(0.0)), 1.0, "1"),
        (Some(Value::Number(2.0)), 2.0, "2"),
        (Some(Value::from("002")), 2.0, "2"),
        (Some(Value::from(Vec::<Value>::new())), 0.0, "0"),
        (Some(Value::from(vec![Value::Number(2.0)])), 2.0, "2"),
        (Some(Value::from("invalid")), 1.0, "1"),
    ] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let _ = config.session.fields_mut().insert("id".into(), id_policy());
        let store = EphemeralStore::new(Arc::new(config));
        let mut stored = seed()?;
        store.lock()?.sessions.push(stored.clone());
        let updated_at = date("2031-01-02T03:04:05.000Z")?;
        let result = required(
            store
                .update_session_with_writer(
                    stored.token.typed().unwrap(),
                    SessionUpdate {
                        id: Some("300".into()),
                        updated_at: Some(updated_at.clone()),
                        additional_fields: supplied
                            .map(|value| FieldMap::from([("id".into(), value)]))
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                    None,
                )
                .await?,
        )?;
        stored.id = crate::SchemaValue::from_field(Value::Number(expected_id));
        stored.updated_at = updated_at.into();
        assert_eq!(store.lock()?.sessions.snapshot()?, [stored.clone()]);
        stored.id = public_id.into();
        stored.user_id = "1".into();
        assert_eq!(result, stored);
        assert_eq!(
            required(store.get_session(stored.token.typed().unwrap()).await?)?,
            stored
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_id_alias_updates_preserve_storage_order_and_output() -> AuthResult<()> {
    for (id_first, supplied, alias, stored_id, public_id) in [
        (
            true,
            Value::from("100"),
            Value::from("200"),
            Value::from("200"),
            "200",
        ),
        (
            false,
            Value::from("100"),
            Value::from("200"),
            Value::Number(100.0),
            "100",
        ),
        (
            false,
            Value::Undefined,
            Value::from("200"),
            Value::from("200"),
            "200",
        ),
        (
            true,
            Value::from("100"),
            Value::Undefined,
            Value::Number(100.0),
            "100",
        ),
    ] {
        let trace = Events::default();
        let output_trace = trace.clone();
        let alias_field = UserFieldConfig {
            field_type: UserFieldType::Json,
            field_name: Some("id".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    record(
                        &output_trace,
                        json!(["alias-output", required(value.json()?)?]),
                    )?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        config.session.additional_fields = Some(
            if id_first {
                [("id".into(), id_policy()), ("aliasId".into(), alias_field)]
            } else {
                [("aliasId".into(), alias_field), ("id".into(), id_policy())]
            }
            .into(),
        );
        let store = EphemeralStore::new(Arc::new(config));
        let mut stored = seed()?;
        let _ = stored
            .additional_fields
            .insert("id".into(), Value::from("previous-alias-id"));
        store.lock()?.sessions.push(stored.clone());
        let updated_at = date("2031-01-02T03:04:05.000Z")?;
        let result = required(
            store
                .update_session_with_writer(
                    stored.token.typed().unwrap(),
                    SessionUpdate {
                        id: Some("300".into()),
                        updated_at: Some(updated_at.clone()),
                        additional_fields: [("id".into(), supplied), ("aliasId".into(), alias)]
                            .into(),
                        ..Default::default()
                    },
                    None,
                )
                .await?,
        )?;
        stored.id = crate::SchemaValue::from_field(stored_id.clone());
        stored.updated_at = updated_at.into();
        stored.additional_fields.clear();
        assert_eq!(store.lock()?.sessions.snapshot()?, [stored.clone()]);
        stored.id = public_id.into();
        stored.user_id = "1".into();
        stored.additional_fields = [("aliasId".into(), public_id.into())].into();
        assert_eq!(result, stored);
        let expected_event = json!(["alias-output", required(stored_id.json()?)?]);
        assert_eq!(events(&trace)?, [expected_event.clone()]);
        assert_eq!(
            required(store.get_session(stored.token.typed().unwrap()).await?)?,
            stored
        );
        assert_eq!(events(&trace)?, [expected_event.clone(), expected_event]);
    }
    Ok(())
}

struct TypedIdPatch;

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for TypedIdPatch {
    async fn before_update_session(
        &self,
        _: &SessionUpdate,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        Ok(DatabaseHookUpdate::Patch(SessionUpdate {
            id: Some("300".into()),
            updated_at: Some(date("2031-01-02T03:04:05.000Z")?),
            ..Default::default()
        }))
    }
}

#[tokio::test]
async fn memory_session_secondary_updates_share_the_supplied_id_precedence() -> AuthResult<()> {
    for write_database in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        config.session.store_session_in_database = Some(write_database);
        let config = Arc::new(config);
        let inner =
            Arc::new(EphemeralStore::new(config.clone()).with_hooks(vec![Arc::new(TypedIdPatch)]));
        let user = inner.create_user(user_input("owner")?).await?;
        let mut stored = seed()?;
        inner.lock()?.sessions.push(stored.clone());
        let mut cached_session = stored.clone();
        cached_session.id = "1".into();
        cached_session.user_id = "1".into();
        let mut cached = json!({"session":cached_session, "user":user});
        let cache = Arc::new(MemoryCacheAdapter::new());
        cache
            .set(
                stored.token.typed().unwrap(),
                &serde_json::to_string(&cached)?,
                None,
            )
            .await?;
        let runtime = SecondaryStore::<StatelessSchema>::new(
            inner.clone(),
            cache.clone(),
            config,
            Default::default(),
        )?;
        let result = required(
            runtime
                .update_session_fields(
                    stored.token.typed().unwrap(),
                    [("id".into(), "2".into())].into(),
                )
                .await?,
        )?;
        let updated_at = date("2031-01-02T03:04:05.000Z")?;
        cached_session.id = "2".into();
        cached_session.updated_at = updated_at.clone().into();
        assert_eq!(result, cached_session);
        assert_eq!(
            required(runtime.get_session(stored.token.typed().unwrap()).await?)?,
            cached_session
        );
        cached["session"] = serde_json::to_value(&cached_session)?;
        let actual = required(cache.get(stored.token.typed().unwrap()).await?)?;
        assert_eq!(
            serde_json::from_str::<JsonValue>(required(actual.as_str())?)?,
            cached
        );
        if write_database {
            stored.id = crate::SchemaValue::from_field(Value::Number(2.0));
            stored.updated_at = updated_at.into();
        }
        assert_eq!(inner.lock()?.sessions.snapshot()?, [stored]);
    }
    Ok(())
}
