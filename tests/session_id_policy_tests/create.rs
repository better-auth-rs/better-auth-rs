use super::*;
use better_auth_core::{AuthResult, CreateSession, id::IdGenerator};
use better_auth_seaorm::{SeaOrmHookContext, SeaOrmHooks};

type Events = Arc<Mutex<Vec<String>>>;

fn event(events: &Events, value: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Session create event lock poisoned"))?
        .push(value.into());
    Ok(())
}

fn input(label: Option<&str>) -> AuthResult<CreateSession> {
    Ok(CreateSession {
        inherited_fields: Default::default(),
        user_id: "owner".into(),
        expires_at: "2031-01-02T03:04:05Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .into(),
        ip_address: Some(String::new()),
        user_agent: Some(String::new()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: label
            .map(|label| [("label".into(), FieldValue::from(label))].into())
            .unwrap_or_default(),
    })
}

struct ForcedId {
    id: FieldValue,
    events: Events,
    fail: bool,
}

#[better_auth_core::database_hooks()]
impl SeaOrmHooks<BundledSchema> for ForcedId {
    async fn before_create_session(
        &self,
        input: &mut better_auth_core::FieldMap,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        event(&self.events, format!("hook:{}", input.contains_key("id")))?;
        let _ = input.insert("id".into(), self.id.clone());
        if self.fail {
            return Err(AuthError::bad_request("nested hook failure"));
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
}

async fn check_creates(database: &DatabaseConnection) -> TestResult {
    for alias_order in [None, Some(false), Some(true)] {
        let _ = session::Entity::delete_many().exec(database).await?;
        let events = Events::default();
        let generator_events = events.clone();
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                event(&generator_events, format!("generate:{}", request.model))?;
                Ok(Some("G".into()))
            })));
        if let Some(id_first) = alias_order {
            let alias = UserFieldConfig {
                field_name: Some("id".into()),
                ..Default::default()
            };
            config.session.additional_fields = Some(
                if id_first {
                    [("id".into(), id_policy()), ("aliasId".into(), alias)]
                } else {
                    [("aliasId".into(), alias), ("id".into(), id_policy())]
                }
                .into(),
            );
        }
        let store = Store::new(config, database.clone()).with_hooks(vec![Arc::new(ForcedId {
            id: "hook-id".into(),
            events: events.clone(),
            fail: false,
        })]);
        let mut create = input(None)?;
        let _ = create
            .additional_fields
            .insert("id".into(), "request-id".into());
        if alias_order.is_some() {
            let _ = create
                .additional_fields
                .insert("aliasId".into(), "alias-id".into());
        }
        let created = store.create_session(create).await?;
        let expected_id = if alias_order == Some(true) {
            "alias-id"
        } else {
            "hook-id"
        };
        assert_eq!(created.id.typed()?, expected_id);
        if alias_order.is_some() {
            assert_eq!(
                created.additional_fields.get("aliasId"),
                Some(&FieldValue::from(expected_id))
            );
        }
        let stored = session::Model {
            id: expected_id.into(),
            token: created.token.typed()?.clone(),
            user_id: "owner".into(),
            expires_at: "2031-01-02T03:04:05Z".parse()?,
            created_at: created
                .created_at
                .typed()?
                .to_datetime()?
                .ok_or("Created session date is invalid")?,
            updated_at: created
                .updated_at
                .typed()?
                .to_datetime()?
                .ok_or("Updated session date is invalid")?,
            ip_address: Some(String::new()),
            user_agent: Some(String::new()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
        };
        assert_eq!(session::Entity::find().all(database).await?, [stored]);
        assert_eq!(
            store.get_session(created.token.typed()?).await?,
            Some(created)
        );
        assert_eq!(
            *events
                .lock()
                .map_err(|_| "Session create event lock poisoned")?,
            ["hook:false"]
        );
    }
    Ok(())
}

async fn check_history(database: &DatabaseConnection) -> TestResult {
    for hook_failure in [false, true] {
        for id_first in [false, true] {
            for supplied in ["outer-invalid", "f79b497c-7d3b-4ff7-a20d-407fd259f788"] {
                let target = Arc::new(OnceLock::<Weak<Store>>::new());
                let callback_target = target.clone();
                let events = Events::default();
                let callback_events = events.clone();
                let label = UserFieldConfig {
                    field_name: Some("active_organization_id".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new_async(move |value| {
                            let target = callback_target.clone();
                            let events = callback_events.clone();
                            async move {
                                event(
                                    &events,
                                    format!(
                                        "input:{}",
                                        value.as_str().ok_or_else(|| AuthError::internal(
                                            "Session label is not text"
                                        ))?
                                    ),
                                )?;
                                if value.as_str() == Some("inner") {
                                    return Err(AuthError::bad_request("nested field failure"));
                                }
                                let store =
                                    target.get().and_then(Weak::upgrade).ok_or_else(|| {
                                        AuthError::internal("Session callback store is unavailable")
                                    })?;
                                let error = store
                                    .create_session(input(Some("inner"))?)
                                    .await
                                    .err()
                                    .ok_or_else(|| {
                                        AuthError::internal("Nested create unexpectedly succeeded")
                                    })?;
                                event(&events, format!("failed:{error}"))?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                let mut config = AuthConfig::default();
                config.advanced.database.generate_id = Some(IdGeneration::Uuid);
                config.session.additional_fields = Some(
                    if id_first {
                        [("id".into(), id_policy()), ("label".into(), label)]
                    } else {
                        [("label".into(), label), ("id".into(), id_policy())]
                    }
                    .into(),
                );
                let store =
                    Arc::new(
                        Store::new(config, database.clone()).with_hooks(vec![Arc::new(ForcedId {
                            id: "nested-invalid".into(),
                            events: events.clone(),
                            fail: hook_failure,
                        })]),
                    );
                target
                    .set(Arc::downgrade(&store))
                    .map_err(|_| "Session callback store was already assigned")?;
                let mut stored = reset(database).await?;
                let updated_at = stored.updated_at + chrono::Duration::minutes(1);
                let result = store
                    .update_session_with_writer(
                        &stored.token,
                        SessionUpdate {
                            id: Some(supplied.into()),
                            updated_at: Some(updated_at.into()),
                            additional_fields: [("label".into(), "outer".into())].into(),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?
                    .ok_or("Session update returned no row")?;
                let forced = !id_first && !hook_failure;
                let omitted = if forced {
                    supplied == "outer-invalid"
                } else {
                    database.get_database_backend() == DbBackend::Postgres
                };
                stored.id = if omitted { "7" } else { supplied }.into();
                stored.updated_at = updated_at;
                stored.active_organization_id = Some("outer".into());
                assert_eq!(result.id.typed()?, &stored.id);
                assert_eq!(
                    result.updated_at,
                    better_auth_core::FieldDate::from(updated_at)
                );
                assert_eq!(
                    result.additional_fields.get("label"),
                    Some(&FieldValue::from("outer"))
                );
                assert_eq!(session::Entity::find().all(database).await?, [stored]);
                let mut expected = vec!["input:outer".to_owned(), "hook:false".to_owned()];
                if !hook_failure {
                    expected.push("input:inner".into());
                }
                expected.push(format!(
                    "failed:{}",
                    AuthError::bad_request(if hook_failure {
                        "nested hook failure"
                    } else {
                        "nested field failure"
                    })
                ));
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| "Session create event lock poisoned")?,
                    expected
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn contract(database: &DatabaseConnection) -> TestResult {
    check_creates(database).await?;
    check_history(database).await
}
