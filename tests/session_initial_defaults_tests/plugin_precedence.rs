use super::*;
use async_trait::async_trait;
use better_auth::BetterAuth;
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserConfig, UserFieldTransform},
};

#[derive(Clone, Copy, Debug)]
enum Scenario {
    PluginDefault,
    HookUndefined,
    NoPluginDefault,
}

#[derive(Debug, PartialEq)]
enum FieldEvent {
    Default(&'static str),
    Before(FieldMap),
    Input(&'static str, FieldValue),
    After(FieldMap),
}

fn record(events: &Sender<FieldEvent>, event: FieldEvent) -> AuthResult<()> {
    events
        .send(event)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn field(
    storage: &str,
    source: &'static str,
    value: &'static str,
    events: &Sender<FieldEvent>,
) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        field_name: Some(storage.into()),
        default_value_fn: Some(Arc::new(move || {
            record(&events, FieldEvent::Default(source))?;
            Ok(value.into())
        })),
        ..Default::default()
    }
}

fn transformed(
    mut field: UserFieldConfig,
    source: &'static str,
    events: &Sender<FieldEvent>,
) -> UserFieldConfig {
    let events = events.clone();
    field.transform = Some(FieldTransforms {
        input: Some(UserFieldTransform::new(move |value| {
            record(&events, FieldEvent::Input(source, value.clone()))?;
            let value = value
                .as_str()
                .ok_or_else(|| AuthError::internal("Expected the Session default string"))?;
            Ok(format!("{source}:{value}").into())
        })),
        ..Default::default()
    });
    field
}

#[derive(Clone)]
struct Plugin {
    scenario: Scenario,
    fields: UserConfig,
    events: Sender<FieldEvent>,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Plugin {
    async fn before_create_session(
        &self,
        input: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        record(
            &self.events,
            FieldEvent::Before(additional_creation_fields(input)),
        )?;
        if matches!(self.scenario, Scenario::HookUndefined) {
            let _ = input.insert("label".into(), FieldValue::Undefined);
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        record(
            &self.events,
            FieldEvent::After(session.additional_fields.clone()),
        )
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Plugin {
    fn name(&self) -> &'static str {
        "session-default-precedence"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Session, self.fields.clone())?;
        context.register_database_hook(Arc::new(self.clone()));
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> TestResult {
    for pure in [false, true] {
        for call in [Call::Ordinary, Call::Transaction, Call::Deferred] {
            for scenario in [
                Scenario::PluginDefault,
                Scenario::HookUndefined,
                Scenario::NoPluginDefault,
            ] {
                let (events, receiver) = mpsc::channel();
                let mut config =
                    AuthConfig::new("session-default-precedence-at-least-32-characters")
                        .base_url("http://session-defaults.test");
                config.session.store_session_in_database = Some(!pure);
                config.session.additional_fields = Some(
                    [
                        (
                            "appOnly".into(),
                            field("impersonated_by", "appOnly", "A", &events),
                        ),
                        (
                            "label".into(),
                            transformed(
                                field(
                                    "active_organization_id",
                                    "application:label",
                                    "application",
                                    &events,
                                ),
                                "application",
                                &events,
                            ),
                        ),
                    ]
                    .into(),
                );
                let plugin_label = if matches!(scenario, Scenario::NoPluginDefault) {
                    UserFieldConfig {
                        field_name: Some("active_organization_id".into()),
                        ..Default::default()
                    }
                } else {
                    field("active_organization_id", "plugin:label", "plugin", &events)
                };
                let plugin = Plugin {
                    scenario,
                    fields: UserConfig {
                        additional_fields: Some(
                            [
                                ("label".into(), transformed(plugin_label, "plugin", &events)),
                                (
                                    "pluginOnly".into(),
                                    field("active_team_id", "pluginOnly", "P", &events),
                                ),
                            ]
                            .into(),
                        ),
                    },
                    events,
                };
                let cache = Arc::new(MemoryCacheAdapter::new());
                let mut builder = BetterAuth::new(config)
                    .store_arc(raw.clone())
                    .plugin(plugin);
                if pure {
                    builder = builder.secondary_storage(cache.clone());
                }
                let auth = builder.build().await?;
                let owner = raw
                    .create_user(CreateUser::new().with_name("Owner").with_email(format!(
                        "{scenario:?}-{call:?}-{pure}@session-defaults.test"
                    )))
                    .await?;
                let mut create_input = input(Case::Missing)?;
                create_input.user_id = owner.id.clone();
                create_input.additional_fields.clear();
                let created = match call {
                    Call::Ordinary => auth.store().create_session(create_input).await?,
                    Call::Transaction => {
                        transaction(auth.store().as_ref(), move |tx| {
                            Box::pin(async move { tx.create_session(create_input).await })
                        })
                        .await?
                    }
                    Call::Deferred => {
                        transaction(auth.store().as_ref(), move |tx| {
                            Box::pin(async move {
                                tx.create_session_with_deferred_secondary(create_input)
                                    .await
                            })
                        })
                        .await?
                    }
                };
                let mut before = FieldMap::new();
                if pure {
                    let _ = before.insert("id".into(), created.id.field_value());
                }
                let _ = before.insert("appOnly".into(), "A".into());
                let mut expected = vec![FieldEvent::Default("appOnly")];
                if !matches!(scenario, Scenario::NoPluginDefault) {
                    expected.push(FieldEvent::Default("plugin:label"));
                    let _ = before.insert("label".into(), "plugin".into());
                }
                expected.push(FieldEvent::Default("pluginOnly"));
                let _ = before.insert("pluginOnly".into(), "P".into());
                expected.push(FieldEvent::Before(before));
                let mut output: FieldMap = [
                    ("appOnly".into(), "A".into()),
                    ("pluginOnly".into(), "P".into()),
                ]
                .into();
                if pure {
                    match scenario {
                        Scenario::PluginDefault => {
                            let _ = output.insert("label".into(), "plugin".into());
                        }
                        Scenario::HookUndefined => {
                            let _ = output.insert("label".into(), FieldValue::Undefined);
                        }
                        Scenario::NoPluginDefault => {}
                    }
                } else {
                    let value = if matches!(scenario, Scenario::PluginDefault) {
                        "plugin"
                    } else {
                        expected.push(FieldEvent::Default("application:label"));
                        "application"
                    };
                    expected.push(FieldEvent::Input("application", value.into()));
                    let _ = output.insert("label".into(), format!("application:{value}").into());
                }
                expected.push(FieldEvent::After(output.clone()));
                assert_eq!(receiver.try_iter().collect::<Vec<_>>(), expected);
                assert_eq!(created.additional_fields, output);
                let stored = auth
                    .store()
                    .get_session(&created.token)
                    .await?
                    .ok_or("Session readback is missing")?;
                assert_eq!(stored.additional_fields.json()?, output.json()?);
                assert_eq!(stored.id, created.id);
                assert_eq!(stored.user_id, owner.id);
                assert_eq!(stored.expires_at, created.expires_at);
                if pure {
                    assert!(raw.get_user_sessions(owner.id.typed()?).await?.is_empty());
                    let cached = cache
                        .get(&created.token)
                        .await?
                        .ok_or("Session cache is missing")?;
                    let cached: JsonValue =
                        serde_json::from_str(cached.as_str().ok_or("Session cache is not text")?)?;
                    let mut session_fields = FieldMap::from(created.clone());
                    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
                        let _ = session_fields.remove(name);
                    }
                    assert_eq!(
                        cached.get("session"),
                        Some(&JsonValue::Object(session_fields.json()?))
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_plugin_defaults_keep_input_and_adapter_precedence_separate() -> TestResult {
    contract(Arc::new(EphemeralStore::default())).await
}

#[tokio::test]
async fn sqlite_plugin_defaults_keep_input_and_adapter_precedence_separate() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    contract(Arc::new(SeaOrmStore::<BundledSchema>::new(
        AuthConfig::default(),
        database,
    )))
    .await
}
