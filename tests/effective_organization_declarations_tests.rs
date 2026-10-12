#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions must fail the test while setup errors propagate through Result."
)]

use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRecordFields, AuthRequest,
    AuthResponse, AuthResult, AuthRoute, AuthSchema, AuthStore, CreateTeam, FieldDate, FieldMap,
    FieldValue, UpdateTeam,
    store::{
        EphemeralStore, StatelessSchema,
        schema::{EntityRole, SchemaConfiguration},
    },
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "effective_organization_declarations_tests/deletion.rs"]
mod deletion;
#[path = "effective_organization_declarations_tests/member_joins.rs"]
mod member_joins;

const ID: &str = "mapping-row";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Input,
    Output,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

#[derive(Clone, Default)]
struct Callbacks {
    events: Arc<Mutex<Vec<Value>>>,
    failure: Arc<Mutex<Option<Phase>>>,
}

impl Callbacks {
    fn transform(&self, phase: Phase) -> UserFieldTransform {
        let callbacks = self.clone();
        UserFieldTransform::new(move |value| {
            callbacks
                .events
                .lock()
                .map_err(|_| AuthError::internal("Callback event lock poisoned"))?
                .push(json!([phase.name(), "organizationId", value.json()?]));
            if *callbacks
                .failure
                .lock()
                .map_err(|_| AuthError::internal("Callback failure lock poisoned"))?
                == Some(phase)
            {
                return Err(AuthError::internal(format!(
                    "partial-team-{}-failed",
                    phase.name()
                )));
            }
            let prefix = match phase {
                Phase::Input => "stored",
                Phase::Output => "visible",
            };
            Ok(format!(
                "{prefix}:{}",
                better_auth_core::SchemaValue::<String>::from_field(value).display_string()?
            )
            .into())
        })
    }

    fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.events.lock().map_err(|_| {
            AuthError::internal("Callback event lock poisoned")
        })?))
    }

    fn fail(&self, phase: Option<Phase>) -> AuthResult<()> {
        *self
            .failure
            .lock()
            .map_err(|_| AuthError::internal("Callback failure lock poisoned"))? = phase;
        Ok(())
    }

    fn fields(&self, partial: bool) -> UserConfig {
        UserConfig {
            additional_fields: Some(if partial {
                [(
                    "organizationId".into(),
                    UserFieldConfig {
                        field_name: Some("name".into()),
                        required: Some(true),
                        transform: Some(FieldTransforms {
                            input: Some(self.transform(Phase::Input)),
                            output: Some(self.transform(Phase::Output)),
                        }),
                        ..Default::default()
                    },
                )]
                .into()
            } else {
                Default::default()
            }),
        }
    }
}

struct Declaration(EntityRole, UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Declaration {
    fn name(&self) -> &'static str {
        "explicit-model"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(self.0, self.1.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("effective-organization-declarations-at-least-thirty-two-characters")
            .base_url("http://effective-organization-declarations.test");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config
}

struct Fixture {
    raw: EphemeralStore,
    auth: BetterAuth<StatelessSchema>,
    callbacks: Callbacks,
}

impl Fixture {
    async fn new(partial: bool) -> AuthResult<Self> {
        let config = config();
        let raw = EphemeralStore::new(Arc::new(config.clone()));
        let callbacks = Callbacks::default();
        let auth = BetterAuth::new(config)
            .store(raw.clone())
            .plugin(Declaration(EntityRole::Team, callbacks.fields(partial)))
            .build()
            .await?;
        assert!(callbacks.take()?.is_empty());
        Ok(Self {
            raw,
            auth,
            callbacks,
        })
    }

    fn snapshot(&self) -> AuthResult<FieldMap> {
        [
            (EntityRole::User, "user"),
            (EntityRole::Session, "session"),
            (EntityRole::Account, "account"),
            (EntityRole::Verification, "verification"),
            (EntityRole::Team, "team"),
        ]
        .into_iter()
        .map(|(role, name)| {
            Ok((
                name.into(),
                self.raw
                    .storage_rows(role)?
                    .into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            ))
        })
        .collect()
    }
}

fn expected_storage(partial: bool, input: Option<&str>) -> FieldMap {
    let mut expected: FieldMap = ["user", "session", "account", "verification", "team"]
        .into_iter()
        .map(|name| (name.into(), Vec::<FieldValue>::new().into()))
        .collect();
    if let Some(input) = input {
        let mut row = FieldMap::new();
        if partial {
            let _ = row.insert("name".into(), format!("stored:{input}").into());
        }
        let _ = row.insert("id".into(), ID.into());
        let _ = expected.insert("team".into(), vec![FieldValue::from(row)].into());
    }
    expected
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Create,
    Read,
    Update,
}

async fn operation(
    store: &dyn AuthStore<StatelessSchema>,
    operation: Operation,
    input: &str,
) -> AuthResult<FieldMap> {
    let date = FieldDate::from_milliseconds(1_893_456_000_000.0);
    let team = match operation {
        Operation::Create => {
            store
                .create_team(CreateTeam {
                    id: Some(ID.into()),
                    name: "Team".into(),
                    organization_id: input.into(),
                    created_at: Some(date.clone()),
                    updated_at: Some(date),
                    ..Default::default()
                })
                .await?
        }
        Operation::Update => {
            store
                .update_team(
                    ID,
                    UpdateTeam {
                        organization_id: Some(input.into()),
                        updated_at: Some(Some(date)),
                        ..Default::default()
                    },
                )
                .await?
        }
        Operation::Read => store
            .get_team(ID)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored Team"))?,
    };
    team.field_values()
}

fn assert_output(actual: &FieldMap, partial: bool, input: &str) {
    let mut expected = FieldMap::new();
    if partial {
        let _ = expected.insert(
            "organizationId".into(),
            format!("visible:stored:{input}").into(),
        );
    }
    let _ = expected.insert("id".into(), ID.into());
    assert_eq!(actual, &expected);
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn memory_explicit_team_declarations_control_complete_writes_and_reads() -> AuthResult<()> {
    for partial in [false, true] {
        let fixture = Fixture::new(partial).await?;
        assert_eq!(fixture.snapshot()?, expected_storage(partial, None));
        let mut stages = vec![(Operation::Create, "source"), (Operation::Read, "source")];
        if partial {
            stages.extend([(Operation::Update, "next"), (Operation::Read, "next")]);
        }
        for (stage, input) in stages {
            let result = operation(fixture.auth.store().as_ref(), stage, input).await?;
            assert_output(&result, partial, input);
            let mut events = Vec::new();
            if partial {
                if stage != Operation::Read {
                    events.push(json!(["input", "organizationId", input]));
                }
                events.push(json!([
                    "output",
                    "organizationId",
                    format!("stored:{input}")
                ]));
            }
            assert_eq!(fixture.callbacks.take()?, events);
            assert_eq!(fixture.snapshot()?, expected_storage(partial, Some(input)));
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_partial_team_callback_errors_preserve_the_write_boundary() -> AuthResult<()> {
    for stage in [Operation::Create, Operation::Update] {
        for phase in [Phase::Input, Phase::Output] {
            let fixture = Fixture::new(true).await?;
            if stage == Operation::Update {
                assert_output(
                    &operation(fixture.auth.store().as_ref(), Operation::Create, "source").await?,
                    true,
                    "source",
                );
                assert_eq!(
                    fixture.callbacks.take()?,
                    [
                        json!(["input", "organizationId", "source"]),
                        json!(["output", "organizationId", "stored:source"])
                    ]
                );
            }
            let before = if stage == Operation::Update {
                Some("source")
            } else {
                None
            };
            assert_eq!(fixture.snapshot()?, expected_storage(true, before));
            fixture.callbacks.fail(Some(phase))?;
            let error = operation(fixture.auth.store().as_ref(), stage, "next")
                .await
                .err()
                .ok_or_else(|| AuthError::internal("Expected the configured callback failure"))?;
            assert!(matches!(error, AuthError::Internal(_)));
            assert_eq!(
                error.instrumentation_message()?,
                format!("partial-team-{}-failed", phase.name())
            );
            let mut events = vec![json!(["input", "organizationId", "next"])];
            if phase == Phase::Output {
                events.push(json!(["output", "organizationId", "stored:next"]));
            }
            assert_eq!(fixture.callbacks.take()?, events);
            let stored = if phase == Phase::Output {
                Some("next")
            } else {
                before
            };
            assert_eq!(fixture.snapshot()?, expected_storage(true, stored));
            fixture.callbacks.fail(None)?;
            if let Some(input) = stored {
                assert_output(
                    &operation(fixture.auth.store().as_ref(), Operation::Read, input).await?,
                    true,
                    input,
                );
                assert_eq!(
                    fixture.callbacks.take()?,
                    [json!([
                        "output",
                        "organizationId",
                        format!("stored:{input}")
                    ])]
                );
            } else {
                assert!(fixture.auth.store().get_team(ID).await?.is_none());
                assert!(fixture.callbacks.take()?.is_empty());
            }
            assert_eq!(fixture.snapshot()?, expected_storage(true, stored));
        }
    }
    Ok(())
}

#[tokio::test]
async fn organization_partial_initialization_keeps_external_role_declarations_required()
-> AuthResult<()> {
    for enabled in [false, true] {
        let config = Arc::new(config());
        let mut fields = better_auth_core::plugin_runtime::ModelFields::default();
        let mut context = AuthInitContext::<StatelessSchema>::new(
            config.clone(),
            Arc::new(EphemeralStore::new(config.clone())),
        )
        .expect("fixture context initializes");
        let callbacks = Callbacks::default();
        let declaration = |name: &str| UserConfig {
            additional_fields: Some(
                [(
                    name.into(),
                    UserFieldConfig {
                        required: Some(true),
                        transform: Some(FieldTransforms {
                            output: Some(callbacks.transform(Phase::Output)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        fields
            .register_model_fields(EntityRole::OrganizationRole, declaration("externalBefore"))?;
        let mut options = OrganizationConfig {
            dynamic_access_control: enabled,
            ..Default::default()
        };
        options.schema.organization_role = declaration("own");
        let plugin = OrganizationPlugin::with_config(options);
        AuthPlugin::<StatelessSchema>::schema(&plugin, &mut fields)?;
        plugin.on_init(&mut context).await?;
        fields.register_model_fields(EntityRole::OrganizationRole, declaration("externalAfter"))?;
        let settings = SchemaConfiguration {
            config,
            plugins: vec!["organization"],
            metadata: context.metadata.clone(),
            secondary_storage: false,
            rate_limit: Default::default(),
        };
        fields.set_schema_configuration(&settings);
        let resolved = fields.organization_fields(Default::default());
        for declaration in [
            fields.fields(EntityRole::OrganizationRole),
            &resolved.organization_role,
        ] {
            let mut expected = vec!["externalBefore"];
            if enabled {
                expected.extend([
                    "organizationId",
                    "role",
                    "permission",
                    "createdAt",
                    "updatedAt",
                    "own",
                ]);
            }
            expected.push("externalAfter");
            assert_eq!(
                declaration
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                expected
            );
            for name in ["externalBefore", "externalAfter"] {
                assert_eq!(
                    declaration.fields().get(name).map(|field| field.required),
                    Some(Some(true))
                );
            }
            assert_eq!(
                declaration.fields().get("own").map(|field| field.required),
                enabled.then_some(Some(false))
            );
        }
        assert!(callbacks.take()?.is_empty());
    }
    Ok(())
}
