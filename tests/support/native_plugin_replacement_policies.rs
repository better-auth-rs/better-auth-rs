use super::*;
use better_auth::__private_core::{
    __private_async_trait::async_trait,
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthSchema,
    id::{IdGeneration, IdGenerator},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(crate) struct State {
    pub events: Vec<Value>,
    pub failure: Option<String>,
    pub error: Option<String>,
    pub error_pointer: usize,
    pub replace_input: bool,
    pub projection: Option<FieldValue>,
}

pub(crate) type Shared = Arc<Mutex<State>>;

impl State {
    pub(crate) fn fail(&mut self, phase: &str) {
        self.failure = Some(phase.into());
        let error = format!("ordinary native {phase} error");
        self.error_pointer = error.as_ptr() as usize;
        self.error = Some(error);
    }

    fn event(&mut self, phase: &str, field: &str, value: &FieldValue) -> AuthResult<()> {
        self.events
            .push(json!({"phase":phase,"field":field,"value":values::observe(value)?}));
        if field != "marker" && self.failure.as_deref() == Some(phase) {
            return Err(AuthError::internal(
                self.error.take().expect("one callback error"),
            ));
        }
        Ok(())
    }
}

pub(crate) fn config() -> better_auth::AuthConfig {
    let mut config = better_auth::AuthConfig::new(
        "ordinary-native-replacements-contract-at-least-32-characters",
    )
    .base_url("http://native-replacements.test");
    config.telemetry.enabled = false;
    config.logger.disabled = Some(true);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(
                if request.model == "user" { OWNER } else { ID }.into(),
            ))
        })));
    config
}

pub(crate) struct Policy {
    pub target: Target,
    pub defaults: bool,
    pub state: Shared,
}

impl Policy {
    fn fields(&self) -> UserConfig {
        let state = self.state.clone();
        let target = self.target.clone();
        let input = UserFieldTransform::new(move |value| {
            let mut state = state.lock().expect("replacement input state");
            state.event("input", &target.field, &value)?;
            Ok(if state.replace_input {
                target.value(4)?
            } else {
                value
            })
        });
        let state = self.state.clone();
        let target = self.target.clone();
        let output = UserFieldTransform::new(move |value| {
            let mut state = state.lock().expect("replacement output state");
            state.event("output", &target.field, &value)?;
            Ok(state.projection.clone().unwrap_or(value))
        });
        let mut field = UserFieldConfig {
            field_type: self.target.field_type.clone(),
            required: Some(false),
            field_name: Some(self.target.column.clone()),
            transform: Some(FieldTransforms {
                input: Some(input),
                output: Some(output),
            }),
            ..Default::default()
        };
        if self.defaults {
            let state = self.state.clone();
            let target = self.target.clone();
            field.default_value_fn = Some(Arc::new(move || {
                let value = target.value(2)?;
                state.lock().expect("replacement default state").event(
                    "default",
                    &target.field,
                    &value,
                )?;
                Ok(value)
            }));
            let state = self.state.clone();
            let target = self.target.clone();
            field.on_update = Some(Arc::new(move || {
                let value = target.value(3)?;
                state.lock().expect("replacement update state").event(
                    "onUpdate",
                    &target.field,
                    &value,
                )?;
                Ok(value)
            }));
        }
        let marker = |phase| {
            let state = self.state.clone();
            UserFieldTransform::new(move |value| {
                state
                    .lock()
                    .expect("marker state")
                    .event(phase, "marker", &value)?;
                Ok(value)
            })
        };
        UserConfig {
            additional_fields: Some(
                [
                    (self.target.field.clone(), field),
                    (
                        "marker".into(),
                        UserFieldConfig {
                            required: Some(false),
                            field_name: Some("stored_marker".into()),
                            transform: Some(FieldTransforms {
                                input: Some(marker("input")),
                                output: Some(marker("output")),
                            }),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        }
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Policy {
    fn name(&self) -> &'static str {
        "native-field-replacement"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(self.target.role, self.fields())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
