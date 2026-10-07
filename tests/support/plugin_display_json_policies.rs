use super::*;
use better_auth::__private_core::{
    __private_async_trait::async_trait,
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    id::{IdGeneration, IdGenerator},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct State {
    pub(super) events: Vec<Value>,
    pub(super) failure: Option<String>,
    pub(super) wrap_input: bool,
    pub(super) wrap_output: bool,
    pub(super) projection: Option<FieldValue>,
}

pub(super) type Shared = Arc<Mutex<State>>;

fn event(state: &mut State, target: Target, phase: &str, value: &FieldValue) -> AuthResult<()> {
    state
        .events
        .push(json!({"phase": phase, "field": target.field(), "value": values::observe(value)?}));
    if state.failure.as_deref() == Some(phase) {
        return Err(AuthError::internal(format!(
            "ordinary display {phase} error"
        )));
    }
    Ok(())
}

pub(super) struct Policy {
    pub(super) target: Target,
    pub(super) defaults: bool,
    pub(super) state: Shared,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Policy {
    fn name(&self) -> &'static str {
        "ordinary-display-json"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let target = self.target;
        let inputs = self.state.clone();
        let outputs = self.state.clone();
        let mut field = UserFieldConfig {
            field_type: UserFieldType::Json,
            field_name: Some("stored_display".into()),
            required: Some(self.defaults),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let mut state = inputs.lock().expect("display input state");
                    event(&mut state, target, "input", &value)?;
                    Ok(if state.wrap_input {
                        FieldMap::from_iter([("input".into(), value)]).into()
                    } else {
                        value
                    })
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let mut state = outputs.lock().expect("display output state");
                    event(&mut state, target, "output", &value)?;
                    Ok(if state.wrap_output {
                        FieldMap::from_iter([("output".into(), value)]).into()
                    } else {
                        state.projection.clone().unwrap_or(value)
                    })
                })),
            }),
            ..Default::default()
        };
        if self.defaults {
            let defaults = self.state.clone();
            field.default_value_fn = Some(Arc::new(move || {
                let value = FieldMap::from_iter([("source".into(), "default".into())]).into();
                event(
                    &mut defaults.lock().expect("display default state"),
                    target,
                    "default",
                    &value,
                )?;
                Ok(value)
            }));
            let updates = self.state.clone();
            field.on_update = Some(Arc::new(move || {
                let value = FieldMap::from_iter([("source".into(), "onUpdate".into())]).into();
                event(
                    &mut updates.lock().expect("display update state"),
                    target,
                    "onUpdate",
                    &value,
                )?;
                Ok(value)
            }));
        }
        context.register_model_fields(
            target.role(),
            UserConfig {
                additional_fields: Some([(target.field().into(), field)].into()),
            },
        )
    }
}

pub(crate) fn config() -> better_auth::AuthConfig {
    let mut config =
        better_auth::AuthConfig::new("ordinary-display-json-contract-at-least-32-characters")
            .base_url("http://display-json.test");
    config.telemetry.enabled = false;
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(
                if request.model == "user" { OWNER } else { ID }.into(),
            ))
        })));
    config
}
