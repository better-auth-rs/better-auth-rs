use crate::ordinary_field_policies as ordinary;

pub(crate) use ordinary::{Trace, take};

use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
        AuthSchema,
        store::schema::EntityRole,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    },
    AuthConfig,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

#[derive(Clone, Copy)]
pub(crate) enum NameMapping {
    Default,
    Empty,
    Renamed,
}

impl NameMapping {
    pub(crate) const ALL: [Self; 3] = [Self::Default, Self::Empty, Self::Renamed];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Empty => "empty",
            Self::Renamed => "renamed",
        }
    }

    pub(crate) fn column(self) -> &'static str {
        match self {
            Self::Default | Self::Empty => "name",
            Self::Renamed => "stored_name",
        }
    }
}

pub(crate) struct Fields(pub(crate) UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-api-key-additional-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::ApiKey, self.0.clone())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) fn config() -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-api-key-extra-fields-secret-at-least-32-characters")
        .base_url("http://api-key-fields.test");
    config.telemetry.enabled = false;
    config
}

pub(crate) fn policies(events: Option<Trace>, failure: Arc<AtomicU8>) -> UserConfig {
    ordinary::policies("API Key", events, failure)
}

#[expect(
    clippy::expect_used,
    reason = "The mapped name trace must retain each input, output, and onUpdate callback"
)]
pub(crate) fn name_mapping_policies(
    mapping: NameMapping,
    events: Option<Trace>,
    failure: Arc<AtomicU8>,
) -> UserConfig {
    let mut config = policies(events.clone(), failure.clone());
    let mut field = UserFieldConfig {
        field_name: match mapping {
            NameMapping::Default => None,
            NameMapping::Empty => Some(String::new()),
            NameMapping::Renamed => Some("stored_name".into()),
        },
        required: Some(false),
        ..Default::default()
    };
    if let Some(events) = events {
        let updates = events.clone();
        field.on_update = Some(Arc::new(move || {
            updates
                .lock()
                .expect("mapped name trace lock")
                .push(json!(["onUpdate", "name"]));
            json!(" Renewed ")
        }));
        let inputs = events.clone();
        let input_failure = failure.clone();
        field.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                inputs.lock().expect("mapped name trace lock").push(json!([
                    "input",
                    "name",
                    value.clone().unwrap_or(json!({"type":"undefined"})),
                ]));
                if input_failure.load(Ordering::SeqCst) == 1 {
                    return Err(better_auth::__private_core::AuthError::internal(
                        "ordinary API Key input error",
                    ));
                }
                Ok(value.map(|value| match value {
                    Value::String(value) => json!(value.trim()),
                    value => value,
                }))
            })),
            output: Some(UserFieldTransform::new(move |value| {
                events.lock().expect("mapped name trace lock").push(json!([
                    "output",
                    "name",
                    value.clone().unwrap_or(json!({"type":"undefined"})),
                ]));
                if failure.load(Ordering::SeqCst) == 2 {
                    return Err(better_auth::__private_core::AuthError::internal(
                        "ordinary API Key output error",
                    ));
                }
                Ok(value.map(|value| match value {
                    Value::String(value) => json!(format!("{value}:out")),
                    value => value,
                }))
            })),
        });
    }
    let _ = config.fields_mut().shift_insert(0, "name".into(), field);
    config
}
