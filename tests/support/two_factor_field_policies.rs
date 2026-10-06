use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema,
        store::schema::EntityRole,
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

pub(crate) type Trace = Arc<Mutex<Vec<Value>>>;

pub(crate) struct Fields(pub(crate) UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-two-factor-additional-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::TwoFactor, self.0.clone())
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
    let mut config =
        AuthConfig::new("ordinary-two-factor-extra-fields-secret-at-least-32-characters")
            .base_url("http://two-factor-fields.test");
    config.telemetry.enabled = false;
    config
}

#[expect(
    clippy::expect_used,
    reason = "The trace mutex must remain unpoisoned so the contract retains every callback event"
)]
pub(crate) fn push(events: &Trace, value: Value) {
    events.lock().expect("TwoFactor trace lock").push(value);
}

#[expect(
    clippy::expect_used,
    reason = "The trace mutex must remain unpoisoned so each operation retains its complete callback sequence"
)]
pub(crate) fn take(events: &Trace) -> Vec<Value> {
    std::mem::take(&mut *events.lock().expect("TwoFactor trace lock"))
}

pub(crate) fn policies(events: Option<Trace>, failure: Arc<AtomicU8>) -> UserConfig {
    let mut fields = UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        required: Some(false),
                        default_value: Some(json!(" Default ")),
                        ..Default::default()
                    },
                ),
                (
                    "activatedAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        field_name: Some("stored_activation".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "details".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        field_name: Some("stored_details".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "revision".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        field_name: Some("stored_revision".into()),
                        required: Some(false),
                        default_value_fn: Some(Arc::new({
                            let events = events.clone();
                            move || {
                                if let Some(events) = &events {
                                    push(events, json!(["default", "revision"]));
                                }
                                json!(1.5)
                            }
                        })),
                        on_update: Some(Arc::new({
                            let events = events.clone();
                            move || {
                                if let Some(events) = &events {
                                    push(events, json!(["onUpdate", "revision"]));
                                }
                                json!(2.5)
                            }
                        })),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    if let Some(events) = events {
        for (name, field) in fields.fields_mut() {
            let input_events = events.clone();
            let output_events = events.clone();
            let input_name = name.clone();
            let output_name = name.clone();
            let input_failure = failure.clone();
            let output_failure = failure.clone();
            field.transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    push(
                        &input_events,
                        json!([
                            "input",
                            input_name,
                            value.clone().unwrap_or(json!({"type":"undefined"}))
                        ]),
                    );
                    if input_name == "revision" && input_failure.load(Ordering::SeqCst) == 1 {
                        return Err(AuthError::internal("ordinary TwoFactor input error"));
                    }
                    Ok(value.map(|value| match value {
                        Value::String(value) if input_name == "label" => json!(value.trim()),
                        value => value,
                    }))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    push(
                        &output_events,
                        json!([
                            "output",
                            output_name,
                            value.clone().unwrap_or(json!({"type":"undefined"}))
                        ]),
                    );
                    if output_name == "label" && output_failure.load(Ordering::SeqCst) == 2 {
                        return Err(AuthError::internal("ordinary TwoFactor output error"));
                    }
                    Ok(value.map(|value| match value {
                        Value::String(value) if output_name == "label" => {
                            json!(format!("{value}:out"))
                        }
                        value => value,
                    }))
                })),
            });
        }
    }
    fields
}
