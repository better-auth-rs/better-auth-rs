use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldValue,
    organization_fields::OrganizationFields,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    fn record(&self, phase: &str, value: &FieldValue) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|error| {
                AuthError::internal(format!("Member JSON event lock failed: {error}"))
            })?
            .push(json!([phase, "settings", super::values::observe(value)?]));
        Ok(())
    }

    pub(super) fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|error| {
            AuthError::internal(format!("Member JSON event lock failed: {error}"))
        })?))
    }
}

pub(super) fn config() -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config
}

pub(super) fn fields(events: Option<&Events>) -> OrganizationFields {
    let transform = events.map(|events| {
        let input = events.clone();
        let output = events.clone();
        FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                input.record("input", &value)?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output.record("output", &value)?;
                Ok(value)
            })),
        }
    });
    OrganizationFields {
        member: UserConfig {
            additional_fields: Some(
                [(
                    "settings".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        required: Some(false),
                        field_name: Some("stored_settings".into()),
                        transform,
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
        ..Default::default()
    }
}
