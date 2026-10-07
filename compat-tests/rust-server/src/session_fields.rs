use better_auth::config::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
use better_auth::{AuthConfig, AuthError, FieldMap};
use serde_json::{Value, json};
use std::sync::Arc;

fn suffix(suffix: &'static str) -> UserFieldTransform {
    UserFieldTransform::new(move |value| {
        Ok(if value.is_null() || value.is_undefined() {
            value
        } else {
            format!("{}{suffix}", value.as_str().unwrap_or_default()).into()
        })
    })
}

pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
    if !profile.starts_with("session-fields") {
        return;
    }
    config.session.additional_fields = Some(
        [
            (
                "deviceLabel".into(),
                UserFieldConfig {
                    default_value_fn: Some(Arc::new(|| "factory".into())),
                    on_update: Some(Arc::new(|| "tick".into())),
                    transform: Some(FieldTransforms {
                        input: Some(suffix(":input")),
                        output: Some(suffix(":output")),
                    }),
                    ..Default::default()
                },
            ),
            (
                "validatedLabel".into(),
                UserFieldConfig {
                    validator: Some(Arc::new(|value| match value.as_str() {
                        Some(value) if value.len() >= 2 => Ok(format!("{value}:validated").into()),
                        _ => Err(AuthError::BadRequest("label too short".into())),
                    })),
                    transform: Some(FieldTransforms {
                        input: Some(suffix(":input")),
                        output: Some(suffix(":output")),
                    }),
                    ..Default::default()
                },
            ),
            (
                "internalNote".into(),
                UserFieldConfig {
                    input: Some(false),
                    returned: Some(false),
                    default_value: Some("hidden".into()),
                    ..Default::default()
                },
            ),
            (
                "settings".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    default_value: Some(
                        FieldMap::from([("stage".into(), "created".into())]).into(),
                    ),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(|value| {
                            if value.is_null() || value.is_undefined() {
                                return Ok(value);
                            }
                            let text = value.as_str().ok_or_else(|| {
                                AuthError::internal("SQLite JSON output must receive text")
                            })?;
                            let mut value: Value = serde_json::from_str(text)?;
                            value["output"] = json!(true);
                            Ok(value.to_string().into())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    );
}
