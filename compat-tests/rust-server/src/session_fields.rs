use better_auth::config::{UserFieldConfig, UserFieldTransform, UserFieldType};
use better_auth::{AuthConfig, AuthError};
use serde_json::{Value, json};
use std::sync::Arc;

fn suffix(suffix: &'static str) -> UserFieldTransform {
    Arc::new(move |value| {
        Ok(value.map(|value| {
            if value.is_null() {
                value
            } else {
                json!(format!("{}{suffix}", value.as_str().unwrap_or_default()))
            }
        }))
    })
}

pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
    if !profile.starts_with("session-fields") {
        return;
    }
    config.session.additional_fields = [
        (
            "deviceLabel".into(),
            UserFieldConfig {
                default_value_fn: Some(Arc::new(|| json!("factory"))),
                on_update: Some(Arc::new(|| json!("tick"))),
                input_transform: Some(suffix(":input")),
                output_transform: Some(suffix(":output")),
                ..Default::default()
            },
        ),
        (
            "validatedLabel".into(),
            UserFieldConfig {
                validator: Some(Arc::new(|value| match value.as_str() {
                    Some(value) if value.len() >= 2 => Ok(json!(format!("{value}:validated"))),
                    _ => Err(AuthError::BadRequest("label too short".into())),
                })),
                input_transform: Some(suffix(":input")),
                output_transform: Some(suffix(":output")),
                ..Default::default()
            },
        ),
        (
            "internalNote".into(),
            UserFieldConfig {
                input: false,
                returned: false,
                default_value: Some(json!("hidden")),
                ..Default::default()
            },
        ),
        (
            "settings".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                default_value: Some(json!({ "stage": "created" })),
                output_transform: Some(Arc::new(|value| {
                    let Some(value) = value else {
                        return Ok(None);
                    };
                    if value.is_null() {
                        return Ok(Some(value));
                    }
                    let text = value.as_str().ok_or_else(|| {
                        AuthError::internal("SQLite JSON output must receive text")
                    })?;
                    let mut value: Value = serde_json::from_str(text)?;
                    value["output"] = json!(true);
                    Ok(Some(json!(value.to_string())))
                })),
                ..Default::default()
            },
        ),
    ]
    .into();
}
