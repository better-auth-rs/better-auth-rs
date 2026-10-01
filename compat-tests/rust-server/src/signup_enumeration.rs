use std::sync::Arc;

use better_auth::config::UserFieldConfig;
use better_auth::plugins::{EmailPasswordPlugin, email_password::OnExistingUserSignUp};
use better_auth::{AuthConfig, AuthError, AuthResult, wire::UserView};
use better_auth_core::AuthRequest;
use serde_json::json;

struct ExistingSignup;

#[async_trait::async_trait]
impl OnExistingUserSignUp for ExistingSignup {
    async fn on_existing_user_sign_up(
        &self,
        user: &UserView,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()> {
        let request = request.ok_or_else(|| AuthError::internal("Missing signup request"))?;
        if let Some(expected) = request.headers.get("x-expected-user-name")
            && user.name.as_ref() != Some(expected)
        {
            return Err(AuthError::internal(
                "Duplicate callback received the submitted user",
            ));
        }
        if request.headers.get("x-duplicate-error").is_some() {
            return Err(AuthError::Upstream {
                status: 400,
                code: "DUPLICATE_CALLBACK_BLOCKED",
                message: "Duplicate callback blocked",
            });
        }
        Ok(())
    }
}

pub fn configure(profile: &str, config: &mut AuthConfig) {
    if !profile.starts_with("signup-") {
        return;
    }
    config.user.additional_fields = [
        (
            "alias".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some(json!("guest")),
                input_transform: Some(Arc::new(|value| {
                    Ok(
                        value
                            .map(|value| json!(format!("{}:in", value.as_str().unwrap_or("null")))),
                    )
                })),
                output_transform: Some(Arc::new(|value| {
                    Ok(value
                        .map(|value| json!(format!("{}:out", value.as_str().unwrap_or("null")))))
                })),
                ..Default::default()
            },
        ),
        (
            "optionalAlias".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "secretNote".into(),
            UserFieldConfig {
                required: Some(false),
                returned: false,
                default_value: Some(json!("hidden")),
                ..Default::default()
            },
        ),
    ]
    .into();
}

pub fn plugin(profile: &str, plugin: EmailPasswordPlugin) -> EmailPasswordPlugin {
    if !profile.starts_with("signup-") {
        return plugin;
    }
    let plugin = plugin
        .auto_sign_in(profile == "signup-verification")
        .require_email_verification(profile == "signup-verification")
        .on_existing_user_sign_up(Arc::new(ExistingSignup));
    if profile == "signup-synthetic" {
        plugin.custom_synthetic_user(Arc::new(|input| {
            let mut data = input.core_fields;
            let _ = data.insert(
                "name".into(),
                json!(format!(
                    "synthetic:{}",
                    data.get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                )),
            );
            let _ = data.insert(
                "alias".into(),
                json!(format!(
                    "custom:{}",
                    input
                        .additional_fields
                        .get("alias")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                )),
            );
            let _ = data.insert("secretNote".into(), json!("not-public"));
            let _ = data.insert("unknown".into(), json!("not-in-schema"));
            let _ = data.insert("id".into(), json!(input.id));
            Ok(data)
        }))
    } else {
        plugin
    }
}
