use better_auth::config::{FieldTransforms, UserFieldTransform};
use std::sync::Arc;

use better_auth::FieldValue;
use better_auth::config::UserFieldConfig;
use better_auth::plugins::{EmailPasswordPlugin, email_password::OnExistingUserSignUp};
use better_auth::{AuthConfig, AuthError, AuthResult, wire::UserView};
use better_auth_core::AuthRequest;

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
            && user.name.typed()?.as_ref() != Some(expected)
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
    config.user.additional_fields = Some(
        [
            (
                "alias".into(),
                UserFieldConfig {
                    required: Some(false),
                    default_value: Some("guest".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(|value| {
                            Ok(if value.is_undefined() {
                                value
                            } else {
                                format!("{}:in", value.as_str().unwrap_or("null")).into()
                            })
                        })),
                        output: Some(UserFieldTransform::new(|value| {
                            Ok(if value.is_undefined() {
                                value
                            } else {
                                format!("{}:out", value.as_str().unwrap_or("null")).into()
                            })
                        })),
                    }),
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
                    returned: Some(false),
                    default_value: Some("hidden".into()),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    );
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
                format!(
                    "synthetic:{}",
                    data.get("name")
                        .and_then(FieldValue::as_str)
                        .unwrap_or_default()
                )
                .into(),
            );
            let _ = data.insert(
                "alias".into(),
                format!(
                    "custom:{}",
                    input
                        .additional_fields
                        .get("alias")
                        .and_then(FieldValue::as_str)
                        .unwrap_or_default()
                )
                .into(),
            );
            let _ = data.insert("secretNote".into(), "not-public".into());
            let _ = data.insert("unknown".into(), "not-in-schema".into());
            let _ = data.insert("id".into(), input.id.into());
            Ok(data)
        }))
    } else {
        plugin
    }
}
