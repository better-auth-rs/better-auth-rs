use better_auth_core::session::SessionRead;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResult, AuthSchema, BeforeRequestAction, FieldValue,
};
use serde_json::Value;

use super::config::error;
use super::{UsernamePlugin, UsernameValidationOrder};

impl UsernamePlugin {
    pub(crate) async fn before_endpoint<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let signup = request.path() == "/sign-up/email";
        if !signup && request.path() != "/update-user" {
            return Ok(None);
        }
        let mut body: Value = request.body_as_json()?;
        if body.is_null() {
            return Err(better_auth_core::AuthError::internal(
                "Username hooks cannot read properties of null",
            ));
        }
        let Some(body) = body.as_object_mut() else {
            return Ok(None);
        };
        let mut changed = false;
        if signup {
            better_auth_core::observability::instrumentation::with_endpoint_hook(
                &context.config,
                request,
                "before",
                "plugin:username",
                async {
                    if !body.contains_key("username")
                        && let Some(display) = body.get("displayUsername").and_then(Value::as_str)
                        && self
                            .config
                            .validate_input(&FieldValue::from(display))
                            .await?
                            .is_none()
                    {
                        let value = display.to_owned();
                        let _ = body.insert("username".into(), value.into());
                        changed = true;
                    }
                    Ok(())
                },
            )
            .await?;
        }
        better_auth_core::observability::instrumentation::with_endpoint_hook(
            &context.config,
            request,
            "before",
            "plugin:username",
            async {
                if let Some(username) = body.get("username").and_then(Value::as_str) {
                    let username = FieldValue::from(username);
                    if let Some((code, message)) = self.config.validate_input(&username).await? {
                        return Err(error(400, code, message));
                    }
                    let normalized = self.config.normalize(&username)?;
                    let session = if signup {
                        None
                    } else {
                        context.native_session(request, SessionRead::Cached).await?
                    };
                    if !signup
                        && self.config.immutable_username
                        && let Some(session) = &session
                        && session.user_field("username")?.is_truthy()
                        && !session.user_field("username")?.strict_equals(&normalized)
                    {
                        return Err(error(
                            400,
                            "USERNAME_IS_IMMUTABLE",
                            "Username cannot be updated",
                        ));
                    }
                    if let Some(existing) = context
                        .database
                        .get_user_by_field_value("username", &normalized)
                        .await?
                        && (signup
                            || session
                                .as_ref()
                                .map(|session| session.user_field("id"))
                                .transpose()?
                                .is_none_or(|id| !existing.id.field_value().strict_equals(&id)))
                    {
                        return Err(error(
                            400,
                            "USERNAME_IS_ALREADY_TAKEN",
                            "Username is already taken. Please try another.",
                        ));
                    }
                }
                if self.config.display_username
                    && let Some(display) = body.get("displayUsername").and_then(Value::as_str)
                {
                    // The endpoint normalizes for post-validation even without a validator.
                    let normalized = if self.config.display_username_validation_order
                        == Some(UsernameValidationOrder::PostNormalization)
                    {
                        self.config.normalize_display(&FieldValue::from(display))?
                    } else {
                        FieldValue::from(display)
                    };
                    if normalized.is_string()
                        && let Some(validator) = &self.config.display_username_validator
                        && !validator.validate(&normalized).await?
                    {
                        return Err(error(
                            400,
                            "INVALID_DISPLAY_USERNAME",
                            "Display username is invalid",
                        ));
                    }
                }
                Ok(())
            },
        )
        .await?;
        if signup {
            better_auth_core::observability::instrumentation::with_endpoint_hook(
                &context.config,
                request,
                "before",
                "plugin:username",
                async {
                    if self.config.display_username
                        && !body
                            .get("displayUsername")
                            .is_some_and(crate::plugins::json_body::is_truthy)
                        && let Some(value) = body
                            .get("username")
                            .filter(|value| crate::plugins::json_body::is_truthy(value))
                            .cloned()
                    {
                        let _ = body.insert("displayUsername".into(), value);
                        changed = true;
                    }
                    Ok(())
                },
            )
            .await?;
        }
        if changed {
            Ok(Some(BeforeRequestAction::ReplaceBody(serde_json::to_vec(
                body,
            )?)))
        } else {
            Ok(None)
        }
    }
}
