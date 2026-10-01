use better_auth_core::session::SessionRead;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResult, AuthSchema, AuthUser, BeforeRequestAction,
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
        let Some(body) = body.as_object_mut() else {
            return Ok(None);
        };
        let mut changed = false;
        if signup
            && !body.contains_key("username")
            && let Some(display) = body.get("displayUsername").and_then(Value::as_str)
            && self.config.validate_input(display).await?.is_none()
        {
            let value = display.to_owned();
            let _ = body.insert("username".into(), value.into());
            changed = true;
        }
        if let Some(username) = body.get("username").and_then(Value::as_str) {
            if let Some((code, message)) = self.config.validate_input(username).await? {
                return Err(error(400, code, message));
            }
            let normalized = self.config.normalize(username)?;
            let session = if signup {
                None
            } else {
                context
                    .session_manager()
                    .resolve(request, SessionRead::Cached)
                    .await?
                    .data
            };
            if !signup
                && self.config.immutable_username
                && let Some(session) = &session
                && session
                    .user
                    .username
                    .as_deref()
                    .is_some_and(|value| !value.is_empty() && value != normalized)
            {
                return Err(error(
                    400,
                    "USERNAME_IS_IMMUTABLE",
                    "Username cannot be updated",
                ));
            }
            if let Some(existing) = context.database.get_user_by_username(&normalized).await?
                && (signup
                    || session
                        .as_ref()
                        .is_none_or(|session| existing.id().as_ref() != session.user.id))
            {
                return Err(error(
                    400,
                    "USERNAME_IS_ALREADY_TAKEN",
                    "Username is already taken. Please try another.",
                ));
            }
        }
        if self.config.display_username {
            if let Some(display) = body.get("displayUsername").and_then(Value::as_str) {
                // The endpoint normalizes for post-validation even without a validator.
                let normalized = if self.config.display_username_validation_order
                    == Some(UsernameValidationOrder::PostNormalization)
                {
                    self.config.normalize_display(display)?
                } else {
                    display.to_owned()
                };
                if let Some(validator) = &self.config.display_username_validator
                    && !validator.validate(&normalized).await?
                {
                    return Err(error(
                        400,
                        "INVALID_DISPLAY_USERNAME",
                        "Display username is invalid",
                    ));
                }
            }
            if signup
                && !body
                    .get("displayUsername")
                    .is_some_and(better_auth_core::user_fields::is_truthy)
                && let Some(value) = body
                    .get("username")
                    .filter(|value| better_auth_core::user_fields::is_truthy(value))
                    .cloned()
            {
                let _ = body.insert("displayUsername".into(), value);
                changed = true;
            }
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
