use crate::plugins::json_body::is_truthy;
use better_auth_core::utils::username::{
    UsernameValidationError, normalize_username, validate_username,
};
use better_auth_core::{AuthContext, AuthError, AuthResult, AuthSchema, CreateUser};
use serde_json::{Map, Value};

/// Apply the enabled plugins' create-input fields before assigning route-owned proof fields.
pub(crate) async fn apply_user_create_fields(
    ctx: &AuthContext<impl AuthSchema>,
    input: &Map<String, Value>,
    user: &mut CreateUser,
) -> AuthResult<()> {
    let enabled = |plugin| ctx.get_metadata(plugin).and_then(Value::as_bool) == Some(true);
    for (plugin, field, message) in [
        (
            "phone-number.enabled",
            "phoneNumberVerified",
            "phoneNumberVerified is not allowed to be set",
        ),
        ("admin.enabled", "role", "role is not allowed to be set"),
        (
            "admin.enabled",
            "banReason",
            "banReason is not allowed to be set",
        ),
        (
            "admin.enabled",
            "banExpires",
            "banExpires is not allowed to be set",
        ),
    ] {
        if enabled(plugin) && input.get(field).is_some_and(is_truthy) {
            return Err(AuthError::Upstream {
                status: 400,
                code: "FIELD_NOT_ALLOWED",
                message,
            });
        }
    }
    if enabled("username.enabled") {
        if let Some(username) = optional_string(input, "username")? {
            let username = normalize_username(&username);
            if !username.is_empty() {
                validate_username(&username).map_err(|error| {
                    let (code, message) = match error {
                        UsernameValidationError::TooShort => {
                            ("USERNAME_TOO_SHORT", "Username is too short")
                        }
                        UsernameValidationError::TooLong => {
                            ("USERNAME_TOO_LONG", "Username is too long")
                        }
                        UsernameValidationError::Invalid => {
                            ("INVALID_USERNAME", "Username is invalid")
                        }
                    };
                    AuthError::Upstream {
                        status: 400,
                        code,
                        message,
                    }
                })?;
                if ctx
                    .database
                    .get_user_by_username(&username)
                    .await?
                    .is_some()
                {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "USERNAME_IS_ALREADY_TAKEN",
                        message: "Username is already taken. Please try another.",
                    });
                }
            }
            user.username = Some(username);
        }
        if let Some(display) = optional_string(input, "displayUsername")? {
            user.display_username = Some(display);
        }
        if user.display_username.as_deref().is_none_or(str::is_empty)
            && user
                .username
                .as_deref()
                .is_some_and(|username| !username.is_empty())
        {
            user.display_username = user.username.clone();
        }
    }
    if enabled("phone-number.enabled")
        && let Some(phone) = optional_string(input, "phoneNumber")?
    {
        user.phone_number = Some(phone);
    }
    if enabled("anonymous.enabled") {
        user.is_anonymous = Some(false);
    }
    Ok(())
}

fn optional_string(input: &Map<String, Value>, field: &str) -> AuthResult<Option<String>> {
    input
        .get(field)
        .map(|value| serde_json::from_value::<Option<String>>(value.clone()))
        .transpose()
        .map(Option::flatten)
        .map_err(Into::into)
}
