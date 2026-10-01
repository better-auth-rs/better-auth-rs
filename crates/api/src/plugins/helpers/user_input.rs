use better_auth_core::{AuthContext, AuthResult, AuthSchema, CreateUser};
use serde_json::{Map, Value};

/// Apply endpoint field policies once before route-owned proof values are assigned.
pub(crate) fn apply_user_create_fields(
    context: &AuthContext<impl AuthSchema>,
    input: &Map<String, Value>,
    user: &mut CreateUser,
) -> AuthResult<()> {
    user.assign_user_fields(context.parse_user_input(input, true)?)?;
    let enabled = |plugin| context.get_metadata(plugin).and_then(Value::as_bool) == Some(true);
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

fn optional_string(input: &Map<String, Value>, name: &str) -> AuthResult<Option<String>> {
    input
        .get(name)
        .map(|value| serde_json::from_value::<Option<String>>(value.clone()))
        .transpose()
        .map(Option::flatten)
        .map_err(Into::into)
}
