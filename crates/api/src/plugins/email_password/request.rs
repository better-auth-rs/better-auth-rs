use better_auth_core::{AuthError, AuthRequest, AuthResult};
use serde_json::Value;

use super::SignInRequest;
use crate::plugins::json_body::{decode, invalid_type, type_name, validation_error};

pub(super) fn complete_signup_username(body: &mut Value) {
    let Some(body) = body.as_object_mut() else {
        return;
    };
    if !body.contains_key("username")
        && let Some(display) = body.get("displayUsername").and_then(Value::as_str)
        && better_auth_core::utils::username::validate_username(display).is_ok()
    {
        let _ = body.insert("username".into(), display.into());
    }
    if !body
        .get("displayUsername")
        .is_some_and(better_auth_core::user_fields::is_truthy)
        && let Some(username) = body
            .get("username")
            .filter(|value| better_auth_core::user_fields::is_truthy(value))
            .cloned()
    {
        let _ = body.insert("displayUsername".into(), username);
    }
}

pub(super) fn sign_in(req: &AuthRequest) -> AuthResult<SignInRequest> {
    let body = if let Some(body) = req.parsed_http_body() {
        Some(body.clone())
    } else {
        req.body
            .as_deref()
            .filter(|body| !body.is_empty())
            .map(decode)
            .transpose()
            .map_err(AuthError::from)?
    };
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut issues = Vec::new();
    for (field, expected, required) in [
        ("email", "string", true),
        ("password", "string", true),
        ("callbackURL", "string", false),
        ("rememberMe", "boolean", false),
    ] {
        let value = object.get(field);
        if (required || value.is_some()) && type_name(value) != expected {
            issues.push(invalid_type(&format!("body.{field}"), expected, value));
        }
    }
    if !issues.is_empty() {
        return Err(validation_error(&issues.join("; ")).into());
    }
    serde_json::from_value(Value::Object(object.clone())).map_err(AuthError::from)
}

pub(super) fn form_csrf(
    req: &AuthRequest,
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if req.has_http_body_context() || req.url().is_some() {
        let policy = ctx
            .extensions
            .get::<better_auth_core::middleware::CsrfConfig>()
            .cloned()
            .unwrap_or_default();
        better_auth_core::middleware::CsrfMiddleware::new(policy, ctx.config.clone())
            .validate_form_request(req)?;
    }
    Ok(())
}
