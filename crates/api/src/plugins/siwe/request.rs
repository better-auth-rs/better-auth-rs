use crate::plugins::json_body;
use better_auth_core::{AuthError, AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct VerifyBody {
    pub message: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}
pub(super) fn nonce(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let body = req.input_body()?;
    if let Some(value) = &body {
        if !value.is_object() {
            return Err(json_body::validation_error(&json_body::invalid_type(
                "body",
                "object",
                Some(value),
            ))
            .into());
        }
        if let Some(error) = super::unknown_keys(value, &[]) {
            return Err(json_body::validation_error(&error).into());
        }
    }
    Ok(ValidatedBody::new(body, ()))
}
pub(super) fn verify(req: &AuthRequest, anonymous: bool) -> AuthResult<ValidatedBody> {
    let input = req.input_body()?;
    let body = input
        .as_ref()
        .filter(|body| body.is_object())
        .ok_or_else(|| {
            AuthError::from(json_body::validation_error(&json_body::invalid_type(
                "body",
                "object",
                input.as_ref(),
            )))
        })?;
    let mut errors = Vec::new();
    let mut valid_types = true;
    for field in ["message", "signature"] {
        match body.get(field) {
            Some(Value::String(value)) if value.is_empty() => errors.push(format!(
                "[body.{field}] Too small: expected string to have >=1 characters"
            )),
            Some(Value::String(_)) => {}
            value => {
                valid_types = false;
                errors.push(json_body::invalid_type(
                    &format!("body.{field}"),
                    "string",
                    value,
                ));
            }
        }
    }
    let email = body.get("email").and_then(Value::as_str);
    match body.get("email") {
        Some(Value::String(value)) if !json_body::valid_email(value)? => {
            errors.push("[body.email] Invalid email address".to_owned())
        }
        None | Some(Value::String(_)) => {}
        value => {
            valid_types = false;
            errors.push(json_body::invalid_type("body.email", "string", value));
        }
    }
    if let Some(error) = super::unknown_keys(body, &["message", "signature", "email"]) {
        errors.push(error);
    }
    if valid_types && !anonymous && email.is_none_or(str::is_empty) {
        errors.push(
            "[body.email] Email is required when the anonymous plugin option is disabled."
                .to_owned(),
        );
    }
    if !errors.is_empty() {
        return Err(json_body::validation_error(&errors.join("; ")).into());
    }
    if req.original_request().is_none()
        && better_auth_core::hooks::current_request_hook_context()
            .is_some_and(|context| !context.is_http)
    {
        return Err(json_body::validation_error("Request is required").into());
    }
    let typed: VerifyBody = serde_json::from_value(body.clone())?;
    Ok(ValidatedBody::new(
        Some(serde_json::to_value(&typed)?),
        typed,
    ))
}
pub(super) fn read(req: &AuthRequest, anonymous: bool) -> AuthResult<VerifyBody> {
    if let Some(body) = req.validated_body::<VerifyBody>() {
        return Ok(body.clone());
    }
    verify(req, anonymous)?
        .get::<VerifyBody>()
        .cloned()
        .ok_or_else(|| AuthError::internal("SIWE validator returned a different body type"))
}
