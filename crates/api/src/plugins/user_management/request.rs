use super::types::{ChangeEmailRequest, DeleteUserRequest};
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::{AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde_json::{Map, Value};

fn change_input(req: &AuthRequest) -> AuthResult<(ChangeEmailRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut output = Map::new();
    let mut errors = Vec::new();
    for (name, required) in [("newEmail", true), ("callbackURL", false)] {
        match object.get(name) {
            Some(Value::String(value)) => {
                if name == "newEmail" && !crate::plugins::json_body::valid_email(value)? {
                    errors.push("[body.newEmail] Invalid email address".to_owned());
                }
                let _ = output.insert(name.into(), Value::String(value.clone()));
            }
            None if !required => {}
            value => errors.push(invalid_type(&format!("body.{name}"), "string", value)),
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let projection = Value::Object(output);
    Ok((serde_json::from_value(projection.clone())?, projection))
}
fn delete_input(req: &AuthRequest) -> AuthResult<(DeleteUserRequest, Value)> {
    crate::plugins::json_body::string_input(
        req,
        &[
            ("callbackURL", false),
            ("password", false),
            ("token", false),
        ],
    )
}
pub(super) fn change_email_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = change_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn delete_user_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = delete_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn change_email(req: &AuthRequest) -> AuthResult<ChangeEmailRequest> {
    match req.validated_body::<ChangeEmailRequest>() {
        Some(body) => Ok(body.clone()),
        None => change_input(req).map(|(body, _)| body),
    }
}
pub(super) fn delete_user(req: &AuthRequest) -> AuthResult<DeleteUserRequest> {
    match req.validated_body::<DeleteUserRequest>() {
        Some(body) => Ok(body.clone()),
        None => delete_input(req).map(|(body, _)| body),
    }
}
