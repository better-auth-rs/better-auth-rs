use super::types::ResetPasswordRequest;
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::{AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde_json::{Map, Value};

fn parse_reset(req: &AuthRequest) -> AuthResult<(ResetPasswordRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut errors = Vec::new();
    let mut output = Map::new();
    for (name, required) in [("newPassword", true), ("token", false)] {
        match object.get(name) {
            Some(value @ Value::String(_)) => {
                let _ = output.insert(name.to_owned(), value.clone());
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

pub(super) fn reset_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = parse_reset(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}

pub(super) fn reset(req: &AuthRequest) -> AuthResult<ResetPasswordRequest> {
    match req.validated_body::<ResetPasswordRequest>() {
        Some(body) => Ok(body.clone()),
        None => parse_reset(req).map(|(body, _)| body),
    }
}

fn request_reset_input(
    req: &AuthRequest,
) -> AuthResult<(super::types::RequestPasswordResetRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut errors = Vec::new();
    let mut output = Map::new();
    for (name, required) in [("email", true), ("redirectTo", false)] {
        match object.get(name) {
            Some(Value::String(value)) => {
                if name == "email" && !crate::plugins::json_body::valid_email(value)? {
                    errors.push("[body.email] Invalid email address".to_owned());
                }
                let _ = output.insert(name.to_owned(), Value::String(value.clone()));
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

fn change_input(req: &AuthRequest) -> AuthResult<(super::types::ChangePasswordRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut errors = Vec::new();
    let mut output = Map::new();
    for (name, expected, required) in [
        ("newPassword", "string", true),
        ("currentPassword", "string", true),
        ("revokeOtherSessions", "boolean", false),
    ] {
        let value = object.get(name);
        if (required || value.is_some()) && crate::plugins::json_body::type_name(value) != expected
        {
            errors.push(invalid_type(&format!("body.{name}"), expected, value));
        } else if let Some(value) = value {
            let _ = output.insert(name.to_owned(), value.clone());
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let projection = Value::Object(output);
    Ok((serde_json::from_value(projection.clone())?, projection))
}

fn verify_input(req: &AuthRequest) -> AuthResult<(super::types::VerifyPasswordRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let Some(Value::String(password)) = object.get("password") else {
        return Err(validation_error(&invalid_type(
            "body.password",
            "string",
            object.get("password"),
        ))
        .into());
    };
    Ok((
        super::types::VerifyPasswordRequest {
            password: password.clone(),
        },
        serde_json::json!({"password":password}),
    ))
}

pub(super) fn request_reset_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = request_reset_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn change_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = change_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn verify_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = verify_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn request_reset(
    req: &AuthRequest,
) -> AuthResult<super::types::RequestPasswordResetRequest> {
    match req.validated_body::<super::types::RequestPasswordResetRequest>() {
        Some(body) => Ok(body.clone()),
        None => request_reset_input(req).map(|(body, _)| body),
    }
}
pub(super) fn change(req: &AuthRequest) -> AuthResult<super::types::ChangePasswordRequest> {
    match req.validated_body::<super::types::ChangePasswordRequest>() {
        Some(body) => Ok(body.clone()),
        None => change_input(req).map(|(body, _)| body),
    }
}
pub(super) fn verify(req: &AuthRequest) -> AuthResult<super::types::VerifyPasswordRequest> {
    match req.validated_body::<super::types::VerifyPasswordRequest>() {
        Some(body) => Ok(body.clone()),
        None => verify_input(req).map(|(body, _)| body),
    }
}
