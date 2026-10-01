use better_auth_core::{AuthError, AuthRequest, AuthResult};
use serde_json::Value;

use super::SignInRequest;
use crate::plugins::json_body::{invalid_type, type_name, validation_error};

fn parse_sign_in(req: &AuthRequest) -> AuthResult<(SignInRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut issues = Vec::new();
    let mut output = serde_json::Map::new();
    for (field, expected, required) in [
        ("email", "string", true),
        ("password", "string", true),
        ("callbackURL", "string", false),
        ("rememberMe", "boolean", false),
    ] {
        let value = object.get(field);
        if (required || value.is_some()) && type_name(value) != expected {
            issues.push(invalid_type(&format!("body.{field}"), expected, value));
        } else if let Some(value) = value {
            let _ = output.insert(field.to_owned(), value.clone());
        }
    }
    if !issues.is_empty() {
        return Err(validation_error(&issues.join("; ")).into());
    }
    let _ = output
        .entry("rememberMe".to_owned())
        .or_insert(Value::Bool(true));
    let projection = Value::Object(output);
    Ok((serde_json::from_value(projection.clone())?, projection))
}

pub(super) fn sign_in_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (typed, projection) = parse_sign_in(req)?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        typed,
    ))
}

pub(super) fn sign_in(req: &AuthRequest) -> AuthResult<SignInRequest> {
    match req.validated_body::<SignInRequest>() {
        Some(body) => Ok(body.clone()),
        None => parse_sign_in(req).map(|(body, _)| body),
    }
}

pub(super) async fn form_csrf(
    req: &AuthRequest,
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if req.has_http_body_context() || req.url().is_some() {
        let policy = ctx
            .extensions
            .get::<better_auth_core::middleware::CsrfConfig>()
            .cloned()
            .unwrap_or_default();
        better_auth_core::middleware::CsrfMiddleware::from_context(policy, ctx)
            .validate_form_request(req)
            .await?;
    }
    Ok(())
}

fn parse_sign_up(req: &AuthRequest) -> AuthResult<(super::SignUpRequest, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&format!(
            "{}; {}",
            invalid_type("body", "object", body.as_ref()),
            invalid_type("body", "record", body.as_ref())
        )))
    })?;
    let mut errors = Vec::new();
    for (field, expected, required) in [
        ("name", "string", true),
        ("email", "string", true),
        ("password", "string", true),
        ("image", "string", false),
        ("callbackURL", "string", false),
        ("rememberMe", "boolean", false),
    ] {
        let value = object.get(field);
        if (required || value.is_some()) && type_name(value) != expected {
            errors.push(invalid_type(&format!("body.{field}"), expected, value));
        } else if let Some(Value::String(value)) = value {
            if field == "email" && !crate::plugins::json_body::valid_email(value)? {
                errors.push("[body.email] Invalid email address".to_owned());
            }
            if field == "password" && value.is_empty() {
                errors.push(
                    "[body.password] Too small: expected string to have >=1 characters".to_owned(),
                );
            }
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let projection = Value::Object(object.clone());
    Ok((serde_json::from_value(projection.clone())?, projection))
}

pub(super) fn sign_up_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (typed, projection) = parse_sign_up(req)?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        typed,
    ))
}

pub(super) fn sign_up(req: &AuthRequest) -> AuthResult<super::SignUpRequest> {
    match req.validated_body::<super::SignUpRequest>() {
        Some(body) => Ok(body.clone()),
        None => parse_sign_up(req).map(|(body, _)| body),
    }
}
