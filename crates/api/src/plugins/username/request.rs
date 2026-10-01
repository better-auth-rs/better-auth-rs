use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::{AuthRequest, AuthResponse, AuthResult, endpoint_input::ValidatedBody};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Clone, Deserialize)]
pub(crate) struct SignInUsernameRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    #[serde(rename = "rememberMe")]
    pub(crate) remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}
fn sign_in_input(request: &AuthRequest) -> AuthResult<(SignInUsernameRequest, Value)> {
    let body = request.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut issues = Vec::new();
    let mut output = Map::new();
    for (name, expected, required) in [
        ("username", "string", true),
        ("password", "string", true),
        ("rememberMe", "boolean", false),
        ("callbackURL", "string", false),
    ] {
        let value = object.get(name);
        if !required && value.is_none() {
            continue;
        }
        if value.is_some_and(|value| {
            if expected == "boolean" {
                value.is_boolean()
            } else {
                value.is_string()
            }
        }) {
            if let Some(value) = value {
                let _ = output.insert(name.into(), value.clone());
            }
        } else {
            issues.push(invalid_type(&format!("body.{name}"), expected, value));
        }
    }
    if !issues.is_empty() {
        return Err(validation_error(&issues.join("; ")).into());
    }
    let projection = Value::Object(output);
    Ok((serde_json::from_value(projection.clone())?, projection))
}
pub(super) fn sign_in_body(request: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (body, projection) = sign_in_input(request)?;
    Ok(ValidatedBody::new(Some(projection), body))
}
pub(super) fn sign_in(request: &AuthRequest) -> Result<SignInUsernameRequest, AuthResponse> {
    match request.validated_body::<SignInUsernameRequest>() {
        Some(body) => Ok(body.clone()),
        None => sign_in_input(request)
            .map(|(body, _)| body)
            .map_err(|error| error.to_auth_response()),
    }
}
#[derive(Deserialize)]
struct Availability {
    username: String,
}
pub(super) fn availability_body(request: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (body, projection) =
        crate::plugins::json_body::string_input::<Availability>(request, &[("username", true)])?;
    Ok(ValidatedBody::new(Some(projection), body.username))
}
pub(super) fn availability(request: &AuthRequest) -> Result<String, AuthResponse> {
    match request.validated_body::<String>() {
        Some(body) => Ok(body.clone()),
        None => {
            crate::plugins::json_body::string_input::<Availability>(request, &[("username", true)])
                .map(|(body, _)| body.username)
                .map_err(|error| error.to_auth_response())
        }
    }
}
