use better_auth_core::endpoint_input::ValidatedBody;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthResult};
use serde_json::Value;

use crate::plugins::json_body::{invalid_type, validation_error};

pub(super) fn read(req: &AuthRequest) -> Result<Value, AuthResponse> {
    req.validated_body::<Value>()
        .cloned()
        .map_or_else(|| parse(req).map_err(|error| error.to_auth_response()), Ok)
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let body = parse(req)?;
    Ok(ValidatedBody::new(Some(body.clone()), body))
}

fn parse(req: &AuthRequest) -> AuthResult<Value> {
    let (strings, booleans): (&[&str], &[&str]) = match req.path() {
        "/sign-in/phone-number" => (&["phoneNumber", "password"], &["rememberMe"]),
        "/phone-number/send-otp" | "/phone-number/request-password-reset" => {
            (&["phoneNumber"], &[])
        }
        "/phone-number/verify" => (
            &["phoneNumber", "code"],
            &["disableSession", "updatePhoneNumber"],
        ),
        "/phone-number/reset-password" => (&["otp", "phoneNumber", "newPassword"], &[]),
        _ => return Err(AuthError::internal("Unknown Phone Number body schema")),
    };
    let record = req.path() == "/phone-number/verify";
    let input = req.input_body()?;
    let body = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        let mut message = invalid_type("body", "object", input.as_ref());
        if record {
            message.push_str("; ");
            message.push_str(&invalid_type("body", "record", input.as_ref()));
        }
        AuthError::from(validation_error(&message))
    })?;
    let mut errors = Vec::new();
    for key in strings {
        if !body.get(*key).is_some_and(Value::is_string) {
            errors.push(invalid_type(
                &format!("body.{key}"),
                "string",
                body.get(*key),
            ));
        }
    }
    for key in booleans {
        if body.get(*key).is_some_and(|value| !value.is_boolean()) {
            errors.push(invalid_type(
                &format!("body.{key}"),
                "boolean",
                body.get(*key),
            ));
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    Ok(Value::Object(
        body.iter()
            .filter(|(key, _)| {
                key.as_str() != "__proto__"
                    && (record
                        || strings.contains(&key.as_str())
                        || booleans.contains(&key.as_str()))
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}
