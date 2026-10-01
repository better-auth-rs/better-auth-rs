use better_auth_core::{AuthRequest, AuthResponse};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::plugins::json_body::{invalid_type, parse, validation_error};

#[derive(Deserialize)]
pub(crate) struct SignInUsernameRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    #[serde(rename = "rememberMe")]
    pub(crate) remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

fn object(request: &AuthRequest) -> Result<Map<String, Value>, AuthResponse> {
    let body = parse(request)?;
    body.as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| validation_error(&invalid_type("body", "object", body.as_ref())))
}

pub(super) fn sign_in(request: &AuthRequest) -> Result<SignInUsernameRequest, AuthResponse> {
    let body = object(request)?;
    let mut issues = Vec::new();
    for (name, expected, required) in [
        ("username", "string", true),
        ("password", "string", true),
        ("rememberMe", "boolean", false),
        ("callbackURL", "string", false),
    ] {
        let value = body.get(name);
        if (required || value.is_some())
            && !value.is_some_and(|value| {
                if expected == "boolean" {
                    value.is_boolean()
                } else {
                    value.is_string()
                }
            })
        {
            issues.push(invalid_type(&format!("body.{name}"), expected, value));
        }
    }
    if !issues.is_empty() {
        return Err(validation_error(&issues.join("; ")));
    }
    serde_json::from_value(Value::Object(body))
        .map_err(|error| validation_error(&error.to_string()))
}

pub(super) fn availability(request: &AuthRequest) -> Result<String, AuthResponse> {
    let body = object(request)?;
    body.get("username")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            validation_error(&invalid_type(
                "body.username",
                "string",
                body.get("username"),
            ))
        })
}
