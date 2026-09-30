use better_auth_core::{AuthRequest, AuthResponse};
use serde::de::DeserializeOwned;

use crate::plugins::json_body::{invalid_type, parse, validation_error};

pub(super) fn send_otp(req: &AuthRequest) -> Result<serde_json::Value, AuthResponse> {
    let Some(value) = parse(req)? else {
        return Ok(serde_json::Value::Null);
    };
    let body = value
        .as_object()
        .ok_or_else(|| validation_error(&invalid_type("body", "object", Some(&value))))?;
    let mut filtered = serde_json::Map::new();
    if let Some(trust_device) = body.get("trustDevice") {
        if !trust_device.is_boolean() {
            return Err(validation_error(&invalid_type(
                "body.trustDevice",
                "boolean",
                Some(trust_device),
            )));
        }
        _ = filtered.insert("trustDevice".to_owned(), trust_device.clone());
    }
    Ok(serde_json::Value::Object(filtered))
}

pub(super) fn password<T: DeserializeOwned>(
    req: &AuthRequest,
    optional: bool,
    enable: bool,
) -> Result<T, AuthResponse> {
    let value =
        parse(req)?.ok_or_else(|| validation_error(&invalid_type("body", "object", None)))?;
    let body = value
        .as_object()
        .ok_or_else(|| validation_error(&invalid_type("body", "object", Some(&value))))?;
    let mut errors = Vec::new();
    let password = body.get("password");
    if (password.is_some() || !optional) && !password.is_some_and(serde_json::Value::is_string) {
        errors.push(invalid_type("body.password", "string", password));
    }
    if enable {
        if let Some(method) = body.get("method")
            && !matches!(method.as_str(), Some("totp" | "otp"))
        {
            errors
                .push("[body.method] Invalid option: expected one of \"otp\"|\"totp\"".to_owned());
        }
        if let Some(issuer) = body.get("issuer")
            && !issuer.is_string()
        {
            errors.push(invalid_type("body.issuer", "string", Some(issuer)));
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")));
    }
    serde_json::from_value(value).map_err(|error| validation_error(&error.to_string()))
}
