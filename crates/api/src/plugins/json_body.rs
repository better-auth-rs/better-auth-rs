use better_auth_core::{AuthRequest, AuthResponse};
use serde_json::{Value, json};

/// Parse the HTTP JSON boundary before endpoint schema validation.
pub(crate) fn parse(req: &AuthRequest) -> Result<Option<Value>, AuthResponse> {
    let Some(bytes) = req.body.as_deref().filter(|bytes| !bytes.is_empty()) else {
        return Ok(None);
    };
    let content_type = req
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .contains("application/json")
    {
        let message = if content_type.is_empty() {
            "Content-Type is required. Allowed types: application/json".to_owned()
        } else {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
            )
        };
        return Err(error_response(415, "UNSUPPORTED_MEDIA_TYPE", &message));
    }
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|_| error_response(400, "BAD_REQUEST", "Invalid JSON in request body"))
}

pub(crate) fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

pub(crate) fn invalid_type(location: &str, expected: &str, value: Option<&Value>) -> String {
    format!(
        "[{location}] Invalid input: expected {expected}, received {}",
        type_name(value)
    )
}

pub(crate) fn validation_error(message: &str) -> AuthResponse {
    error_response(400, "VALIDATION_ERROR", message)
}

pub(crate) fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn error_response(status: u16, code: &str, message: &str) -> AuthResponse {
    AuthResponse::text(
        status,
        json!({ "code": code, "message": message }).to_string(),
    )
    .with_header("content-type", "application/json")
}

#[derive(Default)]
pub(crate) struct SignOutBody {
    pub callback_url: Option<String>,
    pub disable_redirect: Option<bool>,
    pub state: Option<String>,
}

pub(crate) fn sign_out(req: &AuthRequest) -> Result<SignOutBody, AuthResponse> {
    let Some(body) = parse(req)? else {
        return Ok(SignOutBody::default());
    };
    let Some(body) = body.as_object() else {
        return Err(validation_error(&invalid_type(
            "body",
            "object",
            Some(&body),
        )));
    };
    let mut errors = Vec::new();
    for (field, expected) in [
        ("callbackURL", "string"),
        ("disableRedirect", "boolean"),
        ("state", "string"),
    ] {
        if let Some(value) = body.get(field)
            && type_name(Some(value)) != expected
        {
            errors.push(invalid_type(
                &format!("body.{field}"),
                expected,
                Some(value),
            ));
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")));
    }
    Ok(SignOutBody {
        callback_url: body
            .get("callbackURL")
            .and_then(Value::as_str)
            .map(str::to_owned),
        disable_redirect: body.get("disableRedirect").and_then(Value::as_bool),
        state: body.get("state").and_then(Value::as_str).map(str::to_owned),
    })
}
