use better_auth_core::{AuthRequest, AuthResponse};
use serde_json::{Value, json};

pub(crate) fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Parse the HTTP JSON boundary before endpoint schema validation.
pub(crate) fn parse(req: &AuthRequest) -> Result<Option<Value>, AuthResponse> {
    let Some(bytes) = req.body.as_deref().filter(|bytes| !bytes.is_empty()) else {
        return Ok(None);
    };
    if better_auth_core::hooks::current_request_hook_context()
        .is_some_and(|context| !context.is_http)
    {
        return decode(bytes).map(Some);
    }
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
    decode(bytes).map(Some)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Value, AuthResponse> {
    serde_json::from_slice(bytes)
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

fn error_response(status: u16, code: &str, message: &str) -> AuthResponse {
    AuthResponse::text(
        status,
        json!({ "code": code, "message": message }).to_string(),
    )
    .with_header("content-type", "application/json")
}

#[derive(Clone, Default)]
pub(crate) struct SignOutBody {
    pub callback_url: Option<String>,
    pub disable_redirect: Option<bool>,
    pub state: Option<String>,
}

fn parse_sign_out(req: &AuthRequest) -> better_auth_core::AuthResult<(SignOutBody, Option<Value>)> {
    let input = req.input_body()?;
    let Some(body) = input else {
        return Ok((SignOutBody::default(), None));
    };
    let object = body.as_object().ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            Some(&body),
        )))
    })?;
    let mut errors = Vec::new();
    let mut output = serde_json::Map::new();
    for (field, expected) in [
        ("callbackURL", "string"),
        ("disableRedirect", "boolean"),
        ("state", "string"),
    ] {
        if let Some(value) = object.get(field) {
            if type_name(Some(value)) != expected {
                errors.push(invalid_type(
                    &format!("body.{field}"),
                    expected,
                    Some(value),
                ));
            } else {
                let _ = output.insert(field.to_owned(), value.clone());
            }
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let typed = SignOutBody {
        callback_url: output
            .get("callbackURL")
            .and_then(Value::as_str)
            .map(str::to_owned),
        disable_redirect: output.get("disableRedirect").and_then(Value::as_bool),
        state: output
            .get("state")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    Ok((typed, Some(Value::Object(output))))
}

pub(crate) fn sign_out_body(
    req: &AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (typed, projection) = parse_sign_out(req)?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        projection, typed,
    ))
}

pub(crate) fn sign_out(req: &AuthRequest) -> Result<SignOutBody, AuthResponse> {
    match req.validated_body::<SignOutBody>() {
        Some(body) => Ok(body.clone()),
        None => parse_sign_out(req)
            .map(|(body, _)| body)
            .map_err(|error| error.to_auth_response()),
    }
}

pub(crate) fn valid_email(email: &str) -> better_auth_core::AuthResult<bool> {
    static EMAIL: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"\A(?:[A-Za-z0-9_'+\-]+\.)*[A-Za-z0-9_'+\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}\z",
            )
        });
    let expression = EMAIL.as_ref().map_err(|error| {
        better_auth_core::AuthError::internal(format!("Invalid email schema: {error}"))
    })?;
    Ok(expression.is_match(email))
}

pub(crate) fn string_input<T: serde::de::DeserializeOwned>(
    req: &AuthRequest,
    fields: &[(&str, bool)],
) -> better_auth_core::AuthResult<(T, Value)> {
    string_fields_input(req, fields, None)
}

pub(crate) fn email_input<T: serde::de::DeserializeOwned>(
    req: &AuthRequest,
    email: &str,
    optional: &str,
) -> better_auth_core::AuthResult<(T, Value)> {
    string_fields_input(req, &[(email, true), (optional, false)], Some(email))
}

fn string_fields_input<T: serde::de::DeserializeOwned>(
    req: &AuthRequest,
    fields: &[(&str, bool)],
    email: Option<&str>,
) -> better_auth_core::AuthResult<(T, Value)> {
    let body = req.input_body()?;
    let object = body.as_ref().and_then(Value::as_object).ok_or_else(|| {
        better_auth_core::AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )))
    })?;
    let mut output = serde_json::Map::new();
    let mut errors = Vec::new();
    for &(name, required) in fields {
        match object.get(name) {
            Some(value @ Value::String(text)) => {
                if email == Some(name) && !valid_email(text)? {
                    errors.push(format!("[body.{name}] Invalid email address"));
                }
                let _ = output.insert(name.into(), value.clone());
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
