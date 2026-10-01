use super::types::{CreateKeyRequest, DeleteKeyRequest, UpdateKeyRequest};
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, SchemaValue, endpoint_input::ValidatedBody,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
enum Field {
    String,
    Id,
    Prefix,
    Boolean,
    Number(Option<f64>),
    Permissions,
    Any,
}

type Spec = (&'static str, Field, bool, bool);

pub(super) fn read<T: Clone + Send + Sync + 'static>(req: &AuthRequest) -> AuthResult<T> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok(body.clone());
    }
    validate(req)?.get::<T>().cloned().ok_or_else(|| {
        AuthError::internal("API key body validator returned a different input type")
    })
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    validate_value(req.path(), req.input_body()?.as_ref())
}

fn typed<T: DeserializeOwned + Send + Sync + 'static>(body: Value) -> AuthResult<ValidatedBody> {
    Ok(ValidatedBody::new(
        Some(body.clone()),
        serde_json::from_value::<T>(body)?,
    ))
}

pub(super) fn validate_value(path: &str, input: Option<&Value>) -> AuthResult<ValidatedBody> {
    validate_numbers(path, input, &[])
}

pub(super) fn validate_numbers(
    path: &str,
    input: Option<&Value>,
    numbers: &[(&str, Option<f64>)],
) -> AuthResult<ValidatedBody> {
    use Field::*;
    let body = input
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::from(validation_error(&invalid_type("body", "object", input))))?;
    // Tuple flags describe required and nullable fields, in the declared Zod order.
    let fields: &[Spec] = match path {
        "/api-key/create" => &[
            ("configId", String, false, false),
            ("name", String, false, false),
            ("expiresIn", Number(Some(1.0)), false, true),
            ("prefix", Prefix, false, false),
            ("remaining", Number(Some(0.0)), false, true),
            ("metadata", Any, false, true),
            ("refillAmount", Number(Some(1.0)), false, false),
            ("refillInterval", Number(None), false, false),
            ("rateLimitTimeWindow", Number(None), false, false),
            ("rateLimitMax", Number(None), false, false),
            ("rateLimitEnabled", Boolean, false, false),
            ("permissions", Permissions, false, false),
            ("userId", Id, false, true),
            ("organizationId", Id, false, true),
        ],
        "/api-key/update" => &[
            ("configId", String, false, false),
            ("keyId", String, true, false),
            ("userId", Id, false, true),
            ("name", String, false, false),
            ("enabled", Boolean, false, false),
            ("remaining", Number(Some(1.0)), false, false),
            ("refillAmount", Number(None), false, false),
            ("refillInterval", Number(None), false, false),
            ("metadata", Any, false, true),
            ("expiresIn", Number(Some(1.0)), false, true),
            ("rateLimitEnabled", Boolean, false, false),
            ("rateLimitTimeWindow", Number(None), false, false),
            ("rateLimitMax", Number(None), false, false),
            ("permissions", Permissions, false, true),
        ],
        "/api-key/delete" => &[
            ("configId", String, false, false),
            ("keyId", String, true, false),
        ],
        "verifyApiKey" => &[
            ("configId", String, false, false),
            ("key", String, true, false),
            ("permissions", Permissions, false, false),
        ],
        _ => return Err(AuthError::internal("Unknown API key input schema")),
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for &(name, kind, required, nullable) in fields {
        // serde_json serializes non-finite Rust numbers as null. Retain their schema error before that lossy boundary.
        if let Some(value) = numbers
            .iter()
            .find_map(|(field, value)| (*field == name).then_some(*value).flatten())
            .filter(|value| !value.is_finite())
        {
            errors.push(format!(
                "[body.{name}] {}",
                super::types::nonfinite_number_error(value)
            ));
            continue;
        }
        let value = body.get(name);
        if value.is_none() && !required {
            if path == "/api-key/create" && matches!(name, "expiresIn" | "remaining") {
                let _ = output.insert(name.into(), Value::Null);
            }
            continue;
        }
        let location = format!("body.{name}");
        if matches!(kind, Id) {
            let value = SchemaValue::<Value>::from_json(value.cloned()).display_string()?;
            let _ = output.insert(name.into(), Value::String(value));
            continue;
        }
        if nullable && value.is_some_and(Value::is_null) {
            let _ = output.insert(name.into(), Value::Null);
            continue;
        }
        let (valid, expected) = match kind {
            String | Prefix => (value.is_some_and(Value::is_string), "string"),
            Boolean => (value.is_some_and(Value::is_boolean), "boolean"),
            Number(_) => (value.is_some_and(Value::is_number), "number"),
            Permissions => (value.is_some_and(Value::is_object), "record"),
            Any | Id => (true, "unknown"),
        };
        if !valid {
            errors.push(invalid_type(&location, expected, value));
            continue;
        }
        let Some(value) = value else {
            continue;
        };
        match kind {
            Prefix
                if value.as_str().is_some_and(|prefix| {
                    prefix.is_empty()
                        || !prefix
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                }) =>
            {
                errors.push(format!("[{location}] Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."));
            }
            Number(Some(minimum)) if value.as_f64().is_some_and(|value| value < minimum) => {
                errors.push(format!(
                    "[{location}] Too small: expected number to be >={minimum}"
                ));
            }
            Permissions => {
                if let Some(permissions) = value.as_object() {
                    for (resource, actions) in permissions {
                        let location = format!("{location}.{resource}");
                        if let Some(actions) = actions.as_array() {
                            for (index, action) in actions.iter().enumerate() {
                                if !action.is_string() {
                                    errors.push(invalid_type(
                                        &format!("{location}.{index}"),
                                        "string",
                                        Some(action),
                                    ));
                                }
                            }
                        } else {
                            errors.push(invalid_type(&location, "array", Some(actions)));
                        }
                    }
                }
            }
            _ => {}
        }
        let _ = output.insert(name.into(), value.clone());
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    let output = Value::Object(output);
    match path {
        "/api-key/create" => typed::<CreateKeyRequest>(output),
        "/api-key/update" => typed::<UpdateKeyRequest>(output),
        "/api-key/delete" => typed::<DeleteKeyRequest>(output),
        _ => Ok(ValidatedBody::new(Some(output.clone()), output)),
    }
}
