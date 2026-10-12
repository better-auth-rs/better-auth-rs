use super::types::{CreateKeyRequest, DeleteKeyRequest, UpdateKeyRequest};
use crate::plugins::json_body::{native_invalid_type, validation_error};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, FieldMap, FieldValue, SchemaValue,
    endpoint_input::ValidatedBody,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct VerifyKeyRequest {
    pub key: String,
    pub config_id: Option<String>,
}

/// Capture endpoint destructuring before callbacks while retaining shared child values.
pub(super) struct CapturedInput<'a, T> {
    pub typed: &'a T,
    fields: FieldMap,
}

impl<'a, T> CapturedInput<'a, T> {
    pub(super) fn new(typed: &'a T, body: &FieldValue) -> AuthResult<Self> {
        Ok(Self {
            typed,
            fields: body.enumerable_fields()?,
        })
    }

    pub(super) fn field(&self, name: &str) -> FieldValue {
        self.fields.get(name).cloned().unwrap_or_default()
    }
}

pub(super) fn read<T: Clone + Send + Sync + 'static>(req: &AuthRequest) -> AuthResult<T> {
    read_with_body(req).map(|(body, _)| body)
}

pub(super) fn read_with_body<T: Clone + Send + Sync + 'static>(
    req: &AuthRequest,
) -> AuthResult<(T, FieldValue)> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok((body.clone(), req.input_field_value()?));
    }
    let validated = validate(req)?;
    let body = validated.get::<T>().cloned().ok_or_else(|| {
        AuthError::internal("API key body validator returned a different input type")
    })?;
    Ok((body, validated.field_value()))
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    validate_value(req.path(), &req.input_field_value()?)
}

pub(super) fn typed_input(
    input: &impl Serialize,
    numbers: &[(&str, Option<f64>)],
) -> AuthResult<FieldValue> {
    let value = FieldValue::from_json(serde_json::to_value(input)?)?;
    let object = value
        .as_object()
        .ok_or_else(|| AuthError::internal("API key request DTO must serialize to an object"))?;
    // Restore Rust numbers before hooks; validation must read the values left by those hooks.
    for &(name, number) in numbers {
        if let Some(number) = number {
            object.set(name, number.into())?;
        }
    }
    Ok(value)
}

fn typed<T: DeserializeOwned + Send + Sync + 'static>(
    native: FieldMap,
    body: FieldMap,
) -> AuthResult<ValidatedBody> {
    let body: FieldValue = body.into();
    Ok(ValidatedBody::native(
        native.into(),
        serde_json::from_value::<T>(body.decode()?)?,
    ))
}

pub(super) fn validate_value(path: &str, input: &FieldValue) -> AuthResult<ValidatedBody> {
    use Field::*;
    if !input.is_object() && input.as_date().is_none() {
        return Err(validation_error(&native_invalid_type(
            "body",
            "object",
            Some(input),
        )));
    }
    let body = input.as_object();
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
    let mut output = FieldMap::new();
    let mut typed_output = FieldMap::new();
    let mut errors = Vec::new();
    for &(name, kind, required, nullable) in fields {
        let input = body
            .map_or(Ok(None), |body| body.get(name))?
            .unwrap_or_default();
        let defaulted = path == "/api-key/create" && matches!(name, "expiresIn" | "remaining");
        let mut field_errors = Vec::new();
        let location = format!("body.{name}");
        let value = field_value(
            input,
            (name, kind, required, nullable),
            defaulted,
            &mut field_errors,
        )?;
        let present = body.map_or(Ok(false), |body| body.has_property(name))?;
        if !present && !required && !defaulted {
            continue;
        }
        if !present && required && field_errors.is_empty() {
            field_errors.push(native_invalid_type(&location, "nonoptional", None));
        }
        errors.extend(field_errors);
        if !present && value.is_undefined() {
            continue;
        }
        // Arbitrary values remain in the native projection until business or storage code consumes them.
        if !matches!(kind, Any) && !value.is_undefined() {
            let _ = typed_output.insert(name.into(), value.clone());
        }
        let _ = output.insert(name.into(), value);
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")));
    }
    match path {
        "/api-key/create" => typed::<CreateKeyRequest>(output, typed_output),
        "/api-key/update" => typed::<UpdateKeyRequest>(output, typed_output),
        "/api-key/delete" => typed::<DeleteKeyRequest>(output, typed_output),
        _ => typed::<VerifyKeyRequest>(output, typed_output),
    }
}

fn field_value(
    value: FieldValue,
    (name, kind, required, nullable): Spec,
    defaulted: bool,
    errors: &mut Vec<String>,
) -> AuthResult<FieldValue> {
    use Field::*;
    let location = format!("body.{name}");
    if value.is_undefined() && !required {
        return Ok(if defaulted { FieldValue::Null } else { value });
    }
    if matches!(kind, Id) {
        return Ok(SchemaValue::<FieldValue>::from_field(value)
            .display_string()?
            .into());
    }
    if nullable && value.is_null() {
        return Ok(value);
    }
    let (valid, expected) = match kind {
        String | Prefix => (value.is_string(), "string"),
        Boolean => (value.as_bool().is_some(), "boolean"),
        Number(_) => (value.as_f64().is_some_and(f64::is_finite), "number"),
        Permissions => (value.is_object() || value.as_date().is_some(), "record"),
        Any | Id => (true, "unknown"),
    };
    if !valid {
        errors.push(native_invalid_type(&location, expected, Some(&value)));
        return Ok(value);
    }
    match kind {
        Prefix => {
            let prefix = value.display_utf16()?;
            if prefix.as_utf16().is_empty()
                || !prefix.as_utf16().iter().all(|unit| {
                    u8::try_from(*unit).is_ok_and(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                    })
                })
            {
                errors.push(format!("[{location}] Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."));
            }
        }
        Number(Some(minimum)) if value.as_f64().is_some_and(|value| value < minimum) => {
            errors.push(format!(
                "[{location}] Too small: expected number to be >={minimum}"
            ));
        }
        Permissions => {
            let mut parsed = FieldMap::new();
            if let Some(permissions) = value.as_object() {
                for resource in permissions.own_keys()? {
                    if resource == "__proto__"
                        || !permissions
                            .own_property_descriptor(&resource)?
                            .is_some_and(|descriptor| descriptor.enumerable)
                    {
                        continue;
                    }
                    let actions = permissions.get(&resource)?.unwrap_or_default();
                    let location = format!("{location}.{resource}");
                    if let Some(actions) = actions.as_array() {
                        let mut parsed_actions = Vec::new();
                        for (index, action) in actions.iter()?.enumerate() {
                            let action = action?;
                            if !action.is_string() {
                                errors.push(native_invalid_type(
                                    &format!("{location}.{index}"),
                                    "string",
                                    Some(&action),
                                ));
                            }
                            parsed_actions.push(action);
                        }
                        let _ = parsed.insert(resource, parsed_actions.into());
                    } else {
                        errors.push(native_invalid_type(&location, "array", Some(&actions)));
                    }
                }
            }
            return Ok(parsed.into());
        }
        _ => {}
    }
    Ok(value)
}
