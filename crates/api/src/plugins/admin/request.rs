use super::types::*;
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, SchemaValue, endpoint_input::ValidatedBody,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub(super) fn read<T: Clone + Send + Sync + 'static>(req: &AuthRequest) -> AuthResult<T> {
    if let Some(value) = req.validated_body::<T>() {
        return Ok(value.clone());
    }
    validate(req)?
        .get::<T>()
        .cloned()
        .ok_or_else(|| AuthError::internal("Admin body validator returned a different input type"))
}

fn typed<T: DeserializeOwned + Send + Sync + 'static>(
    output: Map<String, Value>,
) -> AuthResult<ValidatedBody> {
    let output = Value::Object(output);
    Ok(ValidatedBody::new(
        Some(output.clone()),
        serde_json::from_value::<T>(output)?,
    ))
}

#[derive(Clone, Copy)]
enum Field {
    String,
    Id,
    Role,
    Record,
    Number,
}
fn field(
    body: &Map<String, Value>,
    output: &mut Map<String, Value>,
    errors: &mut Vec<String>,
    name: &str,
    kind: Field,
    required: bool,
) -> AuthResult<()> {
    let value = body.get(name);
    if value.is_none() && !required {
        return Ok(());
    }
    if matches!(kind, Field::Id) {
        if value.is_none() {
            errors.push(invalid_type(&format!("body.{name}"), "nonoptional", None));
            return Ok(());
        }
        let value = SchemaValue::<Value>::from_json(value.cloned()).display_string()?;
        let _ = output.insert(name.into(), value.into());
        return Ok(());
    }
    let (valid, expected) = match kind {
        Field::String => (value.is_some_and(Value::is_string), "string"),
        Field::Number => (value.is_some_and(Value::is_number), "number"),
        Field::Record => (value.is_some_and(Value::is_object), "record"),
        Field::Role => (
            value.is_some_and(|v| {
                v.is_string()
                    || v.as_array()
                        .is_some_and(|values| values.iter().all(Value::is_string))
            }),
            "union",
        ),
        Field::Id => (true, "string"),
    };
    if valid {
        if let Some(value) = value {
            let _ = output.insert(name.into(), value.clone());
        }
    } else {
        errors.push(if matches!(kind, Field::Role) {
            format!("[body.{name}] Invalid input")
        } else {
            invalid_type(&format!("body.{name}"), expected, value)
        });
    }
    Ok(())
}

fn permission_branch(body: &Map<String, Value>, name: &str) -> Option<Value> {
    body.get(name)
        .filter(|value| {
            value.as_object().is_some_and(|values| {
                values.values().all(|value| {
                    value
                        .as_array()
                        .is_some_and(|values| values.iter().all(Value::is_string))
                })
            })
        })
        .cloned()
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    use Field::*;
    let input = req.input_body()?;
    let body = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        let mut message = invalid_type("body", "object", input.as_ref());
        if req.path() == "/admin/has-permission" {
            message.push_str("; [body] Invalid input");
        }
        AuthError::from(validation_error(&message))
    })?;
    let mut output = Map::new();
    let mut errors = Vec::new();
    let fields: &[(&str, Field, bool)] = match req.path() {
        "/admin/set-role" => &[("userId", Id, true), ("role", Role, true)],
        "/admin/create-user" => &[
            ("email", String, true),
            ("password", String, false),
            ("name", String, true),
            ("role", Role, false),
            ("data", Record, false),
        ],
        "/admin/update-user" => &[("userId", Id, true), ("data", Record, true)],
        "/admin/ban-user" => &[
            ("userId", Id, true),
            ("banReason", String, false),
            ("banExpiresIn", Number, false),
        ],
        "/admin/revoke-user-session" => &[("sessionToken", String, true)],
        "/admin/set-user-password" => &[("newPassword", String, true), ("userId", Id, true)],
        "/admin/has-permission" => &[("userId", Id, false), ("role", String, false)],
        _ => &[("userId", Id, true)],
    };
    for (name, kind, required) in fields {
        field(body, &mut output, &mut errors, name, *kind, *required)?;
        if req.path() == "/admin/set-user-password"
            && output.get(*name).and_then(Value::as_str) == Some("")
        {
            errors.push(format!("[body.{name}] {name} cannot be empty"));
        }
    }
    if req.path() == "/admin/has-permission" {
        match (
            permission_branch(body, "permission"),
            permission_branch(body, "permissions"),
        ) {
            (Some(_), Some(_)) => {
                errors.push("[body] Invalid input: more than one option matched".into())
            }
            (Some(value), None) => {
                let _ = output.insert("permission".into(), value);
            }
            (None, Some(value)) => {
                let _ = output.insert("permissions".into(), value);
            }
            (None, None) => errors.push("[body] Invalid input".into()),
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    match req.path() {
        "/admin/set-role" => typed::<SetRoleRequest>(output),
        "/admin/create-user" => typed::<CreateUserRequest>(output),
        "/admin/update-user" => typed::<AdminUpdateUserRequest>(output),
        "/admin/ban-user" => typed::<BanUserRequest>(output),
        "/admin/revoke-user-session" => typed::<RevokeSessionRequest>(output),
        "/admin/set-user-password" => typed::<SetUserPasswordRequest>(output),
        "/admin/has-permission" => typed::<HasPermissionRequest>(output),
        _ => typed::<UserIdRequest>(output),
    }
}
