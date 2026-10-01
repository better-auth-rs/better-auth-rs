use super::types::RoleInput;
use crate::plugins::json_body;
use better_auth_core::{AuthError, AuthResult, SchemaValue, user_fields::UserConfig};
use serde_json::{Map, Value};

pub(super) fn string_operation<'a>(
    value: &'a SchemaValue<String>,
    operation: &str,
) -> AuthResult<&'a str> {
    value.typed().map(String::as_str).map_err(|error| {
        tracing::error!(%error, operation, "Organization string operation failed");
        better_auth_core::AuthResponse::new(500).into()
    })
}

pub(super) enum BaseField {
    String,
    Boolean,
    Roles,
    CoercedString,
}

pub(super) fn validate(
    schema: &UserConfig,
    mut body: Map<String, Value>,
    base: &[(&str, BaseField, bool)],
) -> AuthResult<Map<String, Value>> {
    let mut output = Map::new();
    let mut errors = Vec::new();
    let names = base.iter().map(|(name, _, _)| *name).chain(
        schema
            .additional_fields
            .keys()
            .map(String::as_str)
            .filter(|name| !base.iter().any(|(base, _, _)| base == name)),
    );
    for name in names {
        if let Some(field) = schema
            .additional_fields
            .get(name)
            .filter(|field| field.input)
        {
            match field.validate_organization_input(body.get(name), &format!("body.{name}"), false)
            {
                Ok(Some(value)) => {
                    let _ = output.insert(name.into(), value);
                }
                Ok(None) => {}
                Err(AuthError::FieldInput { message, .. }) => errors.push(message),
                Err(error) => return Err(error),
            }
            continue;
        }
        let Some((_, kind, required)) = base.iter().find(|(base, _, _)| *base == name) else {
            continue;
        };
        if matches!(kind, BaseField::CoercedString) {
            let value = SchemaValue::<Value>::from_json(body.remove(name)).display_string()?;
            let _ = output.insert(name.into(), value.into());
            continue;
        }
        let value = body.get(name);
        if value.is_none() && !required {
            continue;
        }
        let valid = match (kind, value) {
            (BaseField::String, Some(Value::String(_)))
            | (BaseField::Boolean, Some(Value::Bool(_))) => true,
            (BaseField::Roles, Some(Value::String(_))) => true,
            (BaseField::Roles, Some(Value::Array(values))) => values.iter().all(Value::is_string),
            _ => false,
        };
        if valid {
            if let Some(value) = body.remove(name) {
                let _ = output.insert(name.into(), value);
            }
        } else {
            errors.push(match kind {
                BaseField::Roles => format!("[body.{name}] Invalid input"),
                BaseField::Boolean => {
                    json_body::invalid_type(&format!("body.{name}"), "boolean", value)
                }
                _ => json_body::invalid_type(&format!("body.{name}"), "string", value),
            });
        }
    }
    if errors.is_empty() {
        Ok(output)
    } else {
        Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: errors.join("; "),
        })
    }
}

pub(super) fn parse_roles(value: &SchemaValue<RoleInput>) -> AuthResult<SchemaValue<String>> {
    match value {
        SchemaValue::Typed(value) => Ok(value.joined().into()),
        SchemaValue::Dynamic(value @ Value::Array(_)) => {
            SchemaValue::<Value>::Dynamic(value.clone())
                .display_string()
                .map(Into::into)
        }
        SchemaValue::Dynamic(value) => Ok(SchemaValue::Dynamic(value.clone())),
        SchemaValue::Undefined => Ok(SchemaValue::Undefined),
        SchemaValue::InvalidDate => Ok(SchemaValue::InvalidDate),
    }
}

pub(super) fn invitation_team_ids(value: Option<Value>) -> SchemaValue<Vec<String>> {
    match value {
        Some(Value::String(value)) => vec![value].into(),
        None | Some(Value::Null) => Vec::new().into(),
        value => SchemaValue::from_json(value),
    }
}

fn has_team_length(value: &Value) -> AuthResult<bool> {
    match value {
        Value::Null => Err(better_auth_core::AuthResponse::new(500).into()),
        Value::Array(values) => Ok(!values.is_empty()),
        Value::String(value) => Ok(!value.is_empty()),
        Value::Object(value) => {
            let length = value.get("length");
            let positive = match length {
                Some(Value::Bool(value)) => *value,
                Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value > 0.0),
                Some(Value::String(_) | Value::Array(_)) => {
                    let length =
                        SchemaValue::<Value>::from_json(length.cloned()).display_string()?;
                    better_auth_core::organization_fields::numeric_filter(&length)
                        .is_some_and(|value| value > 0.0)
                }
                _ => false,
            };
            Ok(positive)
        }
        _ => Ok(false),
    }
}

pub(super) fn invitation_team_alias(
    teams: &SchemaValue<Vec<String>>,
) -> AuthResult<SchemaValue<String>> {
    let value = teams.json()?.ok_or_else(|| {
        better_auth_core::AuthError::from(better_auth_core::AuthResponse::new(500))
    })?;
    if !has_team_length(&value)? {
        return Ok(SchemaValue::Undefined);
    }
    Ok(SchemaValue::from_json(match value {
        Value::Array(values) => values.into_iter().next(),
        Value::Object(values) => values.get("0").cloned(),
        _ => None,
    }))
}

pub(super) fn join_invitation_teams(
    teams: &SchemaValue<Vec<String>>,
) -> AuthResult<Option<String>> {
    let value = teams.json()?.ok_or_else(|| {
        better_auth_core::AuthError::from(better_auth_core::AuthResponse::new(500))
    })?;
    if !has_team_length(&value)? {
        return Ok(None);
    }
    if !value.is_array() {
        return Err(better_auth_core::AuthResponse::new(500).into());
    }
    SchemaValue::<Value>::Dynamic(value)
        .display_string()
        .map(Some)
}
