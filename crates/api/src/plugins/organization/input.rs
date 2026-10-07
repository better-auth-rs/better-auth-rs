use super::types::RoleInput;
use crate::plugins::json_body;
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, SchemaValue, user_fields::UserConfig,
};
use serde_json::{Map, Value};

pub(super) fn string_operation<'a>(
    value: &'a SchemaValue<String>,
    operation: &str,
) -> AuthResult<&'a str> {
    value.typed().map(String::as_str).map_err(|error| {
        better_auth_core::observability::logger::current().error(
            "Organization string operation failed",
            &[
                better_auth_core::observability::LogArgument::Error(&error),
                better_auth_core::observability::LogArgument::Value(&serde_json::json!(operation)),
            ],
        );
        better_auth_core::AuthResponse::new(500).into()
    })
}

pub(super) enum BaseField {
    String,
    NonemptyString,
    NullableString,
    Boolean,
    Roles,
    CoercedString,
    Record,
    Permissions,
}

pub(super) fn validate(
    schema: &UserConfig,
    body: Map<String, Value>,
    base: &[(&str, BaseField, bool)],
) -> AuthResult<FieldMap> {
    let mut errors = Vec::new();
    let output = fields(schema, &body, base, "body", false, false, &mut errors)?;
    finish(errors)?;
    Ok(output)
}

pub(super) fn finish(errors: Vec<String>) -> AuthResult<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: errors.join("; "),
        })
    }
}

pub(super) fn object<'a>(
    value: Option<&'a Value>,
    prefix: &str,
    errors: &mut Vec<String>,
) -> Option<&'a Map<String, Value>> {
    match value.and_then(Value::as_object) {
        Some(value) => Some(value),
        None => {
            errors.push(json_body::invalid_type(prefix, "object", value));
            None
        }
    }
}

/// Merge the configured schema in the same order as the route's object spread.
pub(super) fn fields(
    schema: &UserConfig,
    body: &Map<String, Value>,
    base: &[(&str, BaseField, bool)],
    prefix: &str,
    partial: bool,
    base_wins: bool,
    errors: &mut Vec<String>,
) -> AuthResult<FieldMap> {
    let mut names = indexmap::IndexSet::new();
    let configured = schema
        .fields()
        .iter()
        .filter(|(_, field)| field.input())
        .map(|(name, _)| name.as_str());
    if base_wins {
        names.extend(configured);
        names.extend(base.iter().map(|(name, _, _)| *name));
    } else {
        names.extend(base.iter().map(|(name, _, _)| *name));
        names.extend(configured);
    }
    let mut output = FieldMap::new();
    for name in names {
        let builtin = base.iter().find(|(key, _, _)| *key == name);
        let field = schema.fields().get(name).filter(|field| field.input());
        let location = format!("{prefix}.{name}");
        if let Some(field) = field.filter(|_| !base_wins || builtin.is_none()) {
            let value = body
                .get(name)
                .cloned()
                .map(FieldValue::from_json)
                .transpose()?;
            match field.validate_organization_input(value.as_ref(), &location, partial) {
                Ok(Some(value)) => {
                    let _ = output.insert(name.into(), value);
                }
                Ok(None) => {}
                Err(AuthError::FieldInput { message, .. }) => errors.push(message),
                Err(error) => return Err(error),
            }
        } else if let Some((_, kind, required)) = builtin
            && let Some(value) = field_value(
                body.get(name),
                kind,
                *required && !partial,
                &location,
                errors,
            )?
        {
            let _ = output.insert(name.into(), FieldValue::from_json(value)?);
        }
    }
    Ok(output)
}

fn field_value(
    value: Option<&Value>,
    kind: &BaseField,
    required: bool,
    location: &str,
    errors: &mut Vec<String>,
) -> AuthResult<Option<Value>> {
    if value.is_none() && !required {
        return Ok(None);
    }
    if matches!(kind, BaseField::CoercedString) {
        return Ok(Some(
            SchemaValue::<FieldValue>::from_json(value.cloned())?
                .display_string()?
                .into(),
        ));
    }
    let expected = match kind {
        BaseField::Boolean => "boolean",
        BaseField::Record | BaseField::Permissions => "record",
        _ => "string",
    };
    let valid = match kind {
        BaseField::String | BaseField::NonemptyString | BaseField::CoercedString => {
            value.is_some_and(Value::is_string)
        }
        BaseField::NullableString => {
            value.is_some_and(|value| value.is_null() || value.is_string())
        }
        BaseField::Boolean => value.is_some_and(Value::is_boolean),
        BaseField::Roles => value.is_some_and(|value| {
            value.is_string()
                || value
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_string))
        }),
        BaseField::Record | BaseField::Permissions => value.is_some_and(Value::is_object),
    };
    if !valid {
        errors.push(if matches!(kind, BaseField::Roles) {
            format!("[{location}] Invalid input")
        } else {
            json_body::invalid_type(location, expected, value)
        });
        return Ok(None);
    }
    if matches!(kind, BaseField::NonemptyString) && value.and_then(Value::as_str) == Some("") {
        errors.push(format!(
            "[{location}] Too small: expected string to have >=1 characters"
        ));
    }
    if matches!(kind, BaseField::Permissions)
        && let Some(values) = value.and_then(Value::as_object)
    {
        for (key, value) in values {
            let path = format!("{location}.{key}");
            if let Some(values) = value.as_array() {
                for (index, value) in values.iter().enumerate() {
                    if !value.is_string() {
                        errors.push(json_body::invalid_type(
                            &format!("{path}.{index}"),
                            "string",
                            Some(value),
                        ));
                    }
                }
            } else {
                errors.push(json_body::invalid_type(&path, "array", Some(value)));
            }
        }
    }
    Ok(value.cloned())
}

pub(super) fn parse_roles(value: &SchemaValue<RoleInput>) -> AuthResult<SchemaValue<String>> {
    match value {
        SchemaValue::Typed(value) => Ok(value.joined().into()),
        SchemaValue::Dynamic(value @ FieldValue::Array(_)) => {
            SchemaValue::<FieldValue>::Dynamic(value.clone())
                .display_string()
                .map(Into::into)
        }
        SchemaValue::Dynamic(value) => Ok(SchemaValue::Dynamic(value.clone())),
        SchemaValue::Undefined => Ok(SchemaValue::Undefined),
    }
}

pub(super) fn invitation_team_ids(value: FieldValue) -> SchemaValue<Vec<String>> {
    match value {
        FieldValue::String(value) => vec![value].into(),
        FieldValue::Undefined | FieldValue::Null => Vec::new().into(),
        value => SchemaValue::from_field(value),
    }
}

fn has_team_length(value: &FieldValue) -> AuthResult<bool> {
    match value {
        FieldValue::Undefined | FieldValue::Null => {
            Err(better_auth_core::AuthResponse::new(500).into())
        }
        FieldValue::Array(values) => Ok(!values.is_empty()),
        FieldValue::String(value) => Ok(!value.is_empty()),
        FieldValue::Utf16String(value) => Ok(!value.as_utf16().is_empty()),
        FieldValue::Object(value) => better_auth_core::query::field_number(
            value.get("length").unwrap_or(&FieldValue::Undefined),
        )
        .map(|length| length > 0.0),
        _ => Ok(false),
    }
}

pub(super) fn invitation_team_alias(
    teams: &SchemaValue<Vec<String>>,
) -> AuthResult<SchemaValue<String>> {
    let value = teams.field_value();
    if !has_team_length(&value)? {
        return Ok(SchemaValue::Undefined);
    }
    Ok(SchemaValue::from_field(match value {
        FieldValue::Array(values) => values.first().cloned().unwrap_or_default(),
        FieldValue::Object(values) => values.get("0").cloned().unwrap_or_default(),
        _ => FieldValue::Undefined,
    }))
}

pub(super) fn join_invitation_teams(
    teams: &SchemaValue<Vec<String>>,
) -> AuthResult<Option<String>> {
    let value = teams.field_value();
    if !has_team_length(&value)? {
        return Ok(None);
    }
    if !value.is_array() {
        return Err(better_auth_core::AuthResponse::new(500).into());
    }
    SchemaValue::<FieldValue>::Dynamic(value)
        .display_string()
        .map(Some)
}
