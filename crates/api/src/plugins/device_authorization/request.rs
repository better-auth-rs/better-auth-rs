use super::{
    DEVICE_GRANT_TYPE, DeviceFieldValidation, DeviceRequestFields, DeviceRequestIssue,
    types::{DeviceActionRequest, DeviceCodeRequest, DeviceTokenRequest},
};
use crate::plugins::json_body;
use better_auth_core::{AuthError, AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

fn fields(
    body: Option<&Value>,
    names: &[(&str, bool)],
    token: bool,
) -> (Map<String, Value>, Vec<DeviceRequestIssue>) {
    let mut issues = Vec::new();
    let mut output = Map::new();
    if let Some(object) = body.and_then(Value::as_object) {
        for &(name, required) in names {
            let value = object.get(name);
            if token
                && name == "grant_type"
                && value.and_then(Value::as_str) != Some(DEVICE_GRANT_TYPE)
            {
                issues.push(DeviceRequestIssue {
                    message: format!("Invalid input: expected \"{DEVICE_GRANT_TYPE}\""),
                    path: vec![Value::String(name.to_owned())],
                    details: Map::new(),
                });
            } else {
                match value {
                    Some(value @ Value::String(_)) => {
                        let _ = output.insert(name.to_owned(), value.clone());
                    }
                    None if !required => {}
                    value => issues.push(DeviceRequestIssue::invalid_type(
                        Some(name),
                        "string",
                        value,
                    )),
                }
            }
        }
    } else {
        issues.push(DeviceRequestIssue::invalid_type(None, "object", body));
    }
    (output, issues)
}

fn finish<T: DeserializeOwned + Serialize + Send + Sync + 'static>(
    output: Map<String, Value>,
    issues: Option<Vec<DeviceRequestIssue>>,
    code: bool,
) -> AuthResult<ValidatedBody> {
    if let Some(issues) = issues {
        let message = issues
            .iter()
            .map(DeviceRequestIssue::message)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(if code {
            super::device_error_response(400, "invalid_request", &message)?.into()
        } else {
            json_body::validation_error(&message).into()
        });
    }
    let projection = Value::Object(output);
    let typed: T = serde_json::from_value(projection.clone())?;
    Ok(ValidatedBody::new(Some(projection), typed))
}

fn parse<T: DeserializeOwned + Serialize + Send + Sync + 'static>(
    req: &AuthRequest,
    names: &[(&str, bool)],
    code: bool,
    token: bool,
) -> AuthResult<ValidatedBody> {
    let body = req.input_body()?;
    let (output, issues) = fields(body.as_ref(), names, token);
    finish::<T>(output, (!issues.is_empty()).then_some(issues), code)
}

pub(super) async fn code_with_fields(
    req: &AuthRequest,
    schema: &DeviceRequestFields,
) -> AuthResult<ValidatedBody> {
    let body = req.input_body()?;
    let (mut output, issues) = fields(
        body.as_ref(),
        &[("client_id", true), ("user_id", false), ("scope", false)],
        false,
    );
    let mut issues = (!issues.is_empty()).then_some(issues);
    if let Some(object) = body.as_ref().and_then(Value::as_object) {
        for (name, validator) in &schema.fields {
            match validator.validate(object.get(name).cloned()).await? {
                DeviceFieldValidation::Value(Some(value)) => {
                    let _ = output.insert(name.clone(), value);
                }
                DeviceFieldValidation::Value(None) => {}
                DeviceFieldValidation::Issues(mut field_issues) => {
                    for issue in &mut field_issues {
                        issue.path.insert(0, Value::String(name.clone()));
                    }
                    issues.get_or_insert_with(Vec::new).extend(field_issues);
                }
            }
        }
    }
    if let Some(issues) = &issues {
        schema.report(issues)?;
    }
    finish::<DeviceCodeRequest>(output, issues, true)
}

pub(super) async fn read_code(
    req: &AuthRequest,
    schema: Option<&DeviceRequestFields>,
) -> AuthResult<DeviceCodeRequest> {
    if let Some(body) = req.validated_body::<DeviceCodeRequest>() {
        return Ok(body.clone());
    }
    let validated = match schema {
        Some(schema) => code_with_fields(req, schema).await?,
        None => code(req)?,
    };
    validated
        .get::<DeviceCodeRequest>()
        .cloned()
        .ok_or_else(|| AuthError::internal("Device validator returned a different body type"))
}

pub(super) fn code(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    parse::<DeviceCodeRequest>(
        req,
        &[("client_id", true), ("user_id", false), ("scope", false)],
        true,
        false,
    )
}
pub(super) fn token(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    parse::<DeviceTokenRequest>(
        req,
        &[
            ("grant_type", true),
            ("device_code", true),
            ("client_id", true),
        ],
        false,
        true,
    )
}
pub(super) fn action(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    parse::<DeviceActionRequest>(req, &[("userCode", true)], false, false)
}
pub(super) fn read<T: Clone + Send + Sync + 'static>(
    req: &AuthRequest,
    validator: fn(&AuthRequest) -> AuthResult<ValidatedBody>,
) -> AuthResult<T> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok(body.clone());
    }
    validator(req)?
        .get::<T>()
        .cloned()
        .ok_or_else(|| AuthError::internal("Device validator returned a different body type"))
}

pub(super) fn normalize_code(
    req: &AuthRequest,
    mut body: DeviceCodeRequest,
) -> AuthResult<DeviceCodeRequest> {
    let original = req.original_request().unwrap_or(req);
    if original.headers.get("content-type").is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    }) {
        let parameters: Vec<_> =
            url::form_urlencoded::parse(original.body.as_deref().unwrap_or_default()).collect();
        for field in ["client_id", "user_id", "scope"] {
            let mut values = parameters
                .iter()
                .filter(|(name, value)| name == field && !value.is_empty())
                .map(|(_, value)| value.to_string());
            let value = values.next();
            if values.next().is_some() {
                return Err(super::device_error_response(
                    400,
                    "invalid_request",
                    &format!("{field} must not be repeated"),
                )?
                .into());
            }
            match field {
                "client_id" => body.client_id = value.unwrap_or_default(),
                "user_id" => body.user_id = value,
                "scope" => body.scope = value,
                _ => {}
            }
        }
    }
    body.user_id = body.user_id.filter(|value| !value.is_empty());
    body.scope = body.scope.filter(|value| !value.is_empty());
    let mut projection = serde_json::to_value(&body)?;
    if body.client_id.is_empty()
        && let Some(object) = projection.as_object_mut()
    {
        let _ = object.remove("client_id");
    }
    let mut normalized = req.clone();
    normalized.set_endpoint_body(ValidatedBody::new(Some(projection), body.clone()));
    better_auth_core::hooks::update_request_hook_context(&normalized)?;
    if body.client_id.is_empty() {
        return Err(
            super::device_error_response(400, "invalid_request", "client_id is required")?.into(),
        );
    }
    Ok(body)
}
