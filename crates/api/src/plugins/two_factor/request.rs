use super::*;
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::endpoint_input::ValidatedBody;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub(super) fn read<T: Clone + Send + Sync + 'static>(
    req: &AuthRequest,
    password_optional: bool,
) -> AuthResult<T> {
    if let Some(value) = req.validated_body::<T>() {
        return Ok(value.clone());
    }
    validate(req, password_optional)?
        .get::<T>()
        .cloned()
        .ok_or_else(|| {
            AuthError::internal("Two Factor body validator returned a different input type")
        })
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

pub(super) fn validate(req: &AuthRequest, password_optional: bool) -> AuthResult<ValidatedBody> {
    let input = req.input_body()?;
    if req.path() == "/two-factor/send-otp" && input.is_none() {
        return Ok(ValidatedBody::new(None, Value::Null));
    }
    let body = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        AuthError::from(validation_error(&invalid_type(
            "body",
            "object",
            input.as_ref(),
        )))
    })?;
    let fields: &[(&str, &str, bool)] = match req.path() {
        "/two-factor/enable" => &[
            ("password", "string", !password_optional),
            ("method", "method", false),
            ("issuer", "string", false),
        ],
        "/two-factor/disable"
        | "/two-factor/get-totp-uri"
        | "/two-factor/generate-backup-codes" => &[("password", "string", !password_optional)],
        "/two-factor/verify-totp" | "/two-factor/verify-otp" => {
            &[("code", "string", true), ("trustDevice", "boolean", false)]
        }
        "/two-factor/verify-backup-code" => &[
            ("code", "string", true),
            ("disableSession", "boolean", false),
            ("trustDevice", "boolean", false),
        ],
        "/two-factor/send-otp" => &[("trustDevice", "boolean", false)],
        "generateTOTP" => &[("secret", "string", true)],
        "viewBackupCodes" => &[("userId", "id", true)],
        _ => return Err(AuthError::internal("Unknown Two Factor body schema")),
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for &(name, kind, required) in fields {
        let value = body.get(name);
        if value.is_none() && !required {
            if kind == "method" {
                let _ = output.insert(name.into(), Value::String("totp".into()));
            }
            continue;
        }
        let valid = match kind {
            "id" => value.is_some(),
            "string" => value.is_some_and(Value::is_string),
            "boolean" => value.is_some_and(Value::is_boolean),
            "method" => matches!(value.and_then(Value::as_str), Some("otp" | "totp")),
            _ => false,
        };
        if valid {
            if let Some(value) = value {
                let value = if kind == "id" {
                    better_auth_core::SchemaValue::<better_auth_core::FieldValue>::from_json(Some(
                        value.clone(),
                    ))?
                    .display_string()?
                    .into()
                } else {
                    value.clone()
                };
                let _ = output.insert(name.into(), value);
            }
        } else {
            errors.push(if kind == "method" {
                "[body.method] Invalid option: expected one of \"otp\"|\"totp\"".into()
            } else {
                invalid_type(
                    &format!("body.{name}"),
                    if kind == "id" { "nonoptional" } else { kind },
                    value,
                )
            });
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    match req.path() {
        "/two-factor/enable" => typed::<EnableRequest>(output),
        "/two-factor/disable" => typed::<DisableRequest>(output),
        "/two-factor/get-totp-uri" => typed::<GetTotpUriRequest>(output),
        "/two-factor/verify-totp" => typed::<VerifyTotpRequest>(output),
        "/two-factor/verify-otp" => typed::<VerifyOtpRequest>(output),
        "/two-factor/generate-backup-codes" => typed::<GenerateBackupCodesRequest>(output),
        "/two-factor/verify-backup-code" => typed::<VerifyBackupCodeRequest>(output),
        "generateTOTP" => typed::<GenerateTotpRequest>(output),
        "viewBackupCodes" => typed::<ViewBackupCodesRequest>(output),
        _ => typed::<Value>(output),
    }
}

#[derive(Clone, Deserialize)]
pub(super) struct GenerateTotpRequest {
    pub secret: String,
}
#[derive(Clone, Deserialize)]
pub(super) struct ViewBackupCodesRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
}

pub(super) fn validate_native(request: &AuthRequest, operation: &str) -> AuthResult<ValidatedBody> {
    let mut input = request.clone();
    input.path = operation.into();
    validate(&input, false)
}
