use better_auth_core::endpoint_input::ValidatedBody;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthResult};
use serde_json::{Map, Value};

use super::EmailOtpType;
use crate::plugins::json_body;

#[derive(Clone)]
pub(super) struct Body(Map<String, Value>);

impl Body {
    pub(super) fn parse(req: &AuthRequest) -> Result<Self, AuthResponse> {
        req.validated_body::<Self>()
            .cloned()
            .map_or_else(|| parse(req).map_err(|error| error.to_auth_response()), Ok)
    }
    pub(super) fn value(&self) -> Value {
        Value::Object(self.0.clone())
    }
    pub(super) fn get(&self, field: &str) -> &str {
        self.optional(field).unwrap_or_default()
    }
    pub(super) fn optional(&self, field: &str) -> Option<&str> {
        self.0.get(field).and_then(Value::as_str)
    }
    pub(super) fn fields(&self) -> &Map<String, Value> {
        &self.0
    }
    pub(super) fn kind(&self) -> EmailOtpType {
        match self.get("type") {
            "sign-in" => EmailOtpType::SignIn,
            "forget-password" => EmailOtpType::ForgetPassword,
            "change-email" => EmailOtpType::ChangeEmail,
            _ => EmailOtpType::EmailVerification,
        }
    }
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let body = parse(req)?;
    Ok(ValidatedBody::new(Some(body.value()), body))
}

fn parse(req: &AuthRequest) -> AuthResult<Body> {
    let (required, optional): (&[&str], &[&str]) = match req.path() {
        "/email-otp/send-verification-otp" => (&["email", "type"], &[]),
        "/email-otp/check-verification-otp" => (&["email", "type", "otp"], &[]),
        "/email-otp/verify-email" => (&["email", "otp"], &[]),
        "/sign-in/email-otp" => (&["email", "otp"], &["name", "image"]),
        "/email-otp/request-password-reset" | "/forget-password/email-otp" => (&["email"], &[]),
        "/email-otp/reset-password" => (&["email", "otp", "password"], &[]),
        "/email-otp/request-email-change" => (&["newEmail"], &["otp"]),
        "/email-otp/change-email" => (&["newEmail", "otp"], &[]),
        _ => return Err(AuthError::internal("Unknown Email OTP body schema")),
    };
    let record = req.path() == "/sign-in/email-otp";
    let input = req.input_body()?;
    let body = input.as_ref().and_then(Value::as_object).ok_or_else(|| {
        let mut message = json_body::invalid_type("body", "object", input.as_ref());
        if record {
            message.push_str("; ");
            message.push_str(&json_body::invalid_type("body", "record", input.as_ref()));
        }
        AuthError::from(json_body::validation_error(&message))
    })?;
    let mut errors = Vec::new();
    for field in required.iter().chain(optional) {
        let value = body.get(*field);
        if *field == "type" {
            if !matches!(
                value.and_then(Value::as_str),
                Some("email-verification" | "sign-in" | "forget-password" | "change-email")
            ) {
                errors.push(r#"[body.type] Invalid option: expected one of "email-verification"|"sign-in"|"forget-password"|"change-email""#.to_owned());
            }
        } else if (required.contains(field) || value.is_some())
            && !value.is_some_and(Value::is_string)
        {
            errors.push(json_body::invalid_type(
                &format!("body.{field}"),
                "string",
                value,
            ));
        }
    }
    if !errors.is_empty() {
        return Err(json_body::validation_error(&errors.join("; ")).into());
    }
    Ok(Body(
        body.iter()
            .filter(|(key, _)| {
                key.as_str() != "__proto__"
                    && (record
                        || required.contains(&key.as_str())
                        || optional.contains(&key.as_str()))
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

pub(super) fn validate_email(email: &str) -> AuthResult<()> {
    if json_body::valid_email(email)? {
        Ok(())
    } else {
        Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        })
    }
}
