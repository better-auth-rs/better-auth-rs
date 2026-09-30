use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthResult};
use serde_json::{Map, Value};

use super::EmailOtpType;
use crate::plugins::json_body;

pub(super) struct Body(Map<String, Value>);

impl Body {
    pub(super) fn parse(
        req: &AuthRequest,
        required: &[&str],
        optional: &[&str],
    ) -> Result<Self, AuthResponse> {
        let body = json_body::parse(req)?;
        let Some(Value::Object(body)) = body.as_ref() else {
            return Err(json_body::validation_error(&json_body::invalid_type(
                "body",
                "object",
                body.as_ref(),
            )));
        };
        let mut errors = Vec::new();
        for field in required.iter().chain(optional) {
            let value = body.get(*field);
            if *field == "type" {
                if !matches!(
                    value.and_then(Value::as_str),
                    Some("email-verification" | "sign-in" | "forget-password" | "change-email")
                ) {
                    errors.push("[body.type] Invalid option: expected one of \"email-verification\"|\"sign-in\"|\"forget-password\"|\"change-email\"".to_owned());
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
            return Err(json_body::validation_error(&errors.join("; ")));
        }
        Ok(Self(body.clone()))
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

pub(super) fn validate_email(email: &str) -> AuthResult<()> {
    let valid = email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && !local.starts_with('.')
            && !local.contains("..")
            && local
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || b"_'+-.".contains(&ch))
            && local
                .bytes()
                .last()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || b"_+-".contains(&ch))
            && domain.rsplit_once('.').is_some_and(|(_, tld)| {
                tld.len() >= 2 && tld.bytes().all(|ch| ch.is_ascii_alphabetic())
            })
            && domain.split('.').all(|label| {
                label
                    .bytes()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric())
                    && label
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
            })
    });
    if valid {
        Ok(())
    } else {
        Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        })
    }
}
