use crate::{
    ApiErrorClass, ApiErrorInit, AuthError, AuthRequest, AuthResult, FieldMap, FieldValue,
};
use serde_json::Value;

#[derive(Clone, Debug)]
pub(crate) struct ParsedHttpBody {
    // Public raw bodies and before-request hooks can replace input after HTTP parsing.
    source: Option<Vec<u8>>,
    value: Option<Value>,
    native: FieldValue,
}

fn error(status: u16, code: &str, message: &str) -> AuthError {
    match AuthError::try_api_error(ApiErrorInit {
        class: ApiErrorClass::BetterCall,
        status: status.into(),
        body: FieldMap::from([
            ("message".into(), message.into()),
            ("code".into(), code.into()),
        ])
        .into(),
        ..Default::default()
    }) {
        Ok(error) | Err(error) => error,
    }
}

impl AuthRequest {
    /// Decode an HTTP route's body before origin and endpoint middleware.
    pub fn parse_http_body(&mut self, allowed: &[String]) -> AuthResult<()> {
        let Some(bytes) = self.body.as_deref() else {
            self.parsed_http_body = Some(ParsedHttpBody {
                source: None,
                value: None,
                native: FieldValue::Undefined,
            });
            return Ok(());
        };
        let content_type = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        let normalized = content_type.to_ascii_lowercase();
        let base = normalized.split(';').next().unwrap_or("").trim();
        if !allowed
            .iter()
            .any(|allowed| base.contains(allowed.to_ascii_lowercase().trim()))
        {
            let message = if content_type.is_empty() {
                format!(
                    "Content-Type is required. Allowed types: {}",
                    allowed.join(", ")
                )
            } else {
                format!(
                    "Content-Type \"{content_type}\" is not allowed. Allowed types: {}",
                    allowed.join(", ")
                )
            };
            return Err(error(415, "UNSUPPORTED_MEDIA_TYPE", &message));
        }
        let value = if normalized.contains("application/x-www-form-urlencoded") {
            Value::Object(
                url::form_urlencoded::parse(bytes)
                    .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
                    .collect(),
            )
        } else {
            serde_json::from_slice(bytes)
                .map_err(|_| error(400, "BAD_REQUEST", "Invalid JSON in request body"))?
        };
        self.parsed_http_body = Some(ParsedHttpBody {
            source: self.body.clone(),
            native: value.clone().into(),
            value: Some(value),
        });
        Ok(())
    }

    /// Return the HTTP parser's JSON snapshot while the raw body remains unchanged.
    /// Use `input_body` to project subsequent native input mutations.
    pub fn parsed_http_body(&self) -> Option<&Value> {
        self.parsed_http_body
            .as_ref()
            .filter(|parsed| parsed.source == self.body)
            .and_then(|parsed| parsed.value.as_ref())
    }

    pub(crate) fn parsed_http_field_value(&self) -> Option<FieldValue> {
        self.parsed_http_body
            .as_ref()
            .filter(|parsed| parsed.source == self.body)
            .map(|parsed| parsed.native.clone())
    }

    /// Whether the HTTP router has decoded this request, including an absent body.
    pub fn has_http_body_context(&self) -> bool {
        self.parsed_http_body.is_some()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
mod tests {
    use super::*;
    use crate::{FieldValue, HttpMethod};
    use serde_json::json;

    #[test]
    fn parser_errors_retain_better_call_provenance_before_http_serialization() {
        for (content_type, bytes, status, code, message) in [
            (
                None,
                b"{}".as_slice(),
                415u16,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type is required. Allowed types: application/json",
            ),
            (
                Some("text/plain"),
                b"{}".as_slice(),
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type \"text/plain\" is not allowed. Allowed types: application/json",
            ),
            (
                Some("application/json"),
                b"{".as_slice(),
                400,
                "BAD_REQUEST",
                "Invalid JSON in request body",
            ),
            (
                Some("application/json"),
                b"".as_slice(),
                400,
                "BAD_REQUEST",
                "Invalid JSON in request body",
            ),
        ] {
            let mut request = AuthRequest::new(HttpMethod::Post, "/body");
            request.body = Some(bytes.to_vec());
            if let Some(content_type) = content_type {
                request
                    .headers
                    .insert("content-type".into(), content_type.into());
            }
            let error = request
                .parse_http_body(&["application/json".into()])
                .unwrap_err();
            assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
            assert!(!error.is_api_error_instance(ApiErrorClass::BetterAuth));
            assert_eq!(error.status_value().unwrap(), FieldValue::from(status));
            assert_eq!(error.status_code().unwrap(), status);
            let body = error.body_value().unwrap();
            assert_eq!(
                body,
                FieldValue::from(json!({"message": message, "code": code}))
            );
            assert_eq!(
                body.as_object().unwrap().enumerable_keys().unwrap(),
                ["message", "code"]
            );
            assert!(
                error
                    .headers_value()
                    .unwrap()
                    .enumerable_fields()
                    .unwrap()
                    .is_empty()
            );
            let response = error
                .to_auth_response()
                .unwrap()
                .into_http_response()
                .unwrap();
            assert_eq!(response.status, status);
            assert_eq!(
                response.body.bytes().unwrap().as_ref(),
                serde_json::to_vec(&json!({"message": message, "code": code})).unwrap()
            );
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(request.body.as_deref(), Some(bytes));
            assert!(!request.has_http_body_context());
        }
    }

    #[test]
    fn decoded_form_body_retains_raw_request_and_invalidates_on_replacement() {
        let mut req = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
        let _ = req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        let raw = b"email=first&email=second%40example.com&rememberMe=false".to_vec();
        req.body = Some(raw.clone());
        req.parse_http_body(&[
            "application/x-www-form-urlencoded".into(),
            "application/json".into(),
        ])
        .unwrap();
        assert_eq!(req.body, Some(raw));
        assert_eq!(
            req.body_as_json::<Value>().unwrap(),
            json!({"email":"second@example.com","rememberMe":"false"})
        );
        req.body = Some(br#"{"email":"replacement@example.com"}"#.to_vec());
        assert_eq!(req.parsed_http_body(), None);
        assert!(req.has_http_body_context());
        assert_eq!(
            req.body_as_json::<Value>().unwrap(),
            json!({"email":"replacement@example.com"})
        );
    }
}
