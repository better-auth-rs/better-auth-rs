use crate::{AuthError, AuthRequest, AuthResponse, AuthResult};
use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub(crate) struct ParsedHttpBody {
    // Public raw bodies and before-request hooks can replace input after HTTP parsing.
    source: Option<Vec<u8>>,
    value: Option<Value>,
}

fn error(status: u16, code: &str, message: &str) -> AuthError {
    AuthResponse::text(status, json!({"message":message,"code":code}).to_string())
        .with_header("content-type", "application/json")
        .into()
}

impl AuthRequest {
    /// Decode an HTTP route's body before origin and endpoint middleware.
    pub fn parse_http_body(&mut self, allowed: &[String]) -> AuthResult<()> {
        let Some(bytes) = self.body.as_deref() else {
            self.parsed_http_body = Some(ParsedHttpBody {
                source: None,
                value: None,
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
            value: Some(value),
        });
        Ok(())
    }

    /// Return HTTP-decoded input when no subsequent hook has replaced the raw body.
    pub fn parsed_http_body(&self) -> Option<&Value> {
        self.parsed_http_body
            .as_ref()
            .filter(|parsed| parsed.source == self.body)
            .and_then(|parsed| parsed.value.as_ref())
    }

    /// Whether the HTTP router has decoded this request, including an absent body.
    pub fn has_http_body_context(&self) -> bool {
        self.parsed_http_body.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpMethod;

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
