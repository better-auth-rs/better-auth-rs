use super::{AuthRequest, Headers, native_headers};
use crate::{AuthError, AuthResult, FieldValue};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(super) struct ResponseHeaders {
    headers: Arc<Mutex<Headers>>,
    value: FieldValue,
}

impl Default for ResponseHeaders {
    fn default() -> Self {
        let headers = Arc::new(Mutex::new(Headers::new()));
        let value = native_headers::value(headers.clone());
        Self { headers, value }
    }
}

impl AuthRequest {
    fn with_response_headers<T>(&self, apply: impl FnOnce(&mut Headers) -> T) -> AuthResult<T> {
        let binding = self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?;
        let mut headers = native_headers::lock(&binding.headers)?;
        Ok(apply(&mut headers))
    }

    fn take_response_header_binding(&self) -> AuthResult<ResponseHeaders> {
        let mut binding = self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?;
        // Retained native handles own the old collection after the request starts a new accumulator.
        Ok(std::mem::take(&mut *binding))
    }

    /// Queue a response header from request-scoped authentication middleware.
    pub fn set_response_header(&self, name: &str, value: impl Into<String>) -> AuthResult<()> {
        let value = value.into();
        self.with_response_headers(|headers| {
            let _ = headers.insert(name, value);
        })
    }

    /// Append a response header without replacing earlier values.
    pub fn append_response_header(&self, name: &str, value: String) -> AuthResult<()> {
        self.with_response_headers(|headers| headers.append(name, value))
    }

    pub(crate) fn has_response_cookie(&self, name: &str) -> AuthResult<bool> {
        self.with_response_headers(|headers| headers.has_set_cookie(name))
    }

    pub(crate) fn remove_response_cookie(&self, name: &str) -> AuthResult<()> {
        self.with_response_headers(|headers| headers.remove_set_cookie(name))
    }

    /// Borrow the current response header collection as a stable native Headers object.
    /// Cloned handles observe header mutations until the request starts a new accumulator.
    /// Header entries are not enumerable properties. Use `Headers::from_field_value` to read them.
    pub fn response_headers_value(&self) -> AuthResult<FieldValue> {
        Ok(self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?
            .value
            .clone())
    }

    /// Construct an endpoint redirect with the current response header identity.
    pub fn redirect(&self, location: impl Into<String>) -> AuthResult<AuthError> {
        self.set_response_header("location", location)?;
        AuthError::try_api_error(crate::ApiErrorInit {
            status: "FOUND".into(),
            headers: self.response_headers_value()?,
            class: crate::ApiErrorClass::BetterCall,
            ..Default::default()
        })
    }

    /// Take the current response headers without draining retained native handles.
    pub fn take_response_headers(&self) -> AuthResult<Headers> {
        let binding = self.take_response_header_binding()?;
        let headers = native_headers::lock(&binding.headers)?.clone();
        Ok(headers)
    }

    #[doc(hidden)]
    pub fn take_response_headers_value(&self) -> AuthResult<FieldValue> {
        Ok(self.take_response_header_binding()?.value)
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;

    #[test]
    fn redirect_retains_endpoint_header_identity_and_constructor_class() -> AuthResult<()> {
        let request = AuthRequest::new(crate::HttpMethod::Get, "/callback/provider");
        request.append_response_header("set-cookie", "state=; Max-Age=0".into())?;
        let headers = request.response_headers_value()?;
        let error = request.redirect("/welcome")?;
        assert!(error.headers_value()?.strict_equals(&headers));
        assert!(matches!(headers, FieldValue::Object(_)));
        assert!(headers.enumerable_fields()?.is_empty());
        assert_eq!(headers.json()?, Some(serde_json::json!({})));
        assert!(error.is_api_error_instance(crate::ApiErrorClass::BetterCall));
        assert!(!error.is_api_error_instance(crate::ApiErrorClass::BetterAuth));
        request.append_response_header("set-cookie", "after=1".into())?;
        let captured = request.take_response_headers()?;
        assert_eq!(
            Headers::from_field_value(&error.headers_value()?)?,
            captured
        );
        assert_eq!(captured.get_all("set-cookie").count(), 2);
        assert_eq!(
            captured.get("location").map(String::as_str),
            Some("/welcome")
        );
        let next = request.response_headers_value()?;
        assert!(!next.strict_equals(&headers));
        request.set_response_header("location", "/next")?;
        assert_eq!(
            Headers::from_field_value(&next)?
                .get("location")
                .map(String::as_str),
            Some("/next")
        );
        assert_eq!(Headers::from_field_value(&headers)?, captured);
        Ok(())
    }

    #[test]
    fn native_headers_properties_do_not_replace_the_header_collection() -> AuthResult<()> {
        let mut headers = Headers::new();
        headers.append("set-cookie", "first=1");
        headers.append("set-cookie", "second=2");
        let _ = headers.insert("location", "/original");
        let value: FieldValue = headers.clone().into();
        let object = value
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected a native Headers object"))?;
        let marker: FieldValue = crate::FieldMap::from([("kept".into(), true.into())]).into();
        object.set("location", marker.clone())?;
        assert!(value.model_property("location")?.strict_equals(&marker));
        assert_eq!(object.enumerable_keys()?, ["location"]);
        assert_eq!(
            value.json()?,
            Some(serde_json::json!({"location": {"kept": true}}))
        );
        assert_eq!(Headers::from_field_value(&value)?, headers);
        let _ = object.delete("location")?;
        assert_eq!(value.json()?, Some(serde_json::json!({})));
        assert_eq!(Headers::from_field_value(&value)?, headers);
        Ok(())
    }

    #[test]
    fn native_headers_keep_validation_at_the_existing_conversion_boundary() -> AuthResult<()> {
        let request = AuthRequest::new(crate::HttpMethod::Get, "/headers");
        request.set_response_header("x-invalid", "value\ntrailer")?;
        let value = request.response_headers_value()?;
        assert_eq!(value.json()?, Some(serde_json::json!({})));
        let error = Headers::from_field_value(&value)
            .err()
            .ok_or_else(|| AuthError::internal("HeadersInit must reject an invalid header"))?;
        assert!(matches!(error, AuthError::TypeError(ref message)
            if message == "Header 'x-invalid' has invalid value: 'value\ntrailer'"));
        let captured = request.take_response_headers()?;
        assert_eq!(
            captured.get("x-invalid").map(String::as_str),
            Some("value\ntrailer")
        );
        Ok(())
    }
}
