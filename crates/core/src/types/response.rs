use super::*;

impl AuthResponse {
    /// Whether the returned value represents an API error rather than an ordinary response.
    pub fn is_api_error(&self) -> bool {
        self.api_error
    }

    pub(crate) fn into_api_error(mut self) -> Self {
        if let Some(mut owned) = self.explicit_response_headers.take() {
            if self.error_headers.is_none() {
                self.error_headers = Some(owned.clone());
            }
            owned.merge(std::mem::take(&mut self.headers));
            self.headers = owned;
        }
        self.api_error = true;
        if self.error_headers.is_none() {
            self.error_headers = Some(self.headers.clone());
        }
        self
    }

    /// Explicit headers supplied by the API error before dispatch merged response headers.
    pub fn api_error_headers(&self) -> Option<&Headers> {
        self.error_headers.as_ref()
    }

    /// Endpoint headers captured on a thrown native API error.
    pub fn captured_headers(&self) -> Option<&Headers> {
        self.captured_headers.as_ref()
    }

    /// Read the headers owned by an explicit native response, separate from endpoint headers.
    pub fn explicit_response_headers(&self) -> Option<&Headers> {
        self.explicit_response_headers.as_ref()
    }

    fn separate_explicit_response_headers(&mut self) {
        if !self.json_response && !self.api_error && self.explicit_response_headers.is_none() {
            self.explicit_response_headers = Some(std::mem::take(&mut self.headers));
        }
    }

    pub(crate) fn initialize_endpoint_headers(&mut self, mut headers: Headers) {
        self.separate_explicit_response_headers();
        headers.merge(std::mem::take(&mut self.headers));
        self.headers = headers;
    }

    pub(crate) fn merge_endpoint_headers(&mut self, headers: Headers) {
        self.separate_explicit_response_headers();
        self.headers.merge(headers);
    }

    /// Attach the endpoint header accumulator without changing the error's HTTP headers.
    pub fn capture_error_headers(&mut self, headers: Headers) {
        self.captured_headers = Some(headers);
    }

    /// Replace the returned JSON value while preserving response status and accumulated headers.
    pub fn replace_json<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), serde_json::Error> {
        self.body = crate::ResponseBody::Bytes(serde_json::to_vec(value)?);
        self.json_response = true;
        self.api_error = false;
        self.error_headers = None;
        self.captured_headers = None;
        self.explicit_response_headers = None;
        Ok(())
    }

    /// Replace the endpoint's returned value while retaining accumulated response headers.
    pub fn replace_returned(&mut self, mut returned: Self) {
        returned.separate_explicit_response_headers();
        let mut headers = std::mem::take(&mut self.headers);
        headers.merge(std::mem::take(&mut returned.headers));
        returned.headers = headers;
        *self = returned;
    }

    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: crate::ResponseBody::Bytes(Vec::new()),
            json_response: false,
            api_error: false,
            error_headers: None,
            captured_headers: None,
            explicit_response_headers: None,
        }
    }

    /// Retain runtime fields until an HTTP consumer requests bytes.
    pub fn native(status: u16, value: crate::FieldValue) -> Self {
        let mut response = Self::new(status);
        response.body = crate::ResponseBody::Native(value);
        response.json_response = true;
        response
    }

    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        let body = crate::ResponseBody::Bytes(serde_json::to_vec(data)?);

        Ok(Self {
            status,
            headers: Headers::new(),
            body,
            json_response: true,
            api_error: false,
            error_headers: None,
            captured_headers: None,
            explicit_response_headers: None,
        })
    }

    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = crate::ResponseBody::Bytes(text.into().into_bytes());
        let mut headers = Headers::new();
        _ = headers.insert("content-type".to_string(), "text/plain".to_string());

        Self {
            status,
            headers,
            body,
            json_response: false,
            api_error: false,
            error_headers: None,
            captured_headers: None,
            explicit_response_headers: None,
        }
    }

    pub fn html(status: u16, html: impl Into<String>) -> Self {
        let body = crate::ResponseBody::Bytes(html.into().into_bytes());
        let mut headers = Headers::new();
        _ = headers.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );

        Self {
            status,
            headers,
            body,
            json_response: false,
            api_error: false,
            error_headers: None,
            captured_headers: None,
            explicit_response_headers: None,
        }
    }

    /// Materialize HTTP headers after endpoint hooks finish.
    /// Native results keep endpoint headers separate from explicit response headers.
    pub fn into_http_response(mut self) -> Self {
        if self.json_response {
            // Better-call strips request and transport headers from native endpoint output before HTTP serialization.
            self.headers.strip_request_only();
            let _ = self.headers.insert("content-type", "application/json");
            self.json_response = false;
        } else if let Some(mut owned) = self.explicit_response_headers.take() {
            self.headers.strip_request_only();
            owned.merge(std::mem::take(&mut self.headers));
            self.headers = owned;
        }
        self
    }

    /// Identify JSON output before or after HTTP headers are generated.
    pub fn is_json(&self) -> bool {
        self.json_response
            || self
                .headers
                .get("content-type")
                .or_else(|| self.explicit_response_headers.as_ref()?.get("content-type"))
                .is_some_and(|value| value.starts_with("application/json"))
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        _ = self
            .explicit_response_headers
            .as_mut()
            .unwrap_or(&mut self.headers)
            .insert(name.into(), value.into());
        self
    }

    pub fn with_appended_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.explicit_response_headers
            .as_mut()
            .unwrap_or(&mut self.headers)
            .append(name.into(), value.into());
        self
    }
}
