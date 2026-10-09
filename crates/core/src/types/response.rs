use super::*;

impl AuthResponse {
    fn metadata_mut(&mut self) -> &mut ResponseMetadata {
        self.metadata.get_or_insert_default()
    }

    fn take_explicit_response_headers(&mut self) -> Option<Headers> {
        self.metadata.as_mut()?.explicit_response_headers.take()
    }

    fn returned_headers_mut(&mut self) -> &mut Headers {
        self.metadata
            .as_mut()
            .and_then(|metadata| metadata.explicit_response_headers.as_mut())
            .unwrap_or(&mut self.headers)
    }

    /// Native `returnStatus` provenance, independent of the effective HTTP status.
    pub fn native_status(&self) -> NativeResponseStatus {
        self.native_status
    }

    /// Status owned by the returned API error, before an endpoint status overrides HTTP output.
    pub fn api_error_status(&self) -> Option<u16> {
        self.api_error_status
    }

    pub(crate) fn set_native_status(&mut self, status: NativeResponseStatus) {
        self.native_status = status;
        if let Some(error_status) = self.api_error_status {
            self.status = status.value().unwrap_or(error_status);
        } else if self.native_output {
            self.status = status.value().unwrap_or(200);
        }
    }

    /// Whether the returned value represents an API error rather than an ordinary response.
    pub fn is_api_error(&self) -> bool {
        self.api_error_status.is_some()
    }

    pub(crate) fn into_api_error(mut self) -> Self {
        if self.api_error_status.is_none() {
            self.api_error_status = Some(self.status);
            self.native_status = NativeResponseStatus::Undefined;
        }
        if let Some(mut owned) = self.take_explicit_response_headers() {
            if self.api_error_headers().is_none() {
                self.metadata_mut().error_headers = Some(owned.clone());
            }
            owned.merge(std::mem::take(&mut self.headers));
            self.headers = owned;
        }
        if self.api_error_headers().is_none() {
            let headers = self.headers.clone();
            self.metadata_mut().error_headers = Some(headers);
        }
        self
    }

    /// Explicit headers supplied by the API error before dispatch merged response headers.
    pub fn api_error_headers(&self) -> Option<&Headers> {
        self.metadata.as_ref()?.error_headers.as_ref()
    }

    /// Endpoint headers captured on a thrown native API error.
    pub fn captured_headers(&self) -> Option<&Headers> {
        self.metadata.as_ref()?.captured_headers.as_ref()
    }

    /// Read the headers owned by an explicit native response, separate from endpoint headers.
    pub fn explicit_response_headers(&self) -> Option<&Headers> {
        self.metadata.as_ref()?.explicit_response_headers.as_ref()
    }

    fn separate_explicit_response_headers(&mut self) {
        if !self.native_output && !self.is_api_error() && self.explicit_response_headers().is_none()
        {
            let headers = std::mem::take(&mut self.headers);
            self.metadata_mut().explicit_response_headers = Some(headers);
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
        self.metadata_mut().captured_headers = Some(headers);
    }

    /// Replace the returned JSON value while preserving native endpoint status and accumulated headers.
    pub fn replace_json<T: Serialize + ?Sized>(&mut self, value: &T) -> crate::AuthResult<()> {
        self.body = crate::ResponseBody::Native(crate::FieldValue::parse_json(
            &serde_json::to_string(value)?,
        )?);
        self.native_output = true;
        self.api_error_status = None;
        self.metadata = None;
        self.set_native_status(self.native_status);
        Ok(())
    }

    /// Replace the returned value while retaining native endpoint status and accumulated response headers.
    pub fn replace_returned(&mut self, mut returned: Self) {
        if returned.native_output
            && !returned.is_api_error()
            && matches!(
                returned.body,
                crate::ResponseBody::Native(crate::FieldValue::Undefined)
            )
        {
            self.headers.merge(returned.headers);
            return;
        }
        returned.set_native_status(self.native_status);
        returned.separate_explicit_response_headers();
        let mut headers = std::mem::take(&mut self.headers);
        headers.merge(std::mem::take(&mut returned.headers));
        returned.headers = headers;
        *self = returned;
    }

    pub(crate) fn stops_before_hooks(&self) -> bool {
        self.is_api_error()
            || !self.native_output
            || !matches!(&self.body,
                crate::ResponseBody::Native(value)
                    if !matches!(value, crate::FieldValue::Array(_) | crate::FieldValue::Object(_) | crate::FieldValue::Date(_))
            )
    }

    /// Construct an explicit HTTP response. Its own status does not set native endpoint status.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: crate::ResponseBody::Empty,
            native_output: false,
            metadata: None,
            native_status: NativeResponseStatus::Undefined,
            api_error_status: None,
        }
    }

    /// Retain runtime fields until an HTTP consumer requests bytes.
    /// Pass `None` for an unset endpoint status, or a status code to set it explicitly.
    /// The active endpoint's `set_response_status` call takes precedence over this constructor's status.
    pub fn native(status: impl Into<Option<u16>>, value: crate::FieldValue) -> Self {
        let status = status.into();
        let mut response = Self::new(status.unwrap_or(200));
        response.body = crate::ResponseBody::Native(value);
        response.native_output = true;
        response.native_status =
            status.map_or(NativeResponseStatus::Undefined, NativeResponseStatus::Value);
        response
    }

    /// Return native binary data. Clones retain the supplied buffer until HTTP materialization.
    pub fn binary(status: impl Into<Option<u16>>, bytes: impl Into<std::sync::Arc<[u8]>>) -> Self {
        let mut response = Self::native(status, crate::FieldValue::Undefined);
        response.body = crate::ResponseBody::Binary(bytes.into());
        response
    }

    /// Return a native Blob, including its MIME type and object identity.
    pub fn blob(
        status: impl Into<Option<u16>>,
        blob: impl Into<std::sync::Arc<crate::ResponseBlob>>,
    ) -> Self {
        let mut response = Self::native(status, crate::FieldValue::Undefined);
        response.body = crate::ResponseBody::Blob(blob.into());
        response
    }

    /// Construct a native result from a Serde value; HTTP encoding depends on the resulting value type.
    /// `None` preserves an unset native status; a code sets it explicitly.
    /// The active endpoint's `set_response_status` call takes precedence over this constructor's status.
    pub fn json<T: Serialize>(status: impl Into<Option<u16>>, data: &T) -> crate::AuthResult<Self> {
        Ok(Self::native(
            status,
            crate::FieldValue::parse_json(&serde_json::to_string(data)?)?,
        ))
    }

    /// Construct an explicit text response with its own HTTP status.
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = crate::ResponseBody::Bytes(text.into().into_bytes());
        let mut headers = Headers::new();
        _ = headers.insert("content-type".to_string(), "text/plain".to_string());

        Self {
            status,
            headers,
            body,
            native_output: false,
            metadata: None,
            native_status: NativeResponseStatus::Undefined,
            api_error_status: None,
        }
    }

    /// Construct an explicit HTML response with its own HTTP status.
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
            native_output: false,
            metadata: None,
            native_status: NativeResponseStatus::Undefined,
            api_error_status: None,
        }
    }

    /// Materialize HTTP bytes and headers after endpoint hooks finish.
    /// Native results keep endpoint headers separate from explicit response headers.
    pub fn into_http_response(mut self) -> crate::AuthResult<Self> {
        if !(200..=599).contains(&self.status) {
            return Err(crate::AuthError::type_error(
                "Response status must be between 200 and 599",
            ));
        }
        if self.native_output && matches!(self.body, crate::ResponseBody::Bytes(_)) {
            self.body = crate::ResponseBody::Native(self.body.field_value()?);
        }
        if matches!(self.status, 204 | 205 | 304) && !self.body.is_null_body() {
            return Err(crate::AuthError::type_error(
                "Response status does not permit a body",
            ));
        }
        if self.native_output {
            // Better-call strips request and transport headers from native endpoint output before HTTP serialization.
            self.headers.strip_request_only();
            let _ = self
                .headers
                .insert("content-type", self.body.http_content_type());
            self.native_output = false;
        } else if let Some(mut owned) = self.take_explicit_response_headers() {
            self.headers.strip_request_only();
            owned.merge(std::mem::take(&mut self.headers));
            self.headers = owned;
        }
        self.body = if self.body.is_null_body() {
            crate::ResponseBody::Empty
        } else {
            crate::ResponseBody::Bytes(self.body.into_bytes()?)
        };
        Ok(self)
    }

    /// Whether this response retains a native endpoint value instead of an explicit HTTP Response.
    pub fn is_native(&self) -> bool {
        self.native_output
    }

    /// Identify JSON by the effective HTTP MIME type, without parsing or projecting the body.
    /// A Blob with a JSON MIME type still requires byte decoding; its native value is a Blob.
    pub fn is_json(&self) -> bool {
        if self.native_output {
            self.body
                .http_content_type()
                .starts_with("application/json")
        } else {
            self.headers
                .get("content-type")
                .or_else(|| self.explicit_response_headers()?.get("content-type"))
                .is_some_and(|value| value.starts_with("application/json"))
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        _ = self
            .returned_headers_mut()
            .insert(name.into(), value.into());
        self
    }

    pub fn with_appended_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.returned_headers_mut()
            .append(name.into(), value.into());
        self
    }
}
