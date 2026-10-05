//! Endpoint input projection, separate from the original transport request.

use crate::{AuthRequest, AuthResult, RuntimeExtensions};
use serde_json::Value;

mod body_validator;
pub use body_validator::BodyValidator;

/// One schema result, retaining its typed input and exact callback projection.
#[derive(Clone)]
pub struct ValidatedBody {
    pub(crate) projection: Option<Value>,
    typed: RuntimeExtensions,
}

impl std::fmt::Debug for ValidatedBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedBody")
            .finish_non_exhaustive()
    }
}

impl ValidatedBody {
    pub fn new<T: Send + Sync + 'static>(projection: Option<Value>, value: T) -> Self {
        let mut typed = RuntimeExtensions::default();
        typed.insert(value);
        Self { projection, typed }
    }

    /// Read the typed result without parsing the validated projection again.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.typed.get()
    }

    /// Preserve input for endpoints without a body schema.
    pub fn unvalidated(projection: Option<Value>) -> Self {
        Self {
            projection,
            typed: RuntimeExtensions::default(),
        }
    }
}

/// Validate a record body while retaining values and removing the prototype setter key.
pub fn record_body(request: &AuthRequest) -> AuthResult<ValidatedBody> {
    let body = parse_record_body(request)?;
    Ok(ValidatedBody::new(Some(Value::Object(body.clone())), body))
}

/// Read a validated record, including calls that invoke a plugin directly.
pub fn record_input(request: &AuthRequest) -> AuthResult<serde_json::Map<String, Value>> {
    request
        .validated_body::<serde_json::Map<String, Value>>()
        .cloned()
        .map_or_else(|| parse_record_body(request), Ok)
}

fn parse_record_body(request: &AuthRequest) -> AuthResult<serde_json::Map<String, Value>> {
    let body = request.input_body()?;
    if let Some(Value::Object(mut body)) = body {
        let _ = body.remove("__proto__");
        return Ok(body);
    }
    let actual = match body {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    };
    Err(crate::AuthResponse::json(
        400,
        &serde_json::json!({
            "code": "VALIDATION_ERROR",
            "message": format!("[body] Invalid input: expected record, received {actual}"),
        }),
    )?
    .into())
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointBody {
    source: Option<Vec<u8>>,
    value: ValidatedBody,
}

impl AuthRequest {
    /// Return endpoint input without changing the original Request bytes.
    pub fn input_body(&self) -> AuthResult<Option<Value>> {
        if let Some(body) = self
            .endpoint_body
            .as_ref()
            .filter(|body| body.source == self.body)
        {
            Ok(body.value.projection.clone())
        } else if let Some(body) = self.parsed_http_body() {
            Ok(Some(body.clone()))
        } else {
            self.body
                .as_deref()
                .filter(|bytes| !bytes.is_empty())
                .map(serde_json::from_slice)
                .transpose()
                .map_err(Into::into)
        }
    }

    /// Read the typed result installed by the matched route's body validator.
    pub fn validated_body<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.endpoint_body
            .as_ref()
            .filter(|body| body.source == self.body)?
            .value
            .typed
            .get()
    }

    pub fn set_endpoint_body(&mut self, value: ValidatedBody) {
        self.endpoint_body = Some(EndpointBody {
            source: self.body.clone(),
            value,
        });
    }

    pub(crate) fn projected_body(&self) -> Option<&Option<Value>> {
        self.endpoint_body
            .as_ref()
            .filter(|body| body.source == self.body)
            .map(|body| &body.value.projection)
    }
}

/// Returned before-hook input changes, applied after all before hooks complete.
#[derive(Debug, Clone, Default)]
pub struct EndpointInputPatch {
    pub body: Option<Value>,
    pub query: Option<Value>,
}

impl EndpointInputPatch {
    pub fn merge(&mut self, patch: Self) {
        merge_input(&mut self.body, patch.body);
        merge_input(&mut self.query, patch.query);
    }

    pub fn apply(self, request: &mut AuthRequest) -> AuthResult<()> {
        if self.body.is_some() {
            let mut body = request.input_body()?;
            merge_input(&mut body, self.body);
            request.set_endpoint_body(ValidatedBody::unvalidated(body));
        }
        merge_input(&mut request.query, self.query);
        Ok(())
    }
}

fn merge_input(target: &mut Option<Value>, patch: Option<Value>) {
    if let Some(patch) = patch.filter(|value| !value.is_null()) {
        match target {
            Some(value) => merge_value(value, patch),
            None => *target = Some(patch),
        }
    }
}

fn merge_value(target: &mut Value, patch: Value) {
    if patch.is_null() {
        return;
    }
    if let (Value::Object(target), Value::Object(patch)) = (&mut *target, &patch) {
        for (name, value) in patch {
            if value.is_null() || matches!(name.as_str(), "__proto__" | "constructor") {
                continue;
            }
            match target.get_mut(name) {
                Some(current) => merge_value(current, value.clone()),
                None => {
                    let _ = target.insert(name.clone(), value.clone());
                }
            }
        }
    } else {
        *target = patch;
    }
}

/// Install handler inputs while preserving the raw scope for endpoint after hooks.
pub fn with_validated_input<T>(
    body: Option<Value>,
    query: Option<Value>,
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    let future = Box::pin(future);
    async move {
        if let Some(mut context) = crate::hooks::current_request_hook_context() {
            context.body = body;
            context.query = query;
            crate::hooks::with_request_hook_context_value(context, future).await
        } else {
            future.await
        }
    }
}
