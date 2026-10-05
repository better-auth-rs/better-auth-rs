use better_auth_core::{AuthError, AuthResult};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{future::Future, pin::Pin, sync::Arc};

/// One request-schema issue. Paths are relative to the field being validated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRequestIssue {
    /// Human-readable validation failure.
    pub message: String,
    /// Standard Schema path segments, including JSON-visible `{ "key": ... }` segments.
    #[serde(default)]
    pub path: Vec<Value>,
    /// Validator-specific details, such as Zod's `code` and `expected` fields.
    #[serde(default, flatten)]
    pub details: Map<String, Value>,
}

impl DeviceRequestIssue {
    pub(super) fn invalid_type(field: Option<&str>, expected: &str, value: Option<&Value>) -> Self {
        Self {
            message: format!(
                "Invalid input: expected {expected}, received {}",
                crate::plugins::json_body::type_name(value)
            ),
            path: field.into_iter().map(|field| json!(field)).collect(),
            details: Map::from_iter([
                ("code".into(), json!("invalid_type")),
                ("expected".into(), json!(expected)),
            ]),
        }
    }

    pub(super) fn message(&self) -> String {
        let mut path = String::from("body");
        for segment in &self.path {
            let key = segment.get("key").unwrap_or(segment);
            path.push('.');
            match key {
                Value::String(key) => path.push_str(key),
                key => path.push_str(&key.to_string()),
            }
        }
        format!("[{path}] {}", self.message)
    }
}

/// A parsed field value or the field's structured validation issues.
pub enum DeviceFieldValidation {
    /// `None` preserves omission; `Some(Value::Null)` preserves an explicit null.
    Value(Option<Value>),
    /// Mark validation as failed, including when the issue list is empty.
    Issues(Vec<DeviceRequestIssue>),
}

type FieldResult = AuthResult<DeviceFieldValidation>;
type FieldFuture = Pin<Box<dyn Future<Output = FieldResult> + Send>>;

/// Validate one declared additional request field without changing native request fields.
#[derive(Clone)]
pub struct DeviceRequestField(Callback);

#[derive(Clone)]
enum Callback {
    Sync(Arc<dyn Fn(Option<Value>) -> FieldResult + Send + Sync>),
    Async(Arc<dyn Fn(Option<Value>) -> FieldFuture + Send + Sync>),
}

impl DeviceRequestField {
    /// Use a synchronous field schema.
    pub fn new(callback: impl Fn(Option<Value>) -> FieldResult + Send + Sync + 'static) -> Self {
        Self(Callback::Sync(Arc::new(callback)))
    }

    /// Await a field schema once, without emulating JavaScript's async-detection probe.
    pub fn new_async<F, Fut>(callback: F) -> Self
    where
        F: Fn(Option<Value>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = FieldResult> + Send + 'static,
    {
        Self(Callback::Async(Arc::new(move |value| {
            Box::pin(callback(value))
        })))
    }

    pub(super) async fn validate(&self, value: Option<Value>) -> FieldResult {
        match &self.0 {
            Callback::Sync(callback) => callback(value),
            Callback::Async(callback) => callback(value).await,
        }
    }
}

type ValidationErrorCallback = dyn Fn(&[DeviceRequestIssue]) -> AuthResult<()> + Send + Sync;

/// Additional Device request fields. Storage policies remain separate in `ModelFields`.
#[derive(Clone, Default)]
pub struct DeviceRequestFields {
    pub(super) fields: IndexMap<String, DeviceRequestField>,
    on_validation_error: Option<Arc<ValidationErrorCallback>>,
}

impl DeviceRequestFields {
    /// Start with no additional request fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a field in validation order. Native request fields cannot be replaced.
    pub fn field(mut self, name: impl Into<String>, field: DeviceRequestField) -> AuthResult<Self> {
        let name = name.into();
        if matches!(name.as_str(), "client_id" | "user_id" | "scope") {
            return Err(AuthError::config(format!(
                "Device authorization grant request fields must be additional and cannot redefine request fields: {name}",
            )));
        }
        let _ = self.fields.insert(name, field);
        Ok(self)
    }

    /// Observe issues or return an application error before the default OAuth error is produced.
    pub fn on_validation_error(
        mut self,
        callback: impl Fn(&[DeviceRequestIssue]) -> AuthResult<()> + Send + Sync + 'static,
    ) -> Self {
        self.on_validation_error = Some(Arc::new(callback));
        self
    }

    pub(super) fn report(&self, issues: &[DeviceRequestIssue]) -> AuthResult<()> {
        if let Some(callback) = &self.on_validation_error {
            callback(issues)?;
        }
        Ok(())
    }
}
