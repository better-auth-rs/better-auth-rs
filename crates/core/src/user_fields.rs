//! Application user fields at the input, storage, and public output boundaries.

use crate::store::schema::resolve_field_name;
use crate::{AuthError, AuthResult};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::sync::{Arc, LazyLock};
mod adapter;
mod batch;
pub(crate) use batch::{
    project_fields_batches_then, project_fields_then, project_source_fields_batches_then,
    project_source_fields_then,
};
pub use record::AdapterRecord;
pub(crate) use record::project_adapter_value;
mod organization;
pub(crate) use organization::assign_output;
mod output;
mod record;
mod transform;
mod user_record;
pub use transform::UserFieldTransform;

/// Synchronous public input validator. Return the validated value or a public validation message.
pub type UserFieldValidator = Arc<dyn Fn(Value) -> AuthResult<Value> + Send + Sync>;

/// Referenced model and logical field, shared with the application's migration configuration.
#[derive(Clone, Debug)]
pub struct UserFieldReference {
    /// Logical model name, or the literal name of an application-owned table.
    pub model: String,
    /// Logical field name, or the literal column name of an application-owned table.
    pub field: String,
}

/// Storage type of an application user field.
#[derive(Clone, Debug, Default)]
pub enum UserFieldType {
    /// UTF-8 string.
    #[default]
    String,
    /// JSON number.
    Number,
    /// Boolean.
    Boolean,
    /// RFC 3339 timestamp.
    Date,
    /// JSON document.
    Json,
    /// Array of strings.
    StringArray,
    /// Array of numbers.
    NumberArray,
    /// One of the listed strings.
    Enum(Vec<String>),
}

/// Input and output callbacks configured for an application field.
#[derive(Clone, Default)]
pub struct FieldTransforms {
    /// Transform input at public parsing and storage boundaries.
    /// Public parsing requires a synchronous callback; adapters can await async callbacks.
    pub input: Option<UserFieldTransform>,
    /// Transform stored values at adapter output boundaries.
    pub output: Option<UserFieldTransform>,
}

/// Schema for an application-owned user field.
#[derive(Clone, Default)]
pub struct UserFieldConfig {
    /// Storage type; route validation is supplied separately by `validator`.
    pub field_type: UserFieldType,
    /// User input requires `Some(true)`; organization input requires any value except `Some(false)`.
    pub required: Option<bool>,
    /// Permit public client input. Omission defaults to true.
    pub input: Option<bool>,
    /// Include the field in public user views. Omission defaults to true.
    pub returned: Option<bool>,
    /// Serialized application model field name. Omitted or empty names use the logical field name.
    pub field_name: Option<String>,
    /// Foreign-key metadata. References to `id` use the adapter's ID output conversion.
    pub references: Option<UserFieldReference>,
    /// Constant creation default.
    pub default_value: Option<Value>,
    /// Creation default factory.
    pub default_value_fn: Option<Arc<dyn Fn() -> Value + Send + Sync>>,
    /// Produce a stored value when an update omits this field.
    pub on_update: Option<Arc<dyn Fn() -> Value + Send + Sync>>,
    /// Validate public input before persistence; takes precedence over the route input transform.
    pub validator: Option<UserFieldValidator>,
    /// Field callbacks. `None` preserves omission; `Some(Default::default())` is an empty container.
    pub transform: Option<FieldTransforms>,
}

impl std::fmt::Debug for UserFieldConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserFieldConfig")
            .field("field_type", &self.field_type)
            .field("required", &self.required)
            .field("input", &self.input)
            .field("returned", &self.returned)
            .field("field_name", &self.field_name)
            .finish_non_exhaustive()
    }
}

/// Application user schema.
#[derive(Clone, Default)]
pub struct UserConfig {
    /// Public field policies. `None` preserves omission; `Some(IndexMap::new())` is explicitly empty.
    pub additional_fields: Option<IndexMap<String, UserFieldConfig>>,
}

impl UserFieldConfig {
    /// Whether the public input boundary permits this field; defaults to true.
    pub fn input(&self) -> bool {
        self.input.unwrap_or(true)
    }

    /// Whether public views include this field; defaults to true.
    pub fn returned(&self) -> bool {
        self.returned.unwrap_or(true)
    }

    /// Configured input callback, without invoking the callback.
    pub fn input_transform(&self) -> Option<&UserFieldTransform> {
        self.transform
            .as_ref()
            .and_then(|transform| transform.input.as_ref())
    }

    /// Configured output callback, without invoking the callback.
    pub fn output_transform(&self) -> Option<&UserFieldTransform> {
        self.transform
            .as_ref()
            .and_then(|transform| transform.output.as_ref())
    }

    pub(crate) fn normalize_date(&self, value: &mut Value) -> AuthResult<()> {
        if matches!(self.field_type, UserFieldType::Date) && value.is_string() {
            let date: chrono::DateTime<chrono::Utc> = serde_json::from_value(value.clone())?;
            *value = Value::String(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        }
        Ok(())
    }

    pub(crate) fn default_value(&self) -> Option<Value> {
        self.default_value_fn
            .as_ref()
            .map(|factory| factory())
            .or_else(|| self.default_value.clone())
    }
}

/// JavaScript truthiness used by upstream protected-field checks.
pub fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(crate) fn fields_or_empty(
    fields: &Option<IndexMap<String, UserFieldConfig>>,
) -> &IndexMap<String, UserFieldConfig> {
    static EMPTY: LazyLock<IndexMap<String, UserFieldConfig>> = LazyLock::new(IndexMap::new);
    fields.as_ref().unwrap_or(&EMPTY)
}

impl UserConfig {
    /// Runtime fields. An omitted map has no fields.
    pub fn fields(&self) -> &IndexMap<String, UserFieldConfig> {
        fields_or_empty(&self.additional_fields)
    }

    /// Configure fields, creating an explicitly present map when omitted.
    pub fn fields_mut(&mut self) -> &mut IndexMap<String, UserFieldConfig> {
        self.additional_fields.get_or_insert_default()
    }

    /// Parse public input. Updates omit missing fields and never apply creation defaults.
    pub fn parse_input(
        &self,
        input: &Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut parsed = Map::new();
        for (name, field) in self.fields() {
            let value = if let Some(value) = input.get(name) {
                if !field.input() {
                    if create && let Some(default) = field.default_value() {
                        let _ = parsed.insert(name.clone(), default);
                        continue;
                    }
                    if is_truthy(value) {
                        return Err(AuthError::FieldInput {
                            code: "FIELD_NOT_ALLOWED",
                            message: format!("{name} is not allowed to be set"),
                        });
                    }
                    continue;
                }
                if let Some(validate) = &field.validator {
                    Some(
                        validate(value.clone()).map_err(|error| AuthError::FieldInput {
                            code: "VALIDATION_ERROR",
                            message: error.to_string(),
                        })?,
                    )
                } else if let Some(transform) = field.input_transform() {
                    transform.call_sync(Some(value.clone()))?
                } else {
                    Some(value.clone())
                }
            } else if create {
                if let Some(default) = field.default_value() {
                    Some(default)
                } else if field.required == Some(true) {
                    return Err(AuthError::FieldInput {
                        code: "MISSING_FIELD",
                        message: format!("{name} is required"),
                    });
                } else {
                    continue;
                }
            } else {
                continue;
            };
            if let Some(value) = value {
                let _ = parsed.insert(name.clone(), value);
            }
        }
        Ok(parsed)
    }

    /// Parse an OAuth provider profile without trusting protected application fields.
    pub fn parse_provider_input(
        &self,
        profile: &Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        let allowed = profile
            .iter()
            .filter(|(name, _)| self.fields().get(*name).is_some_and(|field| field.input()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.parse_input(&allowed, create)
    }

    /// Map configured fields to application storage columns and await adapter transforms.
    pub async fn storage_fields(
        &self,
        input: Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        self.storage_fields_async(input, create, false).await
    }

    async fn storage_fields_async(
        &self,
        input: Map<String, Value>,
        create: bool,
        preserve_id: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = Map::new();
        for (name, field) in self.fields() {
            if preserve_id && name == "id" {
                continue;
            }
            let Some(mut value) = field.storage_value(input.get(name), create)? else {
                continue;
            };
            if let Some(transform) = field.input_transform() {
                value = transform.call(value).await?;
            }
            if let Some(value) = value {
                let _ = output.insert(
                    resolve_field_name(field.field_name.as_deref(), name).to_owned(),
                    value,
                );
            }
        }
        Ok(output)
    }
}

impl UserFieldConfig {
    // The outer option omits a field. The inner option passes undefined to its callback.
    fn storage_value(
        &self,
        input: Option<&Value>,
        create: bool,
    ) -> AuthResult<Option<Option<Value>>> {
        let mut value = input.cloned().or_else(|| {
            if create {
                self.default_value()
            } else {
                self.on_update.as_ref().map(|update| update())
            }
        });
        if value.is_none() && (!create || self.input_transform().is_none()) {
            return Ok(None);
        }
        if create
            && self.required == Some(true)
            && value == Some(Value::Null)
            && let Some(default) = self.default_value()
        {
            value = Some(default);
        }
        if let Some(value) = value.as_mut() {
            self.normalize_date(value)?;
        }
        Ok(Some(value))
    }
}
