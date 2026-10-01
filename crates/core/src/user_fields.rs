//! Application user fields at the input, storage, and public output boundaries.

use crate::{AuthError, AuthResult};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::sync::Arc;
mod adapter;
mod organization;
mod output;
mod user_record;

/// Synchronous field transform. `None` represents undefined; `Some(Value::Null)` represents null.
pub type UserFieldTransform = Arc<dyn Fn(Option<Value>) -> AuthResult<Option<Value>> + Send + Sync>;

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

/// Schema for an application-owned user field.
#[derive(Clone)]
pub struct UserFieldConfig {
    /// Storage type; route validation is supplied separately by `validator`.
    pub field_type: UserFieldType,
    /// User input requires `Some(true)`; organization input requires any value except `Some(false)`.
    pub required: Option<bool>,
    /// Permit public client input.
    pub input: bool,
    /// Include the field in public user views.
    pub returned: bool,
    /// Serialized application model field name.
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
    /// Transform input at the route and storage boundaries, matching the upstream adapter.
    pub input_transform: Option<UserFieldTransform>,
    /// Transform a stored value when constructing a user view.
    pub output_transform: Option<UserFieldTransform>,
}

impl Default for UserFieldConfig {
    fn default() -> Self {
        Self {
            field_type: UserFieldType::String,
            required: None,
            input: true,
            returned: true,
            field_name: None,
            references: None,
            default_value: None,
            default_value_fn: None,
            on_update: None,
            validator: None,
            input_transform: None,
            output_transform: None,
        }
    }
}

/// Application user schema.
#[derive(Clone, Default)]
pub struct UserConfig {
    /// Public field names and their storage/input/output policies.
    pub additional_fields: IndexMap<String, UserFieldConfig>,
}

impl UserFieldConfig {
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

impl UserConfig {
    /// Parse public input. Updates omit missing fields and never apply creation defaults.
    pub fn parse_input(
        &self,
        input: &Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut parsed = Map::new();
        for (name, field) in &self.additional_fields {
            let value = if let Some(value) = input.get(name) {
                if !field.input {
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
                } else if let Some(transform) = &field.input_transform {
                    transform(Some(value.clone()))?
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
            .filter(|(name, _)| {
                self.additional_fields
                    .get(*name)
                    .is_some_and(|field| field.input)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.parse_input(&allowed, create)
    }

    /// Map configured fields to application storage columns and apply adapter transforms.
    pub fn storage_fields(
        &self,
        input: Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        self.storage_fields_inner(input, create, false)
    }

    fn storage_fields_inner(
        &self,
        input: Map<String, Value>,
        create: bool,
        preserve_id: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = Map::new();
        for (name, field) in &self.additional_fields {
            if preserve_id && name == "id" {
                continue;
            }
            let mut value = input.get(name).cloned().or_else(|| {
                if create {
                    field.default_value()
                } else {
                    field.on_update.as_ref().map(|update| update())
                }
            });
            if value.is_none() && (!create || field.input_transform.is_none()) {
                continue;
            }
            if create
                && field.required == Some(true)
                && value == Some(Value::Null)
                && let Some(default) = field.default_value()
            {
                value = Some(default);
            }
            if let Some(value) = value.as_mut() {
                field.normalize_date(value)?;
            }
            if let Some(transform) = &field.input_transform {
                value = transform(value)?;
            }
            if let Some(value) = value {
                let _ = output.insert(field.field_name.as_ref().unwrap_or(name).clone(), value);
            }
        }
        Ok(output)
    }
}
