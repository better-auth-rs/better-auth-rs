//! Application user fields at the input, storage, and public output boundaries.

use crate::store::schema::resolve_field_name;
use crate::{AuthError, AuthResult};
use crate::{FieldMap, FieldValue as Value};
use indexmap::IndexMap;
use std::sync::{Arc, LazyLock};
mod adapter;
#[cfg(test)]
mod factory_tests;
#[cfg(test)]
mod input_binding_tests;
pub use adapter::FieldOutputCapabilities;
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
pub use better_auth_schema_registry::FieldReferenceAction;
pub use transform::UserFieldTransform;
pub(crate) use user_record::USER_FIELDS;

/// Synchronous field validator. Return the validated value or a validation error.
pub type UserFieldValidator = Arc<dyn Fn(Value) -> AuthResult<Value> + Send + Sync>;

/// Validator declarations retained with the complete field policy.
#[derive(Clone, Default)]
pub struct FieldValidators {
    /// Validate public input before its route input transform.
    pub input: Option<UserFieldValidator>,
    /// Retain the output validator declaration; Better Auth 1.7.6 does not execute it.
    pub output: Option<UserFieldValidator>,
}

/// Synchronous default or update factory. Errors stop field processing before persistence.
pub type UserFieldFactory = Arc<dyn Fn() -> AuthResult<Value> + Send + Sync>;

/// Referenced model and logical field, shared with the application's migration configuration.
#[derive(Clone, Debug, Default)]
pub struct UserFieldReference {
    /// Logical model name, or the literal name of an application-owned table.
    pub model: String,
    /// Logical field name, or the literal column name of an application-owned table.
    pub field: String,
    /// Database action when the referenced row is deleted. Omission selects Cascade.
    pub on_delete: Option<FieldReferenceAction>,
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
    /// Unique foreign keys select one related row; omission permits a related page.
    pub unique: Option<bool>,
    /// Declare a database index. Omission leaves the field unindexed.
    pub index: Option<bool>,
    /// Select sortable text storage when the adapter supports it.
    pub sortable: Option<bool>,
    /// Select bigint storage for a numeric field.
    pub bigint: Option<bool>,
    /// Constant creation default.
    pub default_value: Option<Value>,
    /// Creation default factory.
    pub default_value_fn: Option<UserFieldFactory>,
    /// Produce a stored value when an update omits this field.
    pub on_update: Option<UserFieldFactory>,
    /// Validator callbacks. An empty container preserves the absence of an input validator.
    pub validator: Option<FieldValidators>,
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

    /// Configured public input validator, without invoking the callback.
    pub fn input_validator(&self) -> Option<&UserFieldValidator> {
        self.validator
            .as_ref()
            .and_then(|validator| validator.input.as_ref())
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
        if matches!(self.field_type, UserFieldType::Date)
            && let Value::String(text) = value
        {
            *value = Value::Date(
                crate::utils::date::parse_adapter_date(text)
                    .map(crate::FieldDate::from)
                    .unwrap_or_else(crate::FieldDate::invalid),
            );
        }
        Ok(())
    }

    pub(crate) fn default_value(&self) -> AuthResult<Option<Value>> {
        match &self.default_value_fn {
            Some(factory) => factory().map(Some),
            None => Ok(self.default_value.clone()),
        }
    }
}

/// JavaScript truthiness used by upstream protected-field checks.
pub fn is_truthy(value: &Value) -> bool {
    value.is_truthy()
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
    pub fn parse_input(&self, input: &FieldMap, create: bool) -> AuthResult<FieldMap> {
        let mut parsed = FieldMap::new();
        for (name, field) in self.fields() {
            let value = if let Some(value) = input.get(name) {
                if !field.input() {
                    if create && let Some(default) = field.default_value()? {
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
                if let Some(validate) = field.input_validator() {
                    Some(
                        validate(value.clone()).map_err(|error| AuthError::FieldInput {
                            code: "VALIDATION_ERROR",
                            message: error.to_string(),
                        })?,
                    )
                } else if let Some(transform) = field.input_transform() {
                    Some(transform.call_sync(value.clone())?)
                } else {
                    Some(value.clone())
                }
            } else if create {
                if let Some(default) = field.default_value()? {
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
            if let Some(value) = value.filter(|value| !value.is_undefined()) {
                let _ = parsed.insert(name.clone(), value);
            }
        }
        Ok(parsed)
    }

    /// Parse an OAuth provider profile without trusting protected application fields.
    pub fn parse_provider_input(&self, profile: &FieldMap, create: bool) -> AuthResult<FieldMap> {
        let allowed = profile
            .iter()
            .filter(|(name, _)| self.fields().get(*name).is_some_and(|field| field.input()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.parse_input(&allowed, create)
    }

    /// Map configured fields to application storage columns and await adapter transforms.
    pub async fn storage_fields(&self, input: FieldMap, create: bool) -> AuthResult<FieldMap> {
        self.storage_fields_async(input, create, false, |_, _, value| Ok(value))
            .await
    }

    async fn storage_fields_async(
        &self,
        input: FieldMap,
        create: bool,
        preserve_id: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let mut output = FieldMap::new();
        for (name, field) in self.fields() {
            if preserve_id && name == "id" {
                continue;
            }
            if let Some(value) = field.storage_input(input.get(name), create).await? {
                let storage = resolve_field_name(field.field_name.as_deref(), name);
                let value = bind(storage, field, value)?;
                if !value.is_undefined() {
                    let _ = output.insert(storage.to_owned(), value);
                }
            }
        }
        Ok(output)
    }
}

impl UserFieldConfig {
    async fn storage_input(
        &self,
        input: Option<&Value>,
        create: bool,
    ) -> AuthResult<Option<Value>> {
        let Some(value) = self.storage_value(input, create)? else {
            return Ok(None);
        };
        let value = match self.input_transform() {
            Some(transform) => transform.call(value).await,
            None => Ok(value),
        }?;
        // Serial references convert callback Undefined to NaN before final omission.
        Ok(Some(value))
    }

    // The option skips a field; Undefined can still reach a configured callback.
    fn storage_value(&self, input: Option<&Value>, create: bool) -> AuthResult<Option<Value>> {
        let mut value = input.cloned().unwrap_or_default();
        if value.is_undefined()
            && if create {
                !self.has_storage_default() && self.input_transform().is_none()
            } else {
                self.on_update.is_none()
            }
        {
            return Ok(None);
        }
        self.normalize_date(&mut value)?;
        if create
            && (value.is_undefined() || (self.required == Some(true) && value.is_null()))
            && self.has_storage_default()
            && let Some(default) = self.default_value()?
        {
            value = default;
        }
        if !create
            && value.is_undefined()
            && let Some(update) = &self.on_update
        {
            value = update()?;
        }
        Ok(Some(value))
    }

    pub(crate) fn has_storage_default(&self) -> bool {
        self.default_value_fn.is_some()
            || self
                .default_value
                .as_ref()
                .is_some_and(|value| !value.is_undefined())
    }
}
