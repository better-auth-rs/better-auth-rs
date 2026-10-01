use super::{UserConfig, UserFieldConfig, UserFieldType};
use crate::AuthResult;
use serde_json::{Map, Value};

impl UserConfig {
    /// Apply storage policies before converting JSON for the selected adapter.
    pub fn storage_fields_for_adapter(
        &self,
        input: Map<String, Value>,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<Map<String, Value>> {
        self.storage_fields_with_binding(input, create, |name, field, value| {
            Ok(field.adapter_input(value, supports_native_json, native_json_field(name)))
        })
    }

    /// Bind transformed fields to an adapter without repeating defaults or application transforms.
    pub fn storage_fields_with_binding(
        &self,
        input: Map<String, Value>,
        create: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<Map<String, Value>> {
        let mut fields = self.storage_fields(input, create)?;
        for (name, field) in &self.additional_fields {
            let storage_name = field.field_name.as_ref().unwrap_or(name);
            if let Some(value) = fields.get_mut(storage_name) {
                *value = bind(storage_name, field, value.take())?;
            }
        }
        Ok(fields)
    }
}

impl UserFieldConfig {
    /// Convert a transformed value to the selected adapter's database binding.
    pub fn adapter_input(
        &self,
        value: Value,
        supports_native_json: bool,
        native_json_field: bool,
    ) -> Value {
        if self.references_id() {
            match (&self.field_type, &value) {
                (UserFieldType::Boolean, Value::Bool(value)) if !supports_native_json => {
                    return Value::from(i64::from(*value));
                }
                (UserFieldType::StringArray | UserFieldType::NumberArray, Value::Array(_))
                | (UserFieldType::Json, Value::Object(_) | Value::Array(_)) => {
                    return Value::String(value.to_string());
                }
                _ => {}
            }
        }
        if !supports_native_json
            && matches!(self.field_type, UserFieldType::Json)
            && (value.is_null() || (!native_json_field && (value.is_object() || value.is_array())))
        {
            Value::String(value.to_string())
        } else {
            value
        }
    }

    /// Whether this field uses the adapter's reference-to-ID conversion.
    pub fn references_id(&self) -> bool {
        self.references
            .as_ref()
            .is_some_and(|reference| reference.field == "id")
    }

    /// Run the output policy on adapter storage values, then decode text-backed JSON.
    pub fn adapter_output(
        &self,
        mut value: Option<Value>,
        supports_native_json: bool,
    ) -> AuthResult<Option<Value>> {
        let text_json = !supports_native_json && matches!(self.field_type, UserFieldType::Json);
        if text_json {
            value = value.map(|value| match value {
                Value::Object(_) | Value::Array(_) => Value::String(value.to_string()),
                value => value,
            });
        }
        if let Some(transform) = &self.output_transform {
            value = transform(value)?;
        }
        if self.references_id() {
            return value
                .map(|value| {
                    if value.is_null() {
                        Ok(value)
                    } else {
                        crate::SchemaValue::<String>::Dynamic(value)
                            .display_string()
                            .map(Value::String)
                    }
                })
                .transpose();
        }
        Ok(value.map(|value| match value {
            Value::String(text) if text_json => crate::utils::json::safe_json_parse(&text),
            value => value,
        }))
    }
}
