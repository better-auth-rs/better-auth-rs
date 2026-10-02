use super::{UserConfig, UserFieldConfig, UserFieldType};
use crate::AuthResult;
use crate::store::schema::resolve_field_name;
use serde_json::{Map, Value};

impl UserConfig {
    /// Apply storage policies before converting JSON for the selected adapter.
    pub async fn storage_fields_for_adapter(
        &self,
        input: Map<String, Value>,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<Map<String, Value>> {
        self.storage_fields_with_binding(input, create, |name, field, value| {
            field.adapter_input(value, supports_native_json, native_json_field(name))
        })
        .await
    }

    /// Bind transformed fields to an adapter without repeating defaults or application transforms.
    pub async fn storage_fields_with_binding(
        &self,
        input: Map<String, Value>,
        create: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<Map<String, Value>> {
        let mut fields = self.storage_fields(input, create).await?;
        for (name, field) in self.fields() {
            let storage_name = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage_name) {
                *value = bind(storage_name, field, value.take())?;
            }
        }
        Ok(fields)
    }
}

impl UserFieldConfig {
    /// Convert a transformed value to the selected adapter's database binding.
    /// JSON text uses JavaScript property ordering and number formatting.
    /// Serialization errors propagate before the adapter writes the value.
    pub fn adapter_input(
        &self,
        value: Value,
        supports_native_json: bool,
        native_json_field: bool,
    ) -> AuthResult<Value> {
        if self.references_id() {
            match (&self.field_type, &value) {
                (UserFieldType::Boolean, Value::Bool(value)) if !supports_native_json => {
                    return Ok(Value::from(i64::from(*value)));
                }
                (UserFieldType::StringArray | UserFieldType::NumberArray, Value::Array(_))
                | (UserFieldType::Json, Value::Object(_) | Value::Array(_)) => {
                    return Ok(Value::String(crate::utils::json::stringify(&value)?));
                }
                _ => {}
            }
        }
        if !supports_native_json
            && matches!(self.field_type, UserFieldType::Json)
            && (value.is_null() || (!native_json_field && (value.is_object() || value.is_array())))
        {
            Ok(Value::String(crate::utils::json::stringify(&value)?))
        } else {
            Ok(value)
        }
    }

    /// Whether this field uses the adapter's reference-to-ID conversion.
    pub fn references_id(&self) -> bool {
        self.references
            .as_ref()
            .is_some_and(|reference| reference.field == "id")
    }

    /// Await the output policy before decoding adapter storage values.
    pub async fn adapter_output(
        &self,
        value: Option<Value>,
        supports_native_json: bool,
    ) -> AuthResult<Option<Value>> {
        let mut value = self.prepare_output(value, supports_native_json)?;
        if let Some(transform) = self.output_transform() {
            value = transform.call(value).await?;
        }
        self.finish_output(value, supports_native_json)
    }

    fn prepare_output(
        &self,
        value: Option<Value>,
        supports_native_json: bool,
    ) -> AuthResult<Option<Value>> {
        if !supports_native_json && matches!(self.field_type, UserFieldType::Json) {
            value
                .map(|value| match value {
                    Value::Object(_) | Value::Array(_) => {
                        Ok(Value::String(crate::utils::json::stringify(&value)?))
                    }
                    value => Ok(value),
                })
                .transpose()
        } else {
            Ok(value)
        }
    }

    fn finish_output(
        &self,
        value: Option<Value>,
        supports_native_json: bool,
    ) -> AuthResult<Option<Value>> {
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
            Value::String(text)
                if !supports_native_json && matches!(self.field_type, UserFieldType::Json) =>
            {
                crate::utils::json::safe_json_parse(&text)
            }
            value => value,
        }))
    }
}
