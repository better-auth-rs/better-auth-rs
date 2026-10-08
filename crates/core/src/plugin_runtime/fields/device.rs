use super::*;
use crate::id::IdGeneration;
use crate::user_fields::UserFieldConfig;
use crate::{DeviceCodeOwnership, DeviceCodeWhere, WhereMode, WhereOperator};

impl ModelFields {
    /// Bind one ownership condition without invoking application field callbacks.
    /// The returned condition uses its physical storage field name.
    /// The third tuple item retains the original operand for adapter-specific conversion.
    pub fn device_code_ownership_query(
        &self,
        ownership: &DeviceCodeOwnership,
        policy: &IdGeneration,
    ) -> AuthResult<(DeviceCodeWhere, &UserFieldConfig, Value)> {
        let (mut query, logical, field) = match ownership {
            DeviceCodeOwnership::ClientId(client) => {
                let (logical, field) = self.declared_device_code_ownership_field("clientId")?;
                (
                    DeviceCodeWhere::new("clientId", client.clone()),
                    logical,
                    field,
                )
            }
            DeviceCodeOwnership::FieldEquals { field, value } => {
                let (logical, config) = self.device_code_ownership_field(field, value)?;
                (DeviceCodeWhere::new(field, value.clone()), logical, config)
            }
            DeviceCodeOwnership::FieldIn { field, values }
            | DeviceCodeOwnership::FieldNotIn { field, values } => {
                let (logical, config) = self.device_code_ownership_set_field(field, values)?;
                (
                    DeviceCodeWhere {
                        field: field.clone(),
                        operator: if matches!(ownership, DeviceCodeOwnership::FieldIn { .. }) {
                            WhereOperator::In
                        } else {
                            WhereOperator::NotIn
                        },
                        value: values.clone().into(),
                        mode: WhereMode::Sensitive,
                    },
                    logical,
                    config,
                )
            }
            DeviceCodeOwnership::Where(query) => {
                if query.operator == WhereOperator::In && !matches!(query.value, Value::Array(_)) {
                    return Err(AuthError::internal("Value must be an array"));
                }
                let (logical, field) = self.declared_device_code_ownership_field(&query.field)?;
                if field.references.is_some()
                    && !(field.references_id()
                        && matches!(
                            field.field_type,
                            UserFieldType::String | UserFieldType::Json | UserFieldType::Date
                        ))
                {
                    return Err(AuthError::config(
                        "DeviceCode Where reference fields require the String, Json, or Date type and an id target",
                    ));
                }
                (query.clone(), logical, field)
            }
        };
        let original = query.value.clone();
        if field.references_id() && matches!(policy, IdGeneration::Serial) {
            query.value = crate::id::serial_reference_query_value(query.value)?;
        }
        query.value = crate::user_query::bind_filter(field, &query.value)?;
        query.field = resolve_field_name(field.field_name.as_deref(), logical).to_owned();
        Ok((query, field, original))
    }

    fn declared_device_code_ownership_field(
        &self,
        name: &str,
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        static NATIVE: LazyLock<UserConfig> =
            LazyLock::new(|| ModelFields::plugin_native_fields(EntityRole::DeviceCode));
        crate::user_query::declared_field(name, self.fields(EntityRole::DeviceCode))
            .or_else(|| crate::user_query::declared_field(name, &NATIVE))
            .ok_or_else(|| {
                AuthError::config(format!(
                    "DeviceCode ownership field {name} is not registered"
                ))
            })
    }

    /// Resolve and validate the supported scalar DeviceCode ownership query without running field callbacks.
    pub fn device_code_ownership_field(
        &self,
        name: &str,
        value: &Value,
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        let (logical, field) = self.declared_device_code_ownership_field(name)?;
        validate_reference(field)?;
        if !matches!(
            field.field_type,
            UserFieldType::String | UserFieldType::Number | UserFieldType::Boolean
        ) {
            return Err(AuthError::config(
                "DeviceCode FieldEquals supports only declared string, number, and boolean fields",
            ));
        }
        if !matches!(
            value,
            Value::Null
                | Value::Bool(_)
                | Value::String(_)
                | Value::Utf16String(_)
                | Value::Number(_)
        ) {
            return Err(AuthError::config(
                "DeviceCode FieldEquals requires a scalar null, string, number, or boolean value",
            ));
        }
        Ok((logical, field))
    }

    /// Validate DeviceCode ownership candidates without invoking field input or output callbacks.
    pub fn device_code_ownership_set_field(
        &self,
        name: &str,
        values: &[Value],
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        let (logical, field) = self.declared_device_code_ownership_field(name)?;
        validate_reference(field)?;
        if !matches!(
            field.field_type,
            UserFieldType::String | UserFieldType::Number
        ) {
            return Err(AuthError::config(
                "DeviceCode field sets support only declared string and number fields",
            ));
        }
        if values.iter().any(|value| {
            !matches!(
                value,
                Value::Null | Value::String(_) | Value::Utf16String(_) | Value::Number(_)
            )
        }) {
            return Err(AuthError::config(
                "DeviceCode field sets require scalar null, string, or number candidates",
            ));
        }
        Ok((logical, field))
    }

    /// Capture original physical bindings under their logical names before output policies run.
    #[doc(hidden)]
    pub fn device_code_storage_bindings(&self, stored: &FieldMap) -> FieldMap {
        let schema = self
            .plugin_fields(EntityRole::DeviceCode)
            .adapter_fields(&[]);
        ["id", "deviceCode", "clientId", "userId", "status"]
            .into_iter()
            .map(|name| {
                let physical = schema.fields().get(name).map_or(name, |field| {
                    resolve_field_name(field.field_name.as_deref(), name)
                });
                (
                    name.to_owned(),
                    stored.get(physical).cloned().unwrap_or_default(),
                )
            })
            .collect()
    }
}

fn validate_reference(field: &UserFieldConfig) -> AuthResult<()> {
    if field.references.is_some()
        && !(field.references_id() && matches!(field.field_type, UserFieldType::String))
    {
        return Err(AuthError::config(
            "DeviceCode ownership reference fields require the String type and an id target",
        ));
    }
    Ok(())
}
