use super::*;
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth_schema_registry::EntityRole;

impl EphemeralStore {
    pub(super) fn organization_query(
        &self,
        role: EntityRole,
        name: &str,
        value: Value,
    ) -> AuthResult<crate::SchemaValue<String>> {
        let value = if name == "id" {
            self.memory_user_id_query(&value)?
        } else {
            self.memory_field_query(&self.field_config(role)?, name, value)?
        };
        Ok(crate::SchemaValue::from_json(Some(value)))
    }

    pub(super) fn organization_primary_id(
        &self,
        value: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        // Join keys come from the stored row before output transforms run.
        value
            .json()?
            .map(|value| self.memory_user_id_query(&value))
            .transpose()
            .map(crate::SchemaValue::from_json)
    }

    pub(super) fn organization_reference_query(
        &self,
        role: EntityRole,
        name: &str,
        value: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        match value.json()? {
            Some(value) => self.organization_query(role, name, value),
            None => Ok(crate::SchemaValue::Undefined),
        }
    }

    fn uses_serial_reference(&self, field: &UserFieldConfig) -> bool {
        matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) && field.references_id()
    }

    pub(super) fn memory_plugin_field_input(
        &self,
        field: &UserFieldConfig,
        value: Value,
    ) -> AuthResult<Value> {
        if self.uses_serial_reference(field) {
            crate::id::serial_reference_value(value)
        } else if matches!(field.field_type, UserFieldType::Json) {
            // Memory stores JSON text but retains native arrays, booleans and dates.
            field.adapter_input(value, false, false)
        } else {
            Ok(value)
        }
    }

    pub(super) fn memory_field_query(
        &self,
        schema: &UserConfig,
        name: &str,
        value: Value,
    ) -> AuthResult<Value> {
        let field = schema.fields().get(name);
        let original_json = field
            .is_some_and(|field| matches!(field.field_type, UserFieldType::Json))
            .then(|| value.clone())
            .filter(|value| value.is_object() || value.is_array() || value.is_null());
        let value = if field.is_some_and(|field| self.uses_serial_reference(field)) {
            let mut value = crate::id::serial_reference_value(value)?;
            // Where conversion uses Number(null), while stored references preserve null.
            let replace_null = |value: &mut Value| {
                if value.is_null() {
                    *value = Value::from(0);
                }
            };
            match &mut value {
                Value::Array(values) => values.iter_mut().for_each(replace_null),
                value => replace_null(value),
            }
            value
        } else {
            value
        };
        // Query JSON conversion follows reference conversion and uses the original query value.
        match original_json {
            Some(value) => Ok(Value::String(crate::utils::json::stringify(&value)?)),
            None => Ok(value),
        }
    }

    pub(super) fn memory_user_id_query(&self, value: &Value) -> AuthResult<Value> {
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            // Memory's typed user rows retain primary IDs as strings.
            let number = crate::query::number(value)?;
            Ok(Value::String(crate::schema_value::number_string(number)))
        } else {
            Ok(value.clone())
        }
    }

    pub(super) fn stored_account_owner_id(
        &self,
        value: Option<Value>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        let reference = self
            .config
            .account
            .field_schema()
            .fields()
            .get("userId")
            .is_some_and(|field| self.uses_serial_reference(field));
        match value {
            Some(value) if reference && !value.is_null() => {
                // Derive the canonical binding from the captured raw value, not output policies.
                crate::SchemaValue::<String>::from_json(Some(value))
                    .display_string()
                    .map(Into::into)
            }
            value => Ok(crate::SchemaValue::from_json(value)),
        }
    }
}
