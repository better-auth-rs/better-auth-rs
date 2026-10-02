use super::*;
use crate::user_fields::{UserConfig, UserFieldConfig};

impl EphemeralStore {
    fn uses_serial_reference(&self, field: &UserFieldConfig) -> bool {
        matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) && field.references_id()
    }

    pub(super) fn memory_field_input(
        &self,
        field: &UserFieldConfig,
        value: Value,
    ) -> AuthResult<Value> {
        if self.uses_serial_reference(field) {
            crate::id::serial_reference_value(value)
        } else {
            Ok(value)
        }
    }

    pub(super) fn memory_record_input(
        &self,
        field: &UserFieldConfig,
        value: Value,
    ) -> AuthResult<Value> {
        if self.uses_serial_reference(field) {
            crate::id::serial_reference_value(value)
        } else {
            Ok(field.adapter_input(value, true, true))
        }
    }

    pub(super) fn memory_field_query(
        &self,
        schema: &UserConfig,
        name: &str,
        value: Value,
    ) -> AuthResult<Value> {
        if schema
            .fields()
            .get(name)
            .is_some_and(|field| self.uses_serial_reference(field))
        {
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
            Ok(value)
        } else {
            Ok(value)
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
