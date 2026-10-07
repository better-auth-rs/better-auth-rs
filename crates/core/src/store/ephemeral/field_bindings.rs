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
        if name == "id" {
            return self.organization_primary_id(&crate::SchemaValue::from_field(value));
        }
        let value = self.memory_field_query(&self.field_config(role)?, name, value)?;
        Ok(crate::SchemaValue::from_field(value))
    }

    pub(super) fn organization_primary_id(
        &self,
        value: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        // Organization records store textual primary IDs.
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            let number = crate::query::field_number(&value.field_value())?;
            Ok(crate::schema_value::number_string(number).into())
        } else {
            Ok(value.clone())
        }
    }

    pub(super) fn organization_reference_query(
        &self,
        role: EntityRole,
        name: &str,
        value: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        self.organization_query(role, name, value.field_value())
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
            .filter(|value| {
                value.is_object()
                    || value.is_array()
                    || value.is_null()
                    || value.as_date().is_some()
            });
        let value = if field.is_some_and(|field| self.uses_serial_reference(field)) {
            crate::id::serial_reference_query_value(value)?
        } else {
            value
        };
        // Query JSON conversion follows reference conversion and uses the original query value.
        match original_json {
            Some(value) => Ok(value.stringify()?.map(Value::String).unwrap_or_default()),
            None => Ok(value),
        }
    }

    pub(super) fn memory_primary_id_query(&self, value: &Value) -> AuthResult<Value> {
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            crate::id::serial_reference_query_value(value.clone())
        } else {
            Ok(value.clone())
        }
    }

    pub(super) fn memory_reference_id_input(
        &self,
        value: Value,
    ) -> AuthResult<crate::SchemaValue<String>> {
        let value = if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            crate::id::serial_reference_value(value)?
        } else {
            value
        };
        Ok(crate::SchemaValue::from_field(value))
    }

    pub(super) fn memory_session_user_id_query(&self, value: Value) -> AuthResult<Value> {
        match self.session_config.fields().get("userId") {
            Some(field) => crate::user_query::bind_filter(
                field,
                &self.memory_field_query(&self.session_config.field_schema(), "userId", value)?,
            ),
            None => self.memory_primary_id_query(&value),
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
                crate::SchemaValue::<String>::from_field(value)
                    .display_string()
                    .map(Into::into)
            }
            value => Ok(crate::SchemaValue::from_field(value.unwrap_or_default())),
        }
    }
}
