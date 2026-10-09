use super::*;
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth_schema_registry::EntityRole;

pub(super) fn memory_json_query_value(value: Value, original: &Value) -> AuthResult<Value> {
    if matches!(
        original,
        Value::Object(_) | Value::Array(_) | Value::Date(_) | Value::Null
    ) {
        original
            .stringify()
            .map(|value| value.map(Value::String).unwrap_or_default())
    } else {
        Ok(value)
    }
}

impl EphemeralStore {
    pub(super) fn organization_query(
        &self,
        role: EntityRole,
        name: &str,
        value: Value,
    ) -> AuthResult<crate::SchemaValue<String>> {
        self.model_fields.begin_id_query(role)?;
        if name == "id" {
            return self
                .memory_primary_id_query(&value)
                .map(crate::SchemaValue::from_field);
        }
        let value = self.memory_field_query(&self.field_config(role)?, name, value)?;
        Ok(crate::SchemaValue::from_field(value))
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
            .then(|| value.clone());
        let value = if field.is_some_and(|field| self.uses_serial_reference(field)) {
            crate::id::serial_reference_query_value(value)?
        } else {
            value
        };
        let value = match field {
            Some(field) => crate::user_query::bind_filter(field, &value)?,
            None => value,
        };
        // Query JSON conversion follows reference conversion and uses the original query value.
        match original_json {
            Some(original) => memory_json_query_value(value, &original),
            None => Ok(value),
        }
    }

    pub(super) fn memory_primary_id_query(&self, value: &Value) -> AuthResult<Value> {
        self.config
            .advanced
            .database
            .generate_id()
            .adapter_id_query(value.clone())
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

    pub(super) fn memory_session_token_query(&self, value: Value) -> AuthResult<(String, Value)> {
        self.memory_session_field_query("token", value)
    }

    pub(super) fn memory_session_field_query(
        &self,
        name: &str,
        value: Value,
    ) -> AuthResult<(String, Value)> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let schema = crate::store::session_create_schema(&self.session_config, &FieldMap::new());
        if !schema.fields().contains_key(name) {
            return Err(AuthError::config(format!("Unknown session field: {name}")));
        }
        let value = if name == "id" {
            self.memory_primary_id_query(&value)?
        } else {
            self.memory_field_query(&schema, name, value)?
        };
        Ok((schema.record_storage_key(name).to_owned(), value))
    }
}
