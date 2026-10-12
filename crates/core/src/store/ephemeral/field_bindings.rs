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
    pub(super) fn memory_query_field(
        &self,
        model: impl Into<crate::plugin_runtime::ModelKey>,
        configured: &UserConfig,
        name: &str,
        value: Value,
    ) -> AuthResult<(String, Value)> {
        let model = model.into();
        let fields = self.model_fields.runtime_fields(&model, configured)?;
        let name = if name == "_id" { "id" } else { name };
        let logical_model = model.logical_name()?;
        let (logical, physical) = if name == "id" {
            (
                "id",
                crate::store::schema::resolve_field_name(
                    fields
                        .fields()
                        .get("id")
                        .and_then(|field| field.field_name.as_deref()),
                    "id",
                ),
            )
        } else {
            let (logical, field) =
                crate::user_query::declared_field(name, &fields).ok_or_else(|| {
                    AuthError::config(format!("Field {name} not found in model {logical_model}"))
                })?;
            (
                logical,
                crate::store::schema::resolve_field_name(field.field_name.as_deref(), logical),
            )
        };
        self.model_fields.begin_id_query(&model)?;
        let value = self.memory_field_query(&fields, logical, value)?;
        Ok((physical.to_owned(), value))
    }

    pub(super) fn organization_query_field(
        &self,
        role: EntityRole,
        name: &str,
        value: Value,
    ) -> AuthResult<(String, Value)> {
        self.memory_query_field(role, &self.field_config(role)?, name, value)
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
        if name == "id" {
            return self.memory_primary_id_query(&value);
        }
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

    pub(super) fn memory_session_token_query(&self, value: Value) -> AuthResult<(String, Value)> {
        self.memory_session_field_query("token", value)
    }

    pub(super) fn memory_session_field_query(
        &self,
        name: &str,
        value: Value,
    ) -> AuthResult<(String, Value)> {
        let schema = self.field_policy().session(&FieldMap::new());
        self.memory_query_field(EntityRole::Session, &schema, name, value)
    }
}
