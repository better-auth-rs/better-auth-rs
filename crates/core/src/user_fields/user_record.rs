//! Bridge configured username fields to the application-owned typed user record.

use serde_json::{Map, Value};

use super::UserConfig;
use crate::{AuthResult, CreateUser, UpdateUser};

fn take_field(fields: &mut Map<String, Value>, name: &str) -> AuthResult<Option<Option<String>>> {
    fields
        .remove(name)
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

fn prepare(
    config: &UserConfig,
    fields: &mut Map<String, Value>,
    username: &mut Option<Option<String>>,
    display_username: &mut Option<Option<String>>,
) -> AuthResult<()> {
    for (name, target) in [
        ("username", username),
        ("displayUsername", display_username),
    ] {
        if config.fields().contains_key(name)
            && let Some(value) = take_field(fields, name)?
        {
            *target = Some(value);
        }
    }
    Ok(())
}

impl CreateUser {
    /// Bind configured fields from trusted adapter input before database hooks inspect the record.
    pub fn prepare_user_fields(&mut self, config: &UserConfig) -> AuthResult<()> {
        for (name, target) in [("name", &mut self.name), ("image", &mut self.image)] {
            if config.fields().contains_key(name)
                && let Some(value) = self.additional_fields.remove(name)
            {
                *target = crate::SchemaValue::from_json(Some(value));
            }
        }
        prepare(
            config,
            &mut self.additional_fields,
            &mut self.username,
            &mut self.display_username,
        )
    }

    /// Assign parsed endpoint fields without performing another transform or validation.
    pub fn assign_user_fields(&mut self, mut fields: Map<String, Value>) -> AuthResult<()> {
        if let Some(value) = take_field(&mut fields, "username")? {
            self.username = Some(value);
        }
        if let Some(value) = take_field(&mut fields, "displayUsername")? {
            self.display_username = Some(value);
        }
        if let Some(value) = fields.remove("name") {
            self.name = crate::SchemaValue::from_json(Some(value));
        }
        if let Some(value) = fields.remove("image") {
            self.image = crate::SchemaValue::from_json(Some(value));
        }
        self.additional_fields = fields;
        Ok(())
    }

    /// Move configured typed values into the shared adapter input before applying storage policies.
    pub fn take_user_field_input(&mut self, config: &UserConfig) -> AuthResult<Map<String, Value>> {
        let mut fields = std::mem::take(&mut self.additional_fields);
        for (name, value) in [
            ("username", &mut self.username),
            ("displayUsername", &mut self.display_username),
        ] {
            if config.fields().contains_key(name)
                && let Some(value) = value.take()
            {
                let _ = fields.insert(name.into(), value.map(Value::String).unwrap_or(Value::Null));
            }
        }
        for (name, value) in [("name", &mut self.name), ("image", &mut self.image)] {
            if config.fields().contains_key(name)
                && let Some(raw) = std::mem::take(value).json()?
            {
                let _ = fields.insert(name.into(), raw);
            }
        }
        Ok(fields)
    }
}

impl UpdateUser {
    /// Bind configured fields from a trusted patch before merging database hook results.
    pub fn prepare_user_fields(&mut self, config: &UserConfig) -> AuthResult<()> {
        for (name, target) in [("name", &mut self.name), ("image", &mut self.image)] {
            if config.fields().contains_key(name)
                && let Some(value) = self.additional_fields.remove(name)
            {
                *target = crate::SchemaValue::from_json(Some(value));
            }
        }
        prepare(
            config,
            &mut self.additional_fields,
            &mut self.username,
            &mut self.display_username,
        )
    }

    /// Assign parsed fields while retaining explicit null updates.
    pub fn assign_user_fields(&mut self, mut fields: Map<String, Value>) -> AuthResult<()> {
        if let Some(value) = take_field(&mut fields, "username")? {
            self.username = Some(value);
        }
        if let Some(value) = take_field(&mut fields, "displayUsername")? {
            self.display_username = Some(value);
        }
        if let Some(value) = fields.remove("name") {
            self.name = crate::SchemaValue::from_json(Some(value));
        }
        if let Some(value) = fields.remove("image") {
            self.image = crate::SchemaValue::from_json(Some(value));
        }
        self.additional_fields = fields;
        Ok(())
    }

    /// Move the final hook-adjusted fields into the adapter input once.
    pub fn take_user_field_input(&mut self, config: &UserConfig) -> AuthResult<Map<String, Value>> {
        let mut fields = std::mem::take(&mut self.additional_fields);
        for (name, value) in [
            ("username", &mut self.username),
            ("displayUsername", &mut self.display_username),
        ] {
            if config.fields().contains_key(name)
                && let Some(value) = value.take()
            {
                let _ = fields.insert(name.into(), value.map(Value::String).unwrap_or(Value::Null));
            }
        }
        for (name, value) in [("name", &mut self.name), ("image", &mut self.image)] {
            if config.fields().contains_key(name)
                && let Some(raw) = std::mem::take(value).json()?
            {
                let _ = fields.insert(name.into(), raw);
            }
        }
        Ok(fields)
    }
}

impl UserConfig {
    /// Read one stored username field for the implicit adapter's typed columns.
    /// Keep the storage entry so output transforms can observe the original stored value once.
    pub fn stored_username_field(
        &self,
        fields: &Map<String, Value>,
        name: &str,
    ) -> AuthResult<Option<Option<String>>> {
        let Some(config) = self.fields().get(name) else {
            return Ok(None);
        };
        fields
            .get(config.field_name.as_deref().unwrap_or(name))
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }
}
