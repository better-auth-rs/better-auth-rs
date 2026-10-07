//! Bridge configured username fields to the application-owned typed user record.

use crate::store::schema::resolve_field_name;
use crate::{FieldMap, FieldValue as Value};

use super::{UserConfig, UserFieldConfig};
use crate::{AuthResult, CreateUser, UpdateUser};

pub(crate) const USER_FIELDS: &[&str] = &[
    "name",
    "email",
    "emailVerified",
    "image",
    "createdAt",
    "updatedAt",
];

fn take_field(fields: &mut FieldMap, name: &str) -> AuthResult<Option<Option<String>>> {
    fields.remove(name).map(|value| value.decode()).transpose()
}

fn prepare(
    config: &UserConfig,
    fields: &mut FieldMap,
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
                *target = crate::SchemaValue::from_field(value);
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
    pub fn assign_user_fields(&mut self, mut fields: FieldMap) -> AuthResult<()> {
        if let Some(value) = take_field(&mut fields, "username")? {
            self.username = Some(value);
        }
        if let Some(value) = take_field(&mut fields, "displayUsername")? {
            self.display_username = Some(value);
        }
        if let Some(value) = fields.remove("name") {
            self.name = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = fields.remove("image") {
            self.image = crate::SchemaValue::from_field(value);
        }
        self.additional_fields = fields;
        Ok(())
    }

    /// Move configured typed values into the shared adapter input before applying storage policies.
    pub fn take_user_field_input(&mut self, config: &UserConfig) -> AuthResult<FieldMap> {
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
            if config.fields().contains_key(name) && !value.is_undefined() {
                let _ = fields.insert(name.into(), std::mem::take(value).into_field_value());
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
                *target = crate::SchemaValue::from_field(value);
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
    pub fn assign_user_fields(&mut self, mut fields: FieldMap) -> AuthResult<()> {
        if let Some(value) = take_field(&mut fields, "username")? {
            self.username = Some(value);
        }
        if let Some(value) = take_field(&mut fields, "displayUsername")? {
            self.display_username = Some(value);
        }
        if let Some(value) = fields.remove("name") {
            self.name = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = fields.remove("image") {
            self.image = crate::SchemaValue::from_field(value);
        }
        self.additional_fields = fields;
        Ok(())
    }

    /// Move the final hook-adjusted fields into the adapter input once.
    pub fn take_user_field_input(&mut self, config: &UserConfig) -> AuthResult<FieldMap> {
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
            if config.fields().contains_key(name) && !value.is_undefined() {
                let _ = fields.insert(name.into(), std::mem::take(value).into_field_value());
            }
        }
        Ok(fields)
    }
}

impl UserConfig {
    /// Resolve User schema order and replace the adapter-owned ID policy.
    #[doc(hidden)]
    pub fn user_adapter_fields(&self) -> Self {
        let mut fields = self.adapter_fields(USER_FIELDS);
        if !self.fields().contains_key("id") {
            let _ = fields.fields_mut().shift_remove("id");
        }
        fields
    }

    /// Apply User input policies and generate the ID at its effective schema position.
    #[doc(hidden)]
    pub async fn create_user_storage_fields<I>(
        &self,
        input: FieldMap,
        generate_id: impl FnMut() -> AuthResult<Option<I>>,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<(FieldMap, Option<I>)> {
        self.user_adapter_fields()
            .create_adapter_storage_fields(input, generate_id, bind)
            .await
    }

    /// Read one stored username field for the implicit adapter's typed columns.
    /// Keep the storage entry so output transforms can observe the original stored value once.
    pub fn stored_username_field(
        &self,
        fields: &FieldMap,
        name: &str,
    ) -> AuthResult<Option<Option<String>>> {
        let Some(config) = self.fields().get(name) else {
            return Ok(None);
        };
        fields
            .get(resolve_field_name(config.field_name.as_deref(), name))
            .cloned()
            .map(|value| value.decode())
            .transpose()
    }
}
