//! Convert convenience inputs once before hooks and ordered adapter policies.

use crate::{
    AuthError, AuthResult, CreateUser, FieldMap, FieldValue as Value, SchemaField, UpdateUser,
};

pub(crate) const USER_FIELDS: &[&str] = &[
    "name",
    "email",
    "emailVerified",
    "image",
    "createdAt",
    "updatedAt",
];

macro_rules! insert_optional {
    ($fields:ident, $input:ident, $($field:ident => $name:literal),* $(,)?) => {
        $(if let Some(value) = $input.$field {
            let _ = $fields.insert($name.into(), value.into_field());
        })*
    };
}

fn normalize_email(fields: &mut FieldMap, create: bool) -> AuthResult<()> {
    let email = fields.get("email").cloned().unwrap_or_default();
    if !create && !email.is_truthy() {
        return Ok(());
    }
    let value = match email {
        Value::Undefined | Value::Null if create => Value::Undefined,
        Value::String(text) => text.to_lowercase().into(),
        Value::Utf16String(text) => text.to_lowercase().into(),
        _ => {
            return Err(AuthError::internal(
                "user.email.toLowerCase is not a function",
            ));
        }
    };
    let _ = fields.insert("email".into(), value);
    Ok(())
}

impl CreateUser {
    /// Preserve parsed values until the adapter consumes the complete input object.
    pub fn assign_user_fields(&mut self, fields: FieldMap) -> AuthResult<()> {
        self.additional_fields.extend(fields);
        Ok(())
    }

    /// Apply internal-adapter defaults and email normalization before creation hooks.
    pub fn into_user_fields(self) -> AuthResult<FieldMap> {
        let mut fields: FieldMap = [
            ("createdAt".into(), chrono::Utc::now().into()),
            ("updatedAt".into(), chrono::Utc::now().into()),
        ]
        .into();
        insert_optional!(fields, self,
            created_at => "createdAt", updated_at => "updatedAt", id => "id",
            email => "email", email_verified => "emailVerified", username => "username",
            display_username => "displayUsername", is_anonymous => "isAnonymous",
            phone_number => "phoneNumber", phone_number_verified => "phoneNumberVerified",
            role => "role", banned => "banned", ban_reason => "banReason",
            ban_expires => "banExpires", metadata => "metadata",
        );
        for (name, value) in [("name", self.name), ("image", self.image)] {
            if !value.is_undefined() {
                let _ = fields.insert(name.into(), value.into_field_value());
            }
        }
        fields.extend(self.additional_fields);
        normalize_email(&mut fields, true)?;
        fields.sort_property_order();
        Ok(fields)
    }
}

impl UpdateUser {
    /// Preserve parsed fields, including explicit null and own-undefined properties.
    pub fn assign_user_fields(&mut self, fields: FieldMap) -> AuthResult<()> {
        self.additional_fields.extend(fields);
        Ok(())
    }

    /// Normalize only a truthy email before update hooks inspect the original object.
    pub fn into_user_fields(self) -> AuthResult<FieldMap> {
        let mut fields = FieldMap::new();
        insert_optional!(fields, self,
            email => "email", email_verified => "emailVerified", username => "username",
            display_username => "displayUsername", is_anonymous => "isAnonymous",
            phone_number => "phoneNumber", phone_number_verified => "phoneNumberVerified",
            role => "role", banned => "banned", ban_reason => "banReason",
            ban_expires => "banExpires", two_factor_enabled => "twoFactorEnabled", metadata => "metadata",
        );
        for (name, value) in [("name", self.name), ("image", self.image)] {
            if !value.is_undefined() {
                let _ = fields.insert(name.into(), value.into_field_value());
            }
        }
        fields.extend(self.additional_fields);
        normalize_email(&mut fields, false)?;
        fields.sort_property_order();
        Ok(fields)
    }
}
