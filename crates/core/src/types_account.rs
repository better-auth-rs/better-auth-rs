//! Native adapter inputs preserve explicit null, replacement types, and omission.
use crate::{AuthResult, SchemaValue};

/// Creation input passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct CreateAccount {
    pub id: SchemaValue<String>,
    pub account_id: SchemaValue<String>,
    pub provider_id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub access_token: SchemaValue<Option<String>>,
    pub refresh_token: SchemaValue<Option<String>>,
    pub id_token: SchemaValue<Option<String>>,
    pub access_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub refresh_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl CreateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        let mut fields = self.additional_fields.clone();
        if !self.id.is_undefined() {
            let _ = fields.insert("id".into(), self.id.field_value());
        }
        if !self.account_id.is_undefined() {
            let _ = fields.insert("accountId".into(), self.account_id.field_value());
        }
        if !self.provider_id.is_undefined() {
            let _ = fields.insert("providerId".into(), self.provider_id.field_value());
        }
        if !self.user_id.is_undefined() {
            let _ = fields.insert("userId".into(), self.user_id.field_value());
        }
        if !self.access_token.is_undefined() {
            let _ = fields.insert("accessToken".into(), self.access_token.field_value());
        }
        if !self.refresh_token.is_undefined() {
            let _ = fields.insert("refreshToken".into(), self.refresh_token.field_value());
        }
        if !self.id_token.is_undefined() {
            let _ = fields.insert("idToken".into(), self.id_token.field_value());
        }
        if !self.access_token_expires_at.is_undefined() {
            let _ = fields.insert(
                "accessTokenExpiresAt".into(),
                self.access_token_expires_at.field_value(),
            );
        }
        if !self.refresh_token_expires_at.is_undefined() {
            let _ = fields.insert(
                "refreshTokenExpiresAt".into(),
                self.refresh_token_expires_at.field_value(),
            );
        }
        if !self.scope.is_undefined() {
            let _ = fields.insert("scope".into(), self.scope.field_value());
        }
        if !self.password.is_undefined() {
            let _ = fields.insert("password".into(), self.password.field_value());
        }
        if !self.created_at.is_undefined() {
            let _ = fields.insert("createdAt".into(), self.created_at.field_value());
        }
        if !self.updated_at.is_undefined() {
            let _ = fields.insert("updatedAt".into(), self.updated_at.field_value());
        }
        Ok(fields)
    }
    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: crate::FieldDate) -> Self {
        if self.created_at.is_undefined() {
            self.created_at = now.clone().into();
        }
        if self.updated_at.is_undefined() {
            self.updated_at = now.into();
        }
        self
    }
}

/// Typed update converted to logical fields before database hooks and adapter policies.
#[derive(Debug, Clone, Default)]
pub struct UpdateAccount {
    pub id: SchemaValue<String>,
    pub account_id: SchemaValue<String>,
    pub provider_id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub access_token: SchemaValue<Option<String>>,
    pub refresh_token: SchemaValue<Option<String>>,
    pub id_token: SchemaValue<Option<String>>,
    pub access_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub refresh_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl UpdateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        let mut fields = self.additional_fields.clone();
        if !self.id.is_undefined() {
            let _ = fields.insert("id".into(), self.id.field_value());
        }
        if !self.account_id.is_undefined() {
            let _ = fields.insert("accountId".into(), self.account_id.field_value());
        }
        if !self.provider_id.is_undefined() {
            let _ = fields.insert("providerId".into(), self.provider_id.field_value());
        }
        if !self.user_id.is_undefined() {
            let _ = fields.insert("userId".into(), self.user_id.field_value());
        }
        if !self.access_token.is_undefined() {
            let _ = fields.insert("accessToken".into(), self.access_token.field_value());
        }
        if !self.refresh_token.is_undefined() {
            let _ = fields.insert("refreshToken".into(), self.refresh_token.field_value());
        }
        if !self.id_token.is_undefined() {
            let _ = fields.insert("idToken".into(), self.id_token.field_value());
        }
        if !self.access_token_expires_at.is_undefined() {
            let _ = fields.insert(
                "accessTokenExpiresAt".into(),
                self.access_token_expires_at.field_value(),
            );
        }
        if !self.refresh_token_expires_at.is_undefined() {
            let _ = fields.insert(
                "refreshTokenExpiresAt".into(),
                self.refresh_token_expires_at.field_value(),
            );
        }
        if !self.scope.is_undefined() {
            let _ = fields.insert("scope".into(), self.scope.field_value());
        }
        if !self.password.is_undefined() {
            let _ = fields.insert("password".into(), self.password.field_value());
        }
        if !self.created_at.is_undefined() {
            let _ = fields.insert("createdAt".into(), self.created_at.field_value());
        }
        if !self.updated_at.is_undefined() {
            let _ = fields.insert("updatedAt".into(), self.updated_at.field_value());
        }
        Ok(fields)
    }
}

/// Creation input passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct CreateVerification {
    /// Source property order, independent of the current field values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub identifier: SchemaValue<String>,
    pub value: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl CreateVerification {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        Ok(self.native_fields().in_field_order(&self.field_order))
    }

    fn native_fields(&self) -> crate::FieldMap {
        let mut fields = self.additional_fields.clone();
        if !self.id.is_undefined()
            || (!fields.contains_key("id") && self.field_order.iter().any(|name| name == "id"))
        {
            let _ = fields.insert("id".into(), self.id.field_value());
        }
        if !self.identifier.is_undefined()
            || (!fields.contains_key("identifier")
                && self.field_order.iter().any(|name| name == "identifier"))
        {
            let _ = fields.insert("identifier".into(), self.identifier.field_value());
        }
        if !self.value.is_undefined()
            || (!fields.contains_key("value")
                && self.field_order.iter().any(|name| name == "value"))
        {
            let _ = fields.insert("value".into(), self.value.field_value());
        }
        if !self.expires_at.is_undefined()
            || (!fields.contains_key("expiresAt")
                && self.field_order.iter().any(|name| name == "expiresAt"))
        {
            let _ = fields.insert("expiresAt".into(), self.expires_at.field_value());
        }
        if !self.created_at.is_undefined()
            || (!fields.contains_key("createdAt")
                && self.field_order.iter().any(|name| name == "createdAt"))
        {
            let _ = fields.insert("createdAt".into(), self.created_at.field_value());
        }
        if !self.updated_at.is_undefined()
            || (!fields.contains_key("updatedAt")
                && self.field_order.iter().any(|name| name == "updatedAt"))
        {
            let _ = fields.insert("updatedAt".into(), self.updated_at.field_value());
        }
        fields
    }
    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: crate::FieldDate) -> Self {
        let original = self.native_fields().in_field_order(&self.field_order);
        self.field_order = ["createdAt", "updatedAt"]
            .into_iter()
            .map(str::to_owned)
            .chain(
                original
                    .keys()
                    .filter(|name| !matches!(name.as_str(), "createdAt" | "updatedAt"))
                    .cloned(),
            )
            .collect();
        if self.created_at.is_undefined() {
            self.created_at = now.clone().into();
        }
        if self.updated_at.is_undefined() {
            self.updated_at = now.into();
        }
        self
    }
}

/// Partial update passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct VerificationUpdate {
    pub id: SchemaValue<String>,
    pub identifier: SchemaValue<String>,
    pub value: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl VerificationUpdate {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        let mut fields = self.additional_fields.clone();
        if !self.id.is_undefined() {
            let _ = fields.insert("id".into(), self.id.field_value());
        }
        if !self.identifier.is_undefined() {
            let _ = fields.insert("identifier".into(), self.identifier.field_value());
        }
        if !self.value.is_undefined() {
            let _ = fields.insert("value".into(), self.value.field_value());
        }
        if !self.expires_at.is_undefined() {
            let _ = fields.insert("expiresAt".into(), self.expires_at.field_value());
        }
        if !self.created_at.is_undefined() {
            let _ = fields.insert("createdAt".into(), self.created_at.field_value());
        }
        if !self.updated_at.is_undefined() {
            let _ = fields.insert("updatedAt".into(), self.updated_at.field_value());
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod verification_create_tests {
    use super::*;

    #[test]
    fn verification_hook_values_keep_timestamp_prefix_and_own_undefined() -> AuthResult<()> {
        let mut input = CreateVerification {
            id: "explicit".into(),
            identifier: "lookup".into(),
            value: "proof".into(),
            expires_at: crate::FieldDate::from_milliseconds(10_000.0).into(),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        input.value = SchemaValue::Undefined;
        input.expires_at = SchemaValue::from_field(crate::FieldValue::Null);
        let fields = input.fields()?;
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "createdAt",
                "updatedAt",
                "id",
                "identifier",
                "value",
                "expiresAt"
            ]
        );
        assert_eq!(fields.get("value"), Some(&crate::FieldValue::Undefined));
        assert_eq!(fields.get("expiresAt"), Some(&crate::FieldValue::Null));
        Ok(())
    }
}
