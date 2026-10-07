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

/// Partial update passed to database hooks before adapter field policies.
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
    /// Merge only supplied fields; undefined retains the previous patch value.
    pub fn merge(&mut self, patch: Self) {
        if !patch.id.is_undefined() {
            self.id = patch.id;
        }
        if !patch.account_id.is_undefined() {
            self.account_id = patch.account_id;
        }
        if !patch.provider_id.is_undefined() {
            self.provider_id = patch.provider_id;
        }
        if !patch.user_id.is_undefined() {
            self.user_id = patch.user_id;
        }
        if !patch.access_token.is_undefined() {
            self.access_token = patch.access_token;
        }
        if !patch.refresh_token.is_undefined() {
            self.refresh_token = patch.refresh_token;
        }
        if !patch.id_token.is_undefined() {
            self.id_token = patch.id_token;
        }
        if !patch.access_token_expires_at.is_undefined() {
            self.access_token_expires_at = patch.access_token_expires_at;
        }
        if !patch.refresh_token_expires_at.is_undefined() {
            self.refresh_token_expires_at = patch.refresh_token_expires_at;
        }
        if !patch.scope.is_undefined() {
            self.scope = patch.scope;
        }
        if !patch.password.is_undefined() {
            self.password = patch.password;
        }
        if !patch.created_at.is_undefined() {
            self.created_at = patch.created_at;
        }
        if !patch.updated_at.is_undefined() {
            self.updated_at = patch.updated_at;
        }
        self.additional_fields.extend(patch.additional_fields);
    }
}

/// Creation input passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct CreateVerification {
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
    /// Merge only supplied fields; undefined retains the previous patch value.
    pub fn merge(&mut self, patch: Self) {
        if !patch.id.is_undefined() {
            self.id = patch.id;
        }
        if !patch.identifier.is_undefined() {
            self.identifier = patch.identifier;
        }
        if !patch.value.is_undefined() {
            self.value = patch.value;
        }
        if !patch.expires_at.is_undefined() {
            self.expires_at = patch.expires_at;
        }
        if !patch.created_at.is_undefined() {
            self.created_at = patch.created_at;
        }
        if !patch.updated_at.is_undefined() {
            self.updated_at = patch.updated_at;
        }
        self.additional_fields.extend(patch.additional_fields);
    }
}
