//! Native adapter inputs preserve explicit null, replacement types, and omission.
use crate::{AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

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
    pub access_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    pub refresh_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<DateTime<Utc>>,
    pub updated_at: SchemaValue<DateTime<Utc>>,
    pub additional_fields: Map<String, Value>,
}

impl CreateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<Map<String, Value>> {
        let mut fields = self.additional_fields.clone();
        if let Some(value) = self.id.json()? {
            let _ = fields.insert("id".into(), value);
        }
        if let Some(value) = self.account_id.json()? {
            let _ = fields.insert("accountId".into(), value);
        }
        if let Some(value) = self.provider_id.json()? {
            let _ = fields.insert("providerId".into(), value);
        }
        if let Some(value) = self.user_id.json()? {
            let _ = fields.insert("userId".into(), value);
        }
        if let Some(value) = self.access_token.json()? {
            let _ = fields.insert("accessToken".into(), value);
        }
        if let Some(value) = self.refresh_token.json()? {
            let _ = fields.insert("refreshToken".into(), value);
        }
        if let Some(value) = self.id_token.json()? {
            let _ = fields.insert("idToken".into(), value);
        }
        if let Some(value) = self.access_token_expires_at.json()? {
            let _ = fields.insert("accessTokenExpiresAt".into(), value);
        }
        if let Some(value) = self.refresh_token_expires_at.json()? {
            let _ = fields.insert("refreshTokenExpiresAt".into(), value);
        }
        if let Some(value) = self.scope.json()? {
            let _ = fields.insert("scope".into(), value);
        }
        if let Some(value) = self.password.json()? {
            let _ = fields.insert("password".into(), value);
        }
        if let Some(value) = self.created_at.json()? {
            let _ = fields.insert("createdAt".into(), value);
        }
        if let Some(value) = self.updated_at.json()? {
            let _ = fields.insert("updatedAt".into(), value);
        }
        Ok(fields)
    }
    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: DateTime<Utc>) -> Self {
        if self.created_at.is_undefined() {
            self.created_at = now.into();
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
    pub access_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    pub refresh_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<DateTime<Utc>>,
    pub updated_at: SchemaValue<DateTime<Utc>>,
    pub additional_fields: Map<String, Value>,
}

impl UpdateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<Map<String, Value>> {
        let mut fields = self.additional_fields.clone();
        if let Some(value) = self.id.json()? {
            let _ = fields.insert("id".into(), value);
        }
        if let Some(value) = self.account_id.json()? {
            let _ = fields.insert("accountId".into(), value);
        }
        if let Some(value) = self.provider_id.json()? {
            let _ = fields.insert("providerId".into(), value);
        }
        if let Some(value) = self.user_id.json()? {
            let _ = fields.insert("userId".into(), value);
        }
        if let Some(value) = self.access_token.json()? {
            let _ = fields.insert("accessToken".into(), value);
        }
        if let Some(value) = self.refresh_token.json()? {
            let _ = fields.insert("refreshToken".into(), value);
        }
        if let Some(value) = self.id_token.json()? {
            let _ = fields.insert("idToken".into(), value);
        }
        if let Some(value) = self.access_token_expires_at.json()? {
            let _ = fields.insert("accessTokenExpiresAt".into(), value);
        }
        if let Some(value) = self.refresh_token_expires_at.json()? {
            let _ = fields.insert("refreshTokenExpiresAt".into(), value);
        }
        if let Some(value) = self.scope.json()? {
            let _ = fields.insert("scope".into(), value);
        }
        if let Some(value) = self.password.json()? {
            let _ = fields.insert("password".into(), value);
        }
        if let Some(value) = self.created_at.json()? {
            let _ = fields.insert("createdAt".into(), value);
        }
        if let Some(value) = self.updated_at.json()? {
            let _ = fields.insert("updatedAt".into(), value);
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
    pub expires_at: SchemaValue<DateTime<Utc>>,
    pub created_at: SchemaValue<DateTime<Utc>>,
    pub updated_at: SchemaValue<DateTime<Utc>>,
    pub additional_fields: Map<String, Value>,
}

impl CreateVerification {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<Map<String, Value>> {
        let mut fields = self.additional_fields.clone();
        if let Some(value) = self.id.json()? {
            let _ = fields.insert("id".into(), value);
        }
        if let Some(value) = self.identifier.json()? {
            let _ = fields.insert("identifier".into(), value);
        }
        if let Some(value) = self.value.json()? {
            let _ = fields.insert("value".into(), value);
        }
        if let Some(value) = self.expires_at.json()? {
            let _ = fields.insert("expiresAt".into(), value);
        }
        if let Some(value) = self.created_at.json()? {
            let _ = fields.insert("createdAt".into(), value);
        }
        if let Some(value) = self.updated_at.json()? {
            let _ = fields.insert("updatedAt".into(), value);
        }
        Ok(fields)
    }
    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: DateTime<Utc>) -> Self {
        if self.created_at.is_undefined() {
            self.created_at = now.into();
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
    pub expires_at: SchemaValue<DateTime<Utc>>,
    pub created_at: SchemaValue<DateTime<Utc>>,
    pub updated_at: SchemaValue<DateTime<Utc>>,
    pub additional_fields: Map<String, Value>,
}

impl VerificationUpdate {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<Map<String, Value>> {
        let mut fields = self.additional_fields.clone();
        if let Some(value) = self.id.json()? {
            let _ = fields.insert("id".into(), value);
        }
        if let Some(value) = self.identifier.json()? {
            let _ = fields.insert("identifier".into(), value);
        }
        if let Some(value) = self.value.json()? {
            let _ = fields.insert("value".into(), value);
        }
        if let Some(value) = self.expires_at.json()? {
            let _ = fields.insert("expiresAt".into(), value);
        }
        if let Some(value) = self.created_at.json()? {
            let _ = fields.insert("createdAt".into(), value);
        }
        if let Some(value) = self.updated_at.json()? {
            let _ = fields.insert("updatedAt".into(), value);
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
