//! Adapter-independent hooks for application-owned authentication writes.

use crate::hooks::RequestHookContext;
use crate::store::AuthTransaction;
use crate::types::{CreateAccount, CreateVerification};
use crate::{AuthConfig, AuthResult, AuthSchema, FieldMap};
use async_trait::async_trait;

/// Preserve the awaited adapter lookup between hooks and adapter field conversion.
#[doc(hidden)]
pub async fn await_adapter_lookup() {
    crate::user_fields::await_adapter_boundary().await;
}

/// Typed Session update input converted to native fields before database hooks.
#[derive(Clone, Default)]
pub struct SessionUpdate {
    /// Replacement record ID.
    pub id: Option<String>,
    /// Replacement session token.
    pub token: Option<String>,
    /// Replacement owner ID.
    pub user_id: Option<String>,
    /// Replacement expiration time.
    pub expires_at: Option<crate::FieldDate>,
    /// Replacement creation time.
    pub created_at: Option<crate::FieldDate>,
    /// Replacement modification time.
    pub updated_at: Option<crate::FieldDate>,
    /// Set or clear the client IP address.
    pub ip_address: Option<Option<String>>,
    /// Set or clear the user agent.
    pub user_agent: Option<Option<String>>,
    /// Set or clear the impersonating administrator.
    pub impersonated_by: Option<Option<String>>,
    /// Set or clear the active organization.
    pub active_organization_id: Option<Option<String>>,
    /// Set or clear the active team.
    pub active_team_id: Option<Option<String>>,
    /// Application fields keyed by their public names.
    pub additional_fields: crate::FieldMap,
}

pub use crate::types_account::VerificationUpdate;

/// Adapter result supplied to a database update hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum DatabaseUpdateResult<T> {
    /// A single update returns its projected record or no matching record.
    One(Option<T>),
    /// A batch update returns the affected row count without projecting records.
    Many(u64),
}

impl<T> DatabaseUpdateResult<T> {
    /// Borrow the projected record while preserving the batch count.
    pub fn as_ref(&self) -> DatabaseUpdateResult<&T> {
        match self {
            Self::One(value) => DatabaseUpdateResult::One(value.as_ref()),
            Self::Many(count) => DatabaseUpdateResult::Many(*count),
        }
    }
}

/// Ordered hook fields preserve shallow patches and the original object after detachment.
#[doc(hidden)]
pub struct PreparedRecordWrite {
    fields: FieldMap,
    original: Option<FieldMap>,
}

impl PreparedRecordWrite {
    pub fn new(mut fields: FieldMap) -> Self {
        fields.sort_property_order();
        Self {
            fields,
            original: None,
        }
    }

    pub fn fields_mut(&mut self) -> &mut FieldMap {
        &mut self.fields
    }

    /// Update hooks receive the original object even after a preceding hook returns a patch.
    pub fn original_fields_mut(&mut self) -> &mut FieldMap {
        self.original.as_mut().unwrap_or(&mut self.fields)
    }

    /// An empty patch still detaches later property replacements from the original object.
    pub fn apply(&mut self, outcome: DatabaseHookUpdate<FieldMap>) -> bool {
        self.fields.sort_property_order();
        if let Some(original) = &mut self.original {
            original.sort_property_order();
        }
        match outcome {
            DatabaseHookUpdate::Continue => true,
            DatabaseHookUpdate::Cancel => false,
            DatabaseHookUpdate::Patch(patch) => {
                if self.original.is_none() {
                    self.original = Some(self.fields.clone());
                }
                self.fields.extend(patch);
                self.fields.sort_property_order();
                true
            }
        }
    }

    pub fn into_fields(mut self) -> FieldMap {
        self.fields.sort_property_order();
        self.fields
    }

    pub fn into_parts(mut self) -> (FieldMap, FieldMap) {
        self.fields.sort_property_order();
        (
            self.original.unwrap_or_else(|| self.fields.clone()),
            self.fields,
        )
    }
}

/// Continue or cancel the current write before storage changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseHookControl {
    /// Continue the write after all before hooks complete.
    Continue,
    /// Cancel only this write.
    Cancel,
}

/// Outcome of a before-create or before-update hook. A patch contains only the fields to overwrite.
pub enum DatabaseHookUpdate<T> {
    /// Keep the accumulated update unchanged.
    Continue,
    /// Cancel only this update.
    Cancel,
    /// Merge the supplied fields into the accumulated update.
    Patch(T),
}

/// Request and active transaction available to application database hooks.
pub struct DatabaseHookContext<'a, S: AuthSchema> {
    /// Effective authentication configuration.
    pub config: &'a AuthConfig,
    /// Request metadata; absent for a native call without a request scope.
    pub request: Option<RequestHookContext>,
    /// Active transaction before commit. After hooks receive `None`.
    pub transaction: Option<&'a dyn AuthTransaction<S>>,
}

/// Application lifecycle hooks for user, account, session, and verification writes.
#[async_trait]
pub trait DatabaseHooks<S: AuthSchema>: Send + Sync {
    /// Declare actual callback implementations; `#[database_hooks]` generates this method.
    fn hook_metadata(&self) -> crate::observability::database::DatabaseHookMetadata;

    /// Edit a user before creation or cancel the write.
    async fn before_create_user(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed user creation.
    async fn after_create_user(
        &self,
        _data: Option<&crate::wire::UserView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original user update and return a patch or cancellation.
    async fn before_update_user(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed user update.
    async fn after_update_user(
        &self,
        _data: Option<&crate::wire::UserView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Cancel a user deletion before storage changes.
    async fn before_delete_user(
        &self,
        _data: &crate::wire::UserView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed user deletion.
    async fn after_delete_user(
        &self,
        _data: &crate::wire::UserView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Edit an account before creation or cancel the write.
    async fn before_create_account(
        &self,
        _data: &mut CreateAccount,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed account creation.
    async fn after_create_account(
        &self,
        _data: Option<&crate::wire::AccountView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original account update and return a patch or cancellation.
    async fn before_update_account(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed single Account update or a batch affected row count.
    async fn after_update_account(
        &self,
        _data: DatabaseUpdateResult<&crate::wire::AccountView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Cancel an account deletion before storage changes.
    async fn before_delete_account(
        &self,
        _data: &crate::wire::AccountView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed account deletion.
    async fn after_delete_account(
        &self,
        _data: &crate::wire::AccountView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Edit complete public Session fields, including token and dates, before adapter conversion.
    /// A returned patch shallow-copies the record, separating later property edits from its original cache keys.
    async fn before_create_session(
        &self,
        _data: &mut crate::FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<crate::FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed session creation.
    async fn after_create_session(
        &self,
        _data: Option<&crate::wire::SessionView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original session update and return a patch or cancellation.
    async fn before_update_session(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed session update.
    async fn after_update_session(
        &self,
        _data: Option<&crate::wire::SessionView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Cancel a session deletion before storage changes.
    async fn before_delete_session(
        &self,
        _data: &crate::wire::SessionView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed session deletion.
    async fn after_delete_session(
        &self,
        _data: &crate::wire::SessionView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Edit a verification before creation or cancel the write.
    async fn before_create_verification(
        &self,
        _data: &mut CreateVerification,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed verification creation.
    async fn after_create_verification(
        &self,
        _data: Option<&crate::wire::VerificationView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original verification update and return a patch or cancellation.
    async fn before_update_verification(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed verification update.
    async fn after_update_verification(
        &self,
        _data: Option<&crate::wire::VerificationView>,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Cancel a verification deletion before storage changes.
    async fn before_delete_verification(
        &self,
        _data: &crate::wire::VerificationView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed verification deletion.
    async fn after_delete_verification(
        &self,
        _data: &crate::wire::VerificationView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
}

impl SessionUpdate {
    /// Convert typed input once to public fields before hooks, preserving native additional fields and adapter ID precedence.
    pub fn into_public_fields(self) -> AuthResult<crate::FieldMap> {
        let mut fields = self.additional_fields;
        if let Some(id) = self.id {
            let _ = fields.entry("id".into()).or_insert(id.into());
        }
        macro_rules! supplied {
            ($($field:ident => $name:literal),* $(,)?) => {$(
                if let Some(value) = self.$field {
                    let _ = fields.insert($name.into(), crate::SchemaField::into_field(value));
                }
            )*};
        }
        supplied!(
            token => "token", user_id => "userId",
            expires_at => "expiresAt", created_at => "createdAt", updated_at => "updatedAt",
            ip_address => "ipAddress", user_agent => "userAgent",
            impersonated_by => "impersonatedBy", active_organization_id => "activeOrganizationId",
            active_team_id => "activeTeamId",
        );
        Ok(fields)
    }
}
