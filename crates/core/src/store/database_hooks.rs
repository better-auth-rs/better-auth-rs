//! Adapter-independent hooks for application-owned authentication writes.

use crate::hooks::RequestHookContext;
use crate::store::AuthTransaction;
use crate::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};
use crate::{AuthConfig, AuthResult, AuthSchema};
use async_trait::async_trait;

/// Partial session values supplied to update hooks.
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

impl UpdateUser {
    /// Merge supplied fields without replacing fields omitted from the patch.
    pub fn merge(&mut self, patch: Self) {
        macro_rules! fields {
            ($($field:ident),* $(,)?) => {$(if patch.$field.is_some() { self.$field = patch.$field; })*};
        }
        fields!(
            email,
            email_verified,
            username,
            display_username,
            is_anonymous,
            phone_number,
            phone_number_verified,
            role,
            banned,
            ban_reason,
            ban_expires,
            two_factor_enabled,
            metadata
        );
        if !patch.name.is_undefined() {
            self.name = patch.name;
        }
        if !patch.image.is_undefined() {
            self.image = patch.image;
        }
        self.additional_fields.extend(patch.additional_fields);
    }
}

impl SessionUpdate {
    /// Merge supplied fields and shallow-merge application fields.
    pub fn merge(&mut self, patch: Self) {
        macro_rules! fields {
            ($($field:ident),* $(,)?) => {$(if patch.$field.is_some() { self.$field = patch.$field; })*};
        }
        fields!(
            id,
            token,
            user_id,
            expires_at,
            created_at,
            updated_at,
            ip_address,
            user_agent,
            impersonated_by,
            active_organization_id,
            active_team_id
        );
        self.additional_fields.extend(patch.additional_fields);
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

/// Outcome of a before-update hook. A patch contains only the fields to overwrite.
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
        _data: &mut CreateUser,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed user creation.
    async fn after_create_user(
        &self,
        _data: &crate::wire::UserView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original user update and return a patch or cancellation.
    async fn before_update_user(
        &self,
        _data: &UpdateUser,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
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
        _data: &crate::wire::AccountView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original account update and return a patch or cancellation.
    async fn before_update_account(
        &self,
        _data: &UpdateAccount,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    /// Observe a committed account update.
    async fn after_update_account(
        &self,
        _data: Option<&crate::wire::AccountView>,
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

    /// Edit a session before creation or cancel the write.
    async fn before_create_session(
        &self,
        _data: &mut CreateSession,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(DatabaseHookControl::Continue)
    }
    /// Observe a committed session creation.
    async fn after_create_session(
        &self,
        _data: &crate::wire::SessionView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original session update and return a patch or cancellation.
    async fn before_update_session(
        &self,
        _data: &SessionUpdate,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
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
        _data: &crate::wire::VerificationView,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Inspect the original verification update and return a patch or cancellation.
    async fn before_update_verification(
        &self,
        _data: &VerificationUpdate,
        _ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
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
    /// Serialize supplied fields using public names, preserving explicit null values.
    pub fn into_public_fields(self) -> AuthResult<crate::FieldMap> {
        let mut fields = self.additional_fields;
        macro_rules! supplied {
            ($($field:ident => $name:literal),* $(,)?) => {$(
                if let Some(value) = self.$field {
                    let _ = fields.insert($name.into(), crate::SchemaField::into_field(value));
                }
            )*};
        }
        supplied!(
            id => "id", token => "token", user_id => "userId",
            expires_at => "expiresAt", created_at => "createdAt", updated_at => "updatedAt",
            ip_address => "ipAddress", user_agent => "userAgent",
            impersonated_by => "impersonatedBy", active_organization_id => "activeOrganizationId",
            active_team_id => "activeTeamId",
        );
        Ok(fields)
    }
}
