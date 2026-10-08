use super::*;
use better_auth_core::{
    CreateVerification, UpdateAccount,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
        VerificationUpdate,
    },
    wire::{AccountView, SessionView, UserView, VerificationView},
};

pub(super) struct Hooks(pub(super) Events);

impl Hooks {
    fn record(
        &self,
        model: &str,
        operation: &str,
        phase: &str,
        fields: FieldValue,
    ) -> AuthResult<()> {
        self.0.push(json!({"kind": "hook", "model": model, "operation": operation, "phase": phase, "data": values::observe(&fields)?}))
    }
    fn unexpected(
        &self,
        model: &str,
        operation: &str,
        phase: &str,
        data: &dyn std::fmt::Debug,
    ) -> AuthResult<()> {
        self.0.push(json!({"kind": "unexpected-hook", "model": model, "operation": operation, "phase": phase, "native": format!("{data:?}")}))
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_user(
        &self,
        data: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        self.unexpected("user", "create", "before", &data)?;
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_create_user(
        &self,
        data: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let data = data
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.unexpected("user", "create", "after", &data)?;
        Ok(())
    }
    async fn before_update_user(
        &self,
        data: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<better_auth_core::FieldMap>> {
        self.record("user", "update", "before", data.clone().into())?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        data: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "user",
            "update",
            "after",
            data.cloned()
                .map(FieldMap::from)
                .map_or(FieldValue::Null, Into::into),
        )?;
        Ok(())
    }
    async fn before_delete_user(
        &self,
        data: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("user", "delete", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_user(
        &self,
        data: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("user", "delete", "after", &data)?;
        Ok(())
    }
    async fn before_create_account(
        &self,
        data: &mut CreateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("account", "create", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_account(
        &self,
        data: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let data = data
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.unexpected("account", "create", "after", &data)?;
        Ok(())
    }
    async fn before_update_account(
        &self,
        data: &UpdateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        self.record("account", "update", "before", data.fields()?.into())?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_account(
        &self,
        data: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "account",
            "update",
            "after",
            data.map(AccountView::internal_fields)
                .transpose()?
                .map_or(FieldValue::Null, Into::into),
        )?;
        Ok(())
    }
    async fn before_delete_account(
        &self,
        data: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("account", "delete", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_account(
        &self,
        data: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("account", "delete", "after", &data)?;
        Ok(())
    }
    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("session", "create", "before", data.clone().into())?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let data = data
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.record(
            "session",
            "create",
            "after",
            FieldMap::from(data.clone()).into(),
        )?;
        Ok(())
    }
    async fn before_update_session(
        &self,
        data: &SessionUpdate,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        self.unexpected(
            "session",
            "update",
            "before",
            &(
                &data.id,
                &data.token,
                &data.user_id,
                &data.expires_at,
                &data.created_at,
                &data.updated_at,
                &data.ip_address,
                &data.user_agent,
                &data.impersonated_by,
                &data.active_organization_id,
                &data.active_team_id,
                &data.additional_fields,
            ),
        )?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("session", "update", "after", &data)?;
        Ok(())
    }
    async fn before_delete_session(
        &self,
        data: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("session", "delete", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        data: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("session", "delete", "after", &data)?;
        Ok(())
    }
    async fn before_create_verification(
        &self,
        data: &mut CreateVerification,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("verification", "create", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        data: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let data = data
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.unexpected("verification", "create", "after", &data)?;
        Ok(())
    }
    async fn before_update_verification(
        &self,
        data: &VerificationUpdate,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        self.unexpected("verification", "update", "before", &data)?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_verification(
        &self,
        data: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("verification", "update", "after", &data)?;
        Ok(())
    }
    async fn before_delete_verification(
        &self,
        data: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.unexpected("verification", "delete", "before", &data)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        data: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.unexpected("verification", "delete", "after", &data)?;
        Ok(())
    }
}
