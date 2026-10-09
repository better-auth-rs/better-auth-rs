use super::*;
use better_auth_core::{
    CreateVerification, UpdateAccount,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
        VerificationUpdate,
    },
    wire::{AccountView, SessionView, UserView, VerificationView},
};

pub(super) struct Hooks {
    pub(super) events: Events,
    pub(super) recording: Arc<AtomicBool>,
}

impl Hooks {
    fn record(&self, model: &str, operation: &str, phase: &str) -> AuthResult<()> {
        if self.recording.load(Ordering::SeqCst) {
            self.events.push(json!({
                "kind": "hook", "model": model, "operation": operation, "phase": phase,
            }))?;
        }
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_user(
        &self,
        _: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        self.record("user", "create", "before")?;
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }

    async fn after_create_user(
        &self,
        _: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user", "create", "after")
    }

    async fn before_update_user(
        &self,
        _: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<better_auth_core::FieldMap>> {
        self.record("user", "update", "before")?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_user(
        &self,
        _: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user", "update", "after")
    }

    async fn before_delete_user(
        &self,
        _: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("user", "delete", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        _: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user", "delete", "after")
    }

    async fn before_create_account(
        &self,
        _: &mut CreateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("account", "create", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_account(
        &self,
        _: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("account", "create", "after")
    }

    async fn before_update_account(
        &self,
        data: &UpdateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        self.events.push(json!({"kind": "hook", "model": "account", "operation": "update", "phase": "before", "data": values::observe(&data.fields()?.into())?}))?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_account(
        &self,
        data: better_auth_core::store::database_hooks::DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let fields = match data {
            better_auth_core::store::database_hooks::DatabaseUpdateResult::One(data) => data
                .map(AccountView::internal_fields)
                .transpose()?
                .map_or(FieldValue::Null, Into::into),
            better_auth_core::store::database_hooks::DatabaseUpdateResult::Many(count) => {
                FieldValue::Number(count as f64)
            }
        };
        self.events.push(json!({"kind": "hook", "model": "account", "operation": "update", "phase": "after", "data": values::observe(&fields)?}))
    }

    async fn before_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("account", "delete", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("account", "delete", "after")
    }

    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        if self.recording.load(Ordering::SeqCst) {
            self.events.push(json!({"kind":"hook", "model":"session", "operation":"create", "phase":"before", "data": values::observe(&data.clone().into())?}))?;
        }
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let data = data
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.events.push(json!({"kind":"hook", "model":"session", "operation":"create", "phase":"after", "data": values::observe(&FieldMap::from(data.clone()).into())?}))
    }

    async fn before_update_session(
        &self,
        _: &SessionUpdate,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        self.record("session", "update", "before")?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_session(
        &self,
        _: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session", "update", "after")
    }

    async fn before_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("session", "delete", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session", "delete", "after")
    }

    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("verification", "create", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        _: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("verification", "create", "after")
    }

    async fn before_update_verification(
        &self,
        _: &VerificationUpdate,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        self.record("verification", "update", "before")?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_verification(
        &self,
        _: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("verification", "update", "after")
    }

    async fn before_delete_verification(
        &self,
        data: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.events.push(json!({"kind":"hook", "model":"verification", "operation":"delete", "phase":"before", "data": values::observe(&data.fields()?.into())?}))?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        data: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events.push(json!({"kind":"hook", "model":"verification", "operation":"delete", "phase":"after", "data": values::observe(&data.fields()?.into())?}))
    }
}
