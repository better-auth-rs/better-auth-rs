use super::*;
use better_auth_core::{
    CreateVerification, UpdateAccount, UpdateUser,
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
        _: &mut CreateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("user", "create", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_user(
        &self,
        _: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user", "create", "after")
    }

    async fn before_update_user(
        &self,
        _: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
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
        _: &AccountView,
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
        data: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let fields = data
            .map(AccountView::internal_fields)
            .transpose()?
            .map_or(FieldValue::Null, Into::into);
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
        self.record("session", "create", "before")?;
        if self.recording.load(Ordering::SeqCst) {
            return Err(AuthError::internal("Refresh must not create a Session"));
        }
        let _ = data.insert("id".into(), "duration-session".into());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session", "create", "after")
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
        _: &VerificationView,
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
        _: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("verification", "delete", "before")?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("verification", "delete", "after")
    }
}
