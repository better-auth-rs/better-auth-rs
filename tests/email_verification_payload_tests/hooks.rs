use super::*;
use better_auth_core::{
    CreateAccount, CreateVerification, FieldMap, UpdateAccount, UpdateUser,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
        VerificationUpdate,
    },
    wire::{AccountView, SessionView, VerificationView},
};

pub(super) struct DatabaseObserver(pub(super) Events);

impl DatabaseObserver {
    fn record(&self, model: &str, operation: &str, phase: &str) -> AuthResult<()> {
        self.0.push(json!({
            "kind": "hook", "model": model, "operation": operation, "phase": phase,
        }))
    }
}

#[better_auth::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for DatabaseObserver {
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
        _: &UpdateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        self.record("account", "update", "before")?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_account(
        &self,
        _: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("account", "update", "after")
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
        _: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("session", "create", "before")?;
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

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DatabaseObserver {
    fn name(&self) -> &'static str {
        "email-payload-database-observer"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(Self(self.0.clone())));
        Ok(())
    }
}
