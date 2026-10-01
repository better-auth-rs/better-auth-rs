use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction};

use better_auth_core::AuthResult;
use better_auth_core::config::AuthConfig;
use better_auth_core::hooks::RequestHookContext;
pub use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::schema::AuthSchema;
pub use better_auth_core::store::database_hooks::{
    DatabaseHookUpdate, SessionUpdate, VerificationUpdate,
};
use better_auth_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};

/// Control flow returned by SeaORM `before_*` hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookControl {
    Continue,
    Cancel,
}

impl HookControl {
    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancel)
    }
}

/// Context passed to SeaORM lifecycle hooks.
pub struct SeaOrmHookContext<'a, S: AuthSchema> {
    pub config: &'a AuthConfig,
    pub db: &'a DatabaseConnection,
    pub tx: Option<&'a DatabaseTransaction>,
    /// The same transaction exposed through the adapter-independent store API.
    pub transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
    pub request: Option<RequestHookContext>,
}

/// SeaORM lifecycle hooks for intercepting auth writes.
#[async_trait]
pub trait SeaOrmHooks<S: AuthSchema>: Send + Sync {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_update_user(
        &self,
        id: &str,
        update: &UpdateUser,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        let _ = (id, update, ctx);
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_user(
        &self,
        user: Option<&S::User>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_delete_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn before_update_session(
        &self,
        token: &str,
        update: &SessionUpdate,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        let _ = (token, update, ctx);
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_session(
        &self,
        session: Option<&S::Session>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn after_delete_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        account: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_update_account(
        &self,
        id: &str,
        update: &UpdateAccount,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        let _ = (id, update, ctx);
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_account(
        &self,
        account: Option<&better_auth_core::wire::AccountView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_delete_account(
        &self,
        account: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        account: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_create_verification(
        &self,
        verification: &mut CreateVerification,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        verification: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        verification: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn before_update_verification(
        &self,
        identifier: &str,
        update: &VerificationUpdate,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        let _ = (identifier, update, ctx);
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_verification(
        &self,
        verification: Option<&better_auth_core::wire::VerificationView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }

    async fn after_delete_verification(
        &self,
        verification: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }
}
