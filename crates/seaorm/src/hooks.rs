use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction};

use better_auth_core::AuthResult;
use better_auth_core::config::AuthConfig;
use better_auth_core::hooks::RequestHookContext;
pub use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::schema::AuthSchema;
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
pub struct SeaOrmHookContext<'a> {
    pub config: &'a AuthConfig,
    pub db: &'a DatabaseConnection,
    pub tx: Option<&'a DatabaseTransaction>,
    pub request: Option<RequestHookContext>,
}

/// SeaORM lifecycle hooks for intercepting auth writes.
#[async_trait]
pub trait SeaOrmHooks<S: AuthSchema>: Send + Sync {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_update_user(
        &self,
        id: &str,
        update: &mut UpdateUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_delete_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        user: &S::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &S::Session,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        account: &S::Account,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_update_account(
        &self,
        id: &str,
        update: &mut UpdateAccount,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_account(
        &self,
        account: &S::Account,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_delete_account(
        &self,
        account: &S::Account,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        account: &S::Account,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_create_verification(
        &self,
        verification: &mut CreateVerification,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        verification: &S::Verification,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        verification: &S::Verification,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        verification: &S::Verification,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }
}
