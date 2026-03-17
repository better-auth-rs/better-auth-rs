use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction};

use crate::config::AuthConfig;
use crate::error::AuthResult;
use crate::types::{
    Account, AuthRequest, CreateAccount, CreateSession, CreateUser, CreateVerification, HttpMethod,
    RequestMeta, Session, UpdateAccount, UpdateUser, User, Verification,
};

/// Control flow returned by database `before_*` hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookControl {
    /// Continue the database operation.
    Continue,
    /// Cancel the database operation without performing the write.
    Cancel,
}

impl HookControl {
    /// Returns `true` when the hook requested cancellation.
    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancel)
    }
}

/// Request-derived data available to database hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    pub method: HttpMethod,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub query: std::collections::HashMap<String, String>,
    pub meta: RequestMeta,
}

impl RequestHookContext {
    /// Build a request hook context from an incoming auth request.
    pub fn from_request(request: &AuthRequest) -> Self {
        Self {
            method: request.method().clone(),
            path: request.path().to_string(),
            headers: request.headers.clone(),
            query: request.query.clone(),
            meta: RequestMeta::from_request(request),
        }
    }
}

/// Context passed to database lifecycle hooks.
pub struct DatabaseHookContext<'a> {
    pub config: &'a AuthConfig,
    pub db: &'a DatabaseConnection,
    pub tx: Option<&'a DatabaseTransaction>,
    pub request: Option<RequestHookContext>,
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: RequestHookContext;
}

/// Run a future with request context available to database hooks.
pub async fn with_request_hook_context<T>(
    request: &AuthRequest,
    future: impl std::future::Future<Output = T>,
) -> T {
    with_request_hook_context_value(RequestHookContext::from_request(request), future).await
}

/// Run a future with an explicit request hook context.
pub async fn with_request_hook_context_value<T>(
    request_context: RequestHookContext,
    future: impl std::future::Future<Output = T>,
) -> T {
    REQUEST_HOOK_CONTEXT.scope(request_context, future).await
}

pub(crate) fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT.try_with(Clone::clone).ok()
}

/// Database lifecycle hooks for intercepting core auth writes.
///
/// The default implementations are no-ops. Returning [`HookControl::Cancel`]
/// from a `before_*` hook aborts that write without running the main query or
/// the corresponding `after_*` hooks.
#[async_trait]
pub trait DatabaseHooks: Send + Sync {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        user: &User,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_update_user(
        &self,
        id: &str,
        update: &mut UpdateUser,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        user: &User,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_delete_user(
        &self,
        user: &User,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        user: &User,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &Session,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        session: &Session,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &Session,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        account: &Account,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_update_account(
        &self,
        id: &str,
        update: &mut UpdateAccount,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_account(
        &self,
        account: &Account,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_delete_account(
        &self,
        account: &Account,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        account: &Account,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_create_verification(
        &self,
        verification: &mut CreateVerification,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        verification: &Verification,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        verification: &Verification,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        verification: &Verification,
        ctx: &DatabaseHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }
}
