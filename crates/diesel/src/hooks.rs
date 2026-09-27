//! Lifecycle hooks for auth writes made by [`DieselStore`](crate::DieselStore).

use async_trait::async_trait;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

use better_auth_core::config::AuthConfig;
use better_auth_core::hooks::RequestHookContext;
pub use better_auth_core::hooks::{HookControl, current_request_hook_context};
use better_auth_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};
use better_auth_core::{AuthError, AuthResult};

use crate::connection::{DieselConnection, DieselPool};
use crate::models::{Account, Session, User, Verification};

/// The connection that runs one auth write, shared with the hooks of that
/// write.
///
/// Inside a transaction it borrows the transaction's connection. Otherwise
/// it checks a connection out of the pool on first use, so hooks that never
/// touch the database do not hold one.
pub(crate) struct HookConnection<'a> {
    pool: &'a DieselPool,
    in_transaction: bool,
    slot: Mutex<Slot<'a>>,
}

enum Slot<'a> {
    Borrowed(&'a mut DieselConnection),
    Pooled(Option<Box<DieselConnection>>),
}

impl<'a> HookConnection<'a> {
    /// Share the connection of an open transaction.
    pub(crate) fn transaction(pool: &'a DieselPool, connection: &'a mut DieselConnection) -> Self {
        Self {
            pool,
            in_transaction: true,
            slot: Mutex::new(Slot::Borrowed(connection)),
        }
    }

    /// Check a connection out of `pool` when it is first locked.
    pub(crate) fn pooled(pool: &'a DieselPool) -> Self {
        Self {
            pool,
            in_transaction: false,
            slot: Mutex::new(Slot::Pooled(None)),
        }
    }

    pub(crate) fn in_transaction(&self) -> bool {
        self.in_transaction
    }

    pub(crate) async fn lock(&self) -> AuthResult<MappedMutexGuard<'_, DieselConnection>> {
        let mut slot = self.slot.lock().await;
        if let Slot::Pooled(connection @ None) = &mut *slot {
            *connection = Some(Box::new(self.pool.get().await?));
        }
        MutexGuard::try_map(slot, |slot| match slot {
            Slot::Borrowed(connection) => Some(&mut **connection),
            Slot::Pooled(connection) => connection.as_deref_mut(),
        })
        .map_err(|_| AuthError::internal("hook connection is not checked out"))
    }
}

/// Context passed to Diesel lifecycle hooks.
pub struct DieselHookContext<'a> {
    /// Configuration of the auth instance that owns the store.
    pub config: &'a AuthConfig,
    /// The store pool. Its connections run outside the auth write's
    /// transaction. Do not wait on it from a hook inside a transaction: when
    /// every connection is in use (always, for a `:memory:` SQLite pool), the
    /// hook waits forever. Use [`connection`](Self::connection) instead.
    pub pool: &'a DieselPool,
    /// `true` when the write runs inside an auth transaction (for example,
    /// the user, account, and session created by sign-up).
    pub in_transaction: bool,
    /// The request being handled, when the write happens during one.
    pub request: Option<RequestHookContext>,
    pub(crate) connection: &'a HookConnection<'a>,
}

impl DieselHookContext<'_> {
    /// Lock the connection that runs the auth write.
    ///
    /// When [`in_transaction`](Self::in_transaction) is `true`, writes made
    /// through it commit or roll back together with the auth write. The lock
    /// is not reentrant: drop the guard before calling `connection` again.
    ///
    /// ```rust,ignore
    /// let mut connection = ctx.connection().await?;
    /// better_auth_diesel::with_connection!(&mut *connection, |c| {
    ///     diesel::insert_into(workspaces::table)
    ///         .values(workspaces::owner_id.eq(&user.id))
    ///         .execute(c)
    ///         .await
    /// })?;
    /// ```
    pub async fn connection(&self) -> AuthResult<MappedMutexGuard<'_, DieselConnection>> {
        self.connection.lock().await
    }
}

/// Diesel lifecycle hooks for intercepting auth writes.
#[async_trait]
pub trait DieselHooks: Send + Sync {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_user(&self, user: &User, ctx: &DieselHookContext<'_>) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_update_user(
        &self,
        id: &str,
        update: &mut UpdateUser,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_user(&self, user: &User, ctx: &DieselHookContext<'_>) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_delete_user(
        &self,
        user: &User,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (user, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(&self, user: &User, ctx: &DieselHookContext<'_>) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }

    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &Session,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        session: &Session,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (session, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &Session,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }

    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        account: &Account,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_update_account(
        &self,
        id: &str,
        update: &mut UpdateAccount,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (id, update, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_update_account(
        &self,
        account: &Account,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_delete_account(
        &self,
        account: &Account,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (account, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        account: &Account,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (account, ctx);
        Ok(())
    }

    async fn before_create_verification(
        &self,
        verification: &mut CreateVerification,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        verification: &Verification,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        verification: &Verification,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = (verification, ctx);
        Ok(HookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        verification: &Verification,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<()> {
        let _ = (verification, ctx);
        Ok(())
    }
}
