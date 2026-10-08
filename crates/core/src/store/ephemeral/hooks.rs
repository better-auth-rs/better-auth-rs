use super::*;

pub(super) type PendingHookQueue = Mutex<Vec<PendingHook>>;
use crate::hooks::{RequestHookContext, current_request_hook_context};
use crate::store::database_hooks::DatabaseHookContext;

pub(super) enum CommittedWrite {
    UserCreated(Option<UserView>),
    UserUpdated(Option<UserView>),
    UserDeleted(UserView),
    AccountCreated(Option<AccountView>),
    AccountUpdated(Option<AccountView>),
    AccountDeleted(AccountView),
    SessionCreated(Option<SessionView>),
    SessionUpdated(Option<SessionView>),
    SessionDeleted(SessionView),
    VerificationCreated(Option<VerificationView>),
    VerificationUpdated(Option<VerificationView>),
    VerificationDeleted(VerificationView),
}

pub(super) enum PendingHook {
    Database {
        write: Box<CommittedWrite>,
        request: Option<Box<RequestHookContext>>,
    },
    External {
        effect: crate::store::TypedTransactionFuture<'static, ()>,
    },
}

impl EphemeralStore {
    pub(super) fn hook_context<'a>(
        &'a self,
        transaction: &'a EphemeralTransaction,
    ) -> DatabaseHookContext<'a, StatelessSchema> {
        DatabaseHookContext {
            config: &self.config,
            request: current_request_hook_context(),
            transaction: self
                .pending_hooks
                .as_ref()
                .map(|_| transaction as &dyn AuthTransaction<StatelessSchema>),
        }
    }

    pub(super) async fn after(&self, write: CommittedWrite) -> AuthResult<()> {
        self.after_with_request(write, current_request_hook_context())
            .await
    }

    pub(super) async fn after_with_request(
        &self,
        write: CommittedWrite,
        request: Option<RequestHookContext>,
    ) -> AuthResult<()> {
        let pending = PendingHook::Database {
            write: Box::new(write),
            request: request.map(Box::new),
        };
        if let Some(queue) = &self.pending_hooks {
            // Only the transaction owner keeps the queue alive. Late writes retain
            // their adapter, but their after hooks cannot restart a completed drain.
            if let Some(queue) = queue.upgrade() {
                queue
                    .lock()
                    .map_err(|_| {
                        AuthError::internal("Ephemeral transaction hook queue lock poisoned")
                    })?
                    .push(pending);
            }
            Ok(())
        } else {
            self.run_after(pending).await
        }
    }

    pub(super) async fn run_after(&self, pending: PendingHook) -> AuthResult<()> {
        let (write, request) = match pending {
            PendingHook::External { effect } => return effect.await,
            PendingHook::Database { write, request } => (write, request.map(|request| *request)),
        };
        let context = DatabaseHookContext {
            config: &self.config,
            request,
            transaction: None,
        };
        for hook in &self.hooks {
            match write.as_ref() {
                CommittedWrite::UserCreated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterCreateUser,
                        hook.after_create_user(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::UserUpdated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterUpdateUser,
                        hook.after_update_user(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::UserDeleted(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterDeleteUser,
                        hook.after_delete_user(row, &context),
                    )
                    .await?
                }
                CommittedWrite::AccountCreated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterCreateAccount,
                        hook.after_create_account(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::AccountUpdated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterUpdateAccount,
                        hook.after_update_account(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::AccountDeleted(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterDeleteAccount,
                        hook.after_delete_account(row, &context),
                    )
                    .await?
                }
                CommittedWrite::SessionCreated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterCreateSession,
                        hook.after_create_session(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::SessionUpdated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterUpdateSession,
                        hook.after_update_session(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::SessionDeleted(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterDeleteSession,
                        hook.after_delete_session(row, &context),
                    )
                    .await?
                }
                CommittedWrite::VerificationCreated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterCreateVerification,
                        hook.after_create_verification(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::VerificationUpdated(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterUpdateVerification,
                        hook.after_update_verification(row.as_ref(), &context),
                    )
                    .await?
                }
                CommittedWrite::VerificationDeleted(row) => {
                    crate::observability::database::with_database_hook(
                        context.config,
                        hook.hook_metadata(),
                        crate::observability::database::DatabaseHook::AfterDeleteVerification,
                        hook.after_delete_verification(row, &context),
                    )
                    .await?
                }
            }
        }
        Ok(())
    }
}
