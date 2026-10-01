use super::*;
use crate::hooks::{RequestHookContext, current_request_hook_context};
use crate::store::database_hooks::DatabaseHookContext;

pub(super) enum CommittedWrite {
    UserCreated(UserView),
    UserUpdated(Option<UserView>),
    UserDeleted(UserView),
    AccountCreated(AccountView),
    AccountUpdated(Option<AccountView>),
    AccountDeleted(AccountView),
    SessionCreated(SessionView),
    SessionUpdated(Option<SessionView>),
    SessionDeleted(SessionView),
    VerificationCreated(VerificationView),
    VerificationUpdated(Option<VerificationView>),
    VerificationDeleted(VerificationView),
}

pub(super) enum PendingHook {
    Database {
        write: Box<CommittedWrite>,
        request: Option<RequestHookContext>,
    },
    External {
        effect: crate::store::TypedTransactionFuture<'static, ()>,
        request: Option<RequestHookContext>,
    },
}

impl EphemeralStore {
    pub(super) fn hook_context<'a>(
        &'a self,
        transaction: &'a EphemeralTransaction<'a>,
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
        let pending = PendingHook::Database {
            write: Box::new(write),
            request: current_request_hook_context(),
        };
        if let Some(queue) = &self.pending_hooks {
            queue
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral transaction hook queue lock poisoned"))?
                .push(pending);
            Ok(())
        } else {
            self.run_after(pending).await
        }
    }

    pub(super) async fn run_after(&self, pending: PendingHook) -> AuthResult<()> {
        let (write, request) = match pending {
            PendingHook::External { effect, request } => {
                return match request {
                    Some(request) => {
                        crate::hooks::with_request_hook_context_value(request, effect).await
                    }
                    None => effect.await,
                };
            }
            PendingHook::Database { write, request } => (write, request),
        };
        let context = DatabaseHookContext {
            config: &self.config,
            request,
            transaction: None,
        };
        for hook in &self.hooks {
            match write.as_ref() {
                CommittedWrite::UserCreated(row) => hook.after_create_user(row, &context).await?,
                CommittedWrite::UserUpdated(row) => {
                    hook.after_update_user(row.as_ref(), &context).await?
                }
                CommittedWrite::UserDeleted(row) => hook.after_delete_user(row, &context).await?,
                CommittedWrite::AccountCreated(row) => {
                    hook.after_create_account(row, &context).await?
                }
                CommittedWrite::AccountUpdated(row) => {
                    hook.after_update_account(row.as_ref(), &context).await?
                }
                CommittedWrite::AccountDeleted(row) => {
                    hook.after_delete_account(row, &context).await?
                }
                CommittedWrite::SessionCreated(row) => {
                    hook.after_create_session(row, &context).await?
                }
                CommittedWrite::SessionUpdated(row) => {
                    hook.after_update_session(row.as_ref(), &context).await?
                }
                CommittedWrite::SessionDeleted(row) => {
                    hook.after_delete_session(row, &context).await?
                }
                CommittedWrite::VerificationCreated(row) => {
                    hook.after_create_verification(row, &context).await?
                }
                CommittedWrite::VerificationUpdated(row) => {
                    hook.after_update_verification(row.as_ref(), &context)
                        .await?
                }
                CommittedWrite::VerificationDeleted(row) => {
                    hook.after_delete_verification(row, &context).await?
                }
            }
        }
        Ok(())
    }
}
