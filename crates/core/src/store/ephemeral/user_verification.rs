use super::hooks::CommittedWrite;
use super::*;
use crate::store::{VerificationSessionCleanup, database_hooks::DatabaseHookControl};

impl EphemeralStore {
    async fn verify_unproven_user_inner(
        &self,
        user_id: &str,
        database_sessions: bool,
        session_cleanup: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<UserView>> {
        let Some(user) = self.get_user_by_id(user_id).await? else {
            return Ok(None);
        };
        if user.email_verified {
            return Ok(Some(user));
        }
        let accounts = self.get_user_accounts(user_id).await?;
        let sessions = if database_sessions {
            self.get_user_sessions(user_id).await?
        } else {
            Vec::new()
        };
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for account in &accounts {
            for hook in &self.hooks {
                if crate::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    crate::observability::database::DatabaseHook::BeforeDeleteAccount,
                    hook.before_delete_account(account, &context),
                )
                .await?
                    == DatabaseHookControl::Cancel
                {
                    return Err(AuthError::forbidden(
                        "unproven account deletion cancelled by database hook",
                    ));
                }
            }
        }
        for session in &sessions {
            for hook in &self.hooks {
                if crate::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    crate::observability::database::DatabaseHook::BeforeDeleteSession,
                    hook.before_delete_session(session, &context),
                )
                .await?
                    == DatabaseHookControl::Cancel
                {
                    return Err(AuthError::forbidden(
                        "unproven session deletion cancelled by database hook",
                    ));
                }
            }
        }
        let update = self
            .prepare_user_update(UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
        let schema = self.config.account.field_schema();
        self.raw("account", "deleteMany", |state| {
            state.accounts.retain(|_, row| {
                row.get(schema.record_storage_key("userId"))
                    != Some(&Value::String(user_id.to_owned()))
            });
            Ok(())
        })
        .await?;
        if database_sessions {
            self.raw("session", "deleteMany", |state| {
                state.sessions.retain(|_, row| row.user_id != user_id);
                Ok(())
            })
            .await?;
        }
        let user = self.update_user_record(user_id, update).await?;
        if let Some(cleanup) = session_cleanup {
            cleanup.revoke().await?;
        }
        for account in accounts {
            self.after(CommittedWrite::AccountDeleted(account)).await?;
        }
        for session in sessions {
            self.after(CommittedWrite::SessionDeleted(session)).await?;
        }
        self.after(CommittedWrite::UserUpdated(Some(user.clone())))
            .await?;
        Ok(Some(user))
    }

    pub(super) async fn verify_unproven_user(
        &self,
        user_id: &str,
        database_sessions: bool,
        session_cleanup: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<UserView>> {
        let lock = self.verification_lock(format!("user:{user_id}"))?;
        let _guard = lock.lock().await;
        if self.pending_hooks.is_some() {
            return self
                .verify_unproven_user_inner(user_id, database_sessions, session_cleanup)
                .await;
        }
        let (base, isolated) = self.begin_transaction()?;
        let user = isolated
            .verify_unproven_user_inner(user_id, database_sessions, session_cleanup)
            .await?;
        self.commit_transaction(base, isolated).await?;
        Ok(user)
    }
}
