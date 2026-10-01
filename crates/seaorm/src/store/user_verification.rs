use super::instrumentation::database_operation;
use better_auth_core::store::VerificationSessionCleanup;
use better_auth_core::{AuthResult, AuthUser, UpdateUser};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, SqliteTransactionMode,
    TransactionOptions, TransactionTrait,
};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    pub(super) async fn verify_unproven_user(
        &self,
        user_id: &str,
        database_sessions: bool,
        session_cleanup: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let tx = crate::TransactionConnection::new(tx);
        let effects = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let hook_transaction = super::SeaOrmTransaction {
            store: self.clone(),
            tx: tx.clone(),
            effects: std::sync::Arc::downgrade(&effects),
        };
        let mut revoked = None;
        let result = async {
            let Some(user) = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(self.config(), "findOne", async { <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().eq(self.parse_id(user_id, S::User::parse_id)?))
                .lock_exclusive()
                .one(&tx)
                .await
                .map_err(map_db_err) }).await?
            else {
                return Ok(None);
            };
            if user.email_verified() {
                return self.output_user(&user, &tx).await.map(Some);
            }
            let hook_context = self.hook_context(Some((&tx, &hook_transaction)));
            let accounts = match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(self.config(), "findMany", async { <S::Account as SeaOrmAccountModel>::Entity::find()
                .filter(S::Account::user_id_column().eq(self.parse_id(user_id, S::Account::parse_user_id)?))
                .limit(super::pagination::default_limit(self.config(), tx.get_database_backend())?)
                .all(&tx)
                .await
                .map_err(map_db_err) }).await { Ok(rows) => self.output_accounts(&rows, &tx).await, Err(error) => Err(error) }?;
            let sessions = if database_sessions {
                match database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(self.config(), "findMany", async { <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(S::Session::user_id_column().eq(self.parse_id(user_id, S::Session::parse_user_id)?))
                    .limit(super::pagination::default_limit(self.config(), tx.get_database_backend())?)
                    .all(&tx)
                    .await
                    .map_err(map_db_err) }).await { Ok(rows) => self.output_sessions(&rows, &tx).await, Err(error) => Err(error) }?
            } else {
                Vec::new()
            };
            for account in &accounts {
                for hook in self.hooks() {
                    if better_auth_core::observability::database::with_database_hook(hook_context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::BeforeDeleteAccount, hook
                        .before_delete_account(account, &hook_context))
                        .await?
                        .is_cancelled()
                    {
                        return Err(cancelled_by_hook("unproven account deletion"));
                    }
                }
            }
            for session in &sessions {
                for hook in self.hooks() {
                    if better_auth_core::observability::database::with_database_hook(hook_context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::BeforeDeleteSession, hook
                        .before_delete_session(session, &hook_context))
                        .await?
                        .is_cancelled()
                    {
                        return Err(cancelled_by_hook("unproven session deletion"));
                    }
                }
            }
            let mut update = UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            };
            let original = update.clone();
            for hook in self.hooks() {
                match better_auth_core::observability::database::with_database_hook(hook_context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::BeforeUpdateUser, hook
                    .before_update_user(user_id, &original, &hook_context))
                    .await?
                {
                    crate::hooks::DatabaseHookUpdate::Continue => {}
                    crate::hooks::DatabaseHookUpdate::Cancel => {
                        return Err(cancelled_by_hook("email verification"));
                    }
                    crate::hooks::DatabaseHookUpdate::Patch(mut patch) => {
                        patch.prepare_user_fields(&self.config().user)?;
                        update.merge(patch);
                    }
                }
            }
            let _ = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(self.config(), "deleteMany", async { <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                .filter(S::Account::user_id_column().eq(self.parse_id(user_id, S::Account::parse_user_id)?))
                .exec(&tx)
                .await
                .map_err(map_db_err) }).await?;
            if database_sessions {
                let _ = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(self.config(), "deleteMany", async { <S::Session as SeaOrmSessionModel>::Entity::delete_many()
                    .filter(S::Session::user_id_column().eq(self.parse_id(user_id, S::Session::parse_user_id)?))
                    .exec(&tx)
                    .await
                    .map_err(map_db_err) }).await?;
            }
            let user = self
                .update_user_record(&tx, self.parse_id(user_id, S::User::parse_id)?, update)
                .await?
                .ok_or(better_auth_core::AuthError::UserNotFound)?;
            let user = self.output_user(&user, &tx).await?;
            // External revocation must succeed before the database publishes verified ownership.
            if let Some(cleanup) = session_cleanup {
                cleanup.revoke().await?;
            }
            revoked = Some((accounts, sessions));
            Ok(Some(user))
        }
        .await;
        if result.is_ok() {
            tx.commit().await.map_err(map_db_err)?;
            self.finish_queued_transaction_effects(&effects).await?;
        } else {
            tx.rollback().await.map_err(map_db_err)?;
        }
        let user = result?;
        if let (Some(user), Some((accounts, sessions))) = (&user, revoked) {
            let hook_context = self.hook_context(None);
            for hook in self.hooks() {
                for account in &accounts {
                    better_auth_core::observability::database::with_database_hook(
                        hook_context.config,
                        hook.hook_metadata(),
                        better_auth_core::observability::database::DatabaseHook::AfterDeleteAccount,
                        hook.after_delete_account(account, &hook_context),
                    )
                    .await?;
                }
                for session in &sessions {
                    better_auth_core::observability::database::with_database_hook(
                        hook_context.config,
                        hook.hook_metadata(),
                        better_auth_core::observability::database::DatabaseHook::AfterDeleteSession,
                        hook.after_delete_session(session, &hook_context),
                    )
                    .await?;
                }
                better_auth_core::observability::database::with_database_hook(
                    hook_context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterUpdateUser,
                    hook.after_update_user(Some(user), &hook_context),
                )
                .await?;
            }
        }
        Ok(user)
    }
}

#[cfg(test)]
#[path = "user_verification_tests.rs"]
mod tests;
