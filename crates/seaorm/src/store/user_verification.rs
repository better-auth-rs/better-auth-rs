use better_auth_core::store::VerificationSessionCleanup;
use better_auth_core::{AuthResult, AuthUser, UpdateUser};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect,
    SqliteTransactionMode, TransactionOptions, TransactionTrait,
};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn verify_unproven_user(
        &self,
        user_id: &str,
        database_sessions: bool,
        session_cleanup: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<S::User>> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let mut revoked = None;
        let result = async {
            let Some(user) = <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().eq(S::User::parse_id(user_id)?))
                .lock_exclusive()
                .one(&tx)
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            if user.email_verified() {
                return Ok(Some(user));
            }
            let hook_context = self.hook_context(Some(&tx));
            let accounts = <S::Account as SeaOrmAccountModel>::Entity::find()
                .filter(S::Account::user_id_column().eq(S::Account::parse_user_id(user_id)?))
                .all(&tx)
                .await
                .map_err(map_db_err)?;
            let sessions = if database_sessions {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(S::Session::user_id_column().eq(S::Session::parse_user_id(user_id)?))
                    .all(&tx)
                    .await
                    .map_err(map_db_err)?
            } else {
                Vec::new()
            };
            for account in &accounts {
                for hook in self.hooks() {
                    if hook
                        .before_delete_account(account, &hook_context)
                        .await?
                        .is_cancelled()
                    {
                        return Err(cancelled_by_hook("unproven account deletion"));
                    }
                }
            }
            for session in &sessions {
                for hook in self.hooks() {
                    if hook
                        .before_delete_session(session, &hook_context)
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
            for hook in self.hooks() {
                if hook
                    .before_update_user(user_id, &mut update, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("email verification"));
                }
            }
            let _ = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                .filter(S::Account::user_id_column().eq(S::Account::parse_user_id(user_id)?))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if database_sessions {
                let _ = <S::Session as SeaOrmSessionModel>::Entity::delete_many()
                    .filter(S::Session::user_id_column().eq(S::Session::parse_user_id(user_id)?))
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
            }
            let mut active = user.into_active_model();
            S::User::apply_update(&mut active, update, Utc::now());
            let user = active.update(&tx).await.map_err(map_db_err)?;
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
        } else {
            tx.rollback().await.map_err(map_db_err)?;
        }
        let user = result?;
        if let (Some(user), Some((accounts, sessions))) = (&user, revoked) {
            let hook_context = self.hook_context(None);
            for hook in self.hooks() {
                for account in &accounts {
                    hook.after_delete_account(account, &hook_context).await?;
                }
                for session in &sessions {
                    hook.after_delete_session(session, &hook_context).await?;
                }
                hook.after_update_user(user, &hook_context).await?;
            }
        }
        Ok(user)
    }
}

#[cfg(test)]
#[path = "user_verification_tests.rs"]
mod tests;
