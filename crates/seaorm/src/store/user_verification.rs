use better_auth_core::store::VerificationSessionCleanup;
use better_auth_core::{AuthResult, AuthUser, UpdateUser};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, SqliteTransactionMode, TransactionOptions, TransactionTrait,
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
    ) -> AuthResult<Option<S::User>> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let hook_transaction = super::SeaOrmTransaction {
            store: self,
            tx: &tx,
            effects: std::sync::Mutex::new(Vec::new()),
        };
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
            let hook_context = self.hook_context(Some((&tx, &hook_transaction)));
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
            let original = update.clone();
            for hook in self.hooks() {
                match hook
                    .before_update_user(user_id, &original, &hook_context)
                    .await?
                {
                    crate::hooks::DatabaseHookUpdate::Continue => {}
                    crate::hooks::DatabaseHookUpdate::Cancel => {
                        return Err(cancelled_by_hook("email verification"));
                    }
                    crate::hooks::DatabaseHookUpdate::Patch(patch) => update.merge(patch),
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
            let fields = self.config().user.storage_fields_for_adapter(
                std::mem::take(&mut update.additional_fields),
                false,
                tx.get_database_backend() == sea_orm::DbBackend::Postgres,
                S::User::native_json_field,
            )?;
            S::User::apply_update(&mut active, update, Utc::now());
            S::User::apply_fields(&mut active, fields)?;
            crate::reference_id::apply_bindings(
                &mut active,
                &self.config().user,
                tx.get_database_backend(),
                S::User::field_column,
            )?;
            let user = active.update(&tx).await.map_err(map_db_err)?;
            // External revocation must succeed before the database publishes verified ownership.
            if let Some(cleanup) = session_cleanup {
                cleanup.revoke().await?;
            }
            revoked = Some((accounts, sessions));
            Ok(Some(user))
        }
        .await;
        let effects = hook_transaction.effects.into_inner().map_err(|_| {
            better_auth_core::AuthError::internal("Transaction hook queue lock poisoned")
        })?;
        if result.is_ok() {
            tx.commit().await.map_err(map_db_err)?;
            self.finish_transaction_effects(effects).await?;
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
                hook.after_update_user(Some(user), &hook_context).await?;
            }
        }
        Ok(user)
    }
}

#[cfg(test)]
#[path = "user_verification_tests.rs"]
mod tests;
