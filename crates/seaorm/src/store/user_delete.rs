use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter};

use super::transaction_hooks::after_write;
use super::{HookTransaction, map_db_err};
use crate::SeaOrmStore;
use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn delete_user_accounts_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<HookTransaction<'_, S>>,
        user_id: &str,
    ) -> AuthResult<Option<usize>> {
        let user_id = S::Account::parse_user_id(user_id)?;
        let condition = S::Account::user_id_column().eq(user_id);
        let snapshot: AuthResult<Vec<better_auth_core::wire::AccountView>> = async {
            <S::Account as SeaOrmAccountModel>::Entity::find()
                .filter(condition.clone())
                .all(db)
                .await
                .map_err(map_db_err)?
                .iter()
                .map(|row| self.output_account(row, db))
                .collect()
        }
        .await;
        // Match the upstream snapshot-only catch; hook and write errors still propagate.
        let accounts = snapshot.unwrap_or_default();
        let context = self.hook_context(tx);
        for account in &accounts {
            for hook in self.hooks() {
                if hook
                    .before_delete_account(account, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(None);
                }
            }
        }
        let result = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
            .filter(condition)
            .exec(db)
            .await
            .map_err(map_db_err)?;
        for account in accounts {
            let store = self.clone();
            after_write(
                tx,
                Box::pin(async move {
                    let context = store.hook_context(None);
                    for hook in store.hooks() {
                        hook.after_delete_account(&account, &context).await?;
                    }
                    Ok(())
                }),
            )
            .await?;
        }
        Ok(Some(result.rows_affected as usize))
    }

    pub(super) async fn delete_user_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<HookTransaction<'_, S>>,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<S::User>> {
        if delete_database_sessions {
            let owner = S::Session::parse_user_id(id)?;
            let condition = Condition::all().add(S::Session::user_id_column().eq(owner));
            // A child batch cancellation does not cancel the later user deletion.
            let _ = self
                .delete_sessions_with_connection(db, tx, condition, false)
                .await?;
        }
        let _ = self
            .delete_user_accounts_with_connection(db, tx, id)
            .await?;
        let user_id = S::User::parse_id(id)?;
        let snapshot = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(S::User::id_column().eq(user_id.clone()))
            .one(db)
            .await;
        // deleteWithHooks returns null after a missing or unreadable snapshot.
        let user = match snapshot {
            Ok(Some(user)) => user,
            Ok(None) | Err(_) => return Ok(None),
        };
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_delete_user(&user, &context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }
        // Retain the existing polymorphic API-key cleanup before the user write.
        let _ = <P::ApiKey as crate::SeaOrmPluginModel>::Entity::delete_many()
            .filter(<P::ApiKey as crate::SeaOrmPluginModel>::column("reference_id")?.eq(id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        let _ = <S::User as SeaOrmUserModel>::Entity::delete_many()
            .filter(S::User::id_column().eq(user_id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_delete_user(&user, &context).await?;
            }
        }
        Ok(Some(user))
    }
}
