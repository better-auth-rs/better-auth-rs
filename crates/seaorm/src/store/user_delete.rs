use super::instrumentation::database_operation;
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

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
        self.model_fields
            .canonicalize_id(better_auth_core::store::schema::EntityRole::Account)?;
        let user_id = self.parse_id(user_id, S::Account::parse_user_id)?;
        let condition = S::Account::user_id_column().eq(user_id);
        let snapshot: AuthResult<Vec<better_auth_core::wire::AccountView>> = async {
            match database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    <S::Account as SeaOrmAccountModel>::Entity::find()
                        .filter(condition.clone())
                        .limit(super::pagination::default_limit(
                            self.config(),
                            db.get_database_backend(),
                        )?)
                        .all(db)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await
            {
                Ok(rows) => self.output_accounts(&rows, db).await,
                Err(error) => Err(error),
            }
        }
        .await;
        // Match the upstream snapshot-only catch; hook and write errors still propagate.
        let accounts = snapshot.unwrap_or_default();
        let context = self.hook_context(tx);
        for account in &accounts {
            for hook in self.hooks() {
                if better_auth_core::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::BeforeDeleteAccount,
                    hook.before_delete_account(account, &context),
                )
                .await?
                .is_cancelled()
                {
                    return Ok(None);
                }
            }
        }
        let result = database_operation::<<S::Account as SeaOrmAccountModel>::Entity, _>(
            self.config(),
            "deleteMany",
            async {
                <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                    .filter(condition)
                    .exec(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        for account in accounts {
            let store = self.clone();
            let request = context.request.clone();
            after_write(
                tx,
                Box::pin(async move {
                    let mut context = store.hook_context(None);
                    context.request = request;
                    for hook in store.hooks() {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterDeleteAccount, hook.after_delete_account(&account, &context)).await?;
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
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        if delete_database_sessions {
            let owner = self.parse_id(id, S::Session::parse_user_id)?;
            let condition = Condition::all().add(S::Session::user_id_column().eq(owner));
            // A child batch cancellation does not cancel the later user deletion.
            let _ = self
                .delete_sessions_with_connection(db, tx, condition, false)
                .await?;
        }
        let _ = self
            .delete_user_accounts_with_connection(db, tx, id)
            .await?;
        self.model_fields
            .canonicalize_id(better_auth_core::store::schema::EntityRole::User)?;
        let user_id = self.parse_id(id, S::User::parse_id)?;
        let snapshot = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(S::User::id_column().eq(user_id.clone()))
                    .one(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await;
        let snapshot = match snapshot {
            Ok(Some(row)) => self.output_user(&row, db).await.map(Some),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };
        // deleteWithHooks returns null after a missing or unreadable snapshot.
        let user = match snapshot {
            Ok(Some(user)) => user,
            Ok(None) | Err(_) => return Ok(None),
        };
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeDeleteUser,
                hook.before_delete_user(&user, &context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(None);
            }
        }
        // Retain the existing polymorphic API-key cleanup before the user write.
        let _ = database_operation::<<P::ApiKey as crate::SeaOrmPluginModel>::Entity, _>(
            self.config(),
            "deleteMany",
            async {
                <P::ApiKey as crate::SeaOrmPluginModel>::Entity::delete_many()
                    .filter(<P::ApiKey as crate::SeaOrmPluginModel>::column("reference_id")?.eq(id))
                    .exec(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        let _ = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "delete",
            async {
                <S::User as SeaOrmUserModel>::Entity::delete_many()
                    .filter(S::User::id_column().eq(user_id))
                    .exec(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        if tx.is_none() {
            for hook in self.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterDeleteUser,
                    hook.after_delete_user(&user, &context),
                )
                .await?;
            }
        }
        Ok(Some(user))
    }
}
