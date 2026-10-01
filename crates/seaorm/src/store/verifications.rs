use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, SqliteTransactionMode, TransactionOptions, TransactionTrait,
};

use better_auth_core::store::VerificationStore;

use crate::entity::AuthVerification;
use crate::error::AuthResult;
use crate::hooks::{DatabaseHookUpdate, VerificationUpdate};
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use crate::types::CreateVerification;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

#[cfg(test)]
#[path = "verification_concurrency_tests.rs"]
mod concurrency_tests;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> VerificationStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    async fn reserve_verification(
        &self,
        id: &str,
        verification: CreateVerification,
    ) -> AuthResult<bool> {
        let reservation_id = S::Verification::parse_id(id)?;
        match S::Verification::new_active(Some(reservation_id.clone()), verification, Utc::now())
            .insert(self.connection())
            .await
        {
            Ok(_) => Ok(true),
            Err(cause) => {
                if <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(S::Verification::id_column().eq(reservation_id))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)?
                    .is_some()
                {
                    Ok(false)
                } else {
                    Err(map_db_err(cause))
                }
            }
        }
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.find_verification_with_connection(self.connection(), identifier)
            .await
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let mut update = VerificationUpdate {
            value,
            expires_at,
            ..Default::default()
        };
        let original = update.clone();
        let context = self.hook_context(None);
        for hook in self.hooks() {
            match hook
                .before_update_verification(identifier, &original, &context)
                .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(()),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let reselect = match update.id.as_deref() {
            Some(id) => S::Verification::id_column().eq(S::Verification::parse_id(id)?),
            None => S::Verification::identifier_column()
                .eq(update.identifier.as_deref().unwrap_or(identifier)),
        };
        let _ = update.updated_at.get_or_insert_with(Utc::now);
        let mut active = <S::Verification as SeaOrmVerificationModel>::ActiveModel::default();
        S::Verification::apply_update(&mut active, update)?;
        let verification = super::updates::update_returning_one::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
            _,
        >(
            self.connection(),
            active,
            S::Verification::identifier_column().eq(identifier),
            reselect,
        )
        .await?;
        for hook in self.hooks() {
            hook.after_update_verification(verification.as_ref(), &context)
                .await?;
        }
        Ok(())
    }

    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let records = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::identifier_column().eq(identifier))
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        for record in records {
            self.delete_verification(record.id().as_ref()).await?;
        }
        Ok(())
    }
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .create_verification_with_connection(self.connection(), None, verification)
            .await?;
        self.after_create_runtime_verification(&verification)
            .await?;
        Ok(verification)
    }

    async fn before_create_runtime_verification(
        &self,
        verification: &mut CreateVerification,
    ) -> AuthResult<()> {
        self.before_runtime_verification_in_tx(verification, None)
            .await
    }

    async fn after_create_runtime_verification(
        &self,
        verification: &S::Verification,
    ) -> AuthResult<()> {
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            hook.after_create_verification(verification, &hook_context)
                .await?;
        }
        Ok(())
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::identifier_column().eq(identifier),
            )
            .filter(<S::Verification as SeaOrmVerificationModel>::value_column().eq(value))
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(<S::Verification as SeaOrmVerificationModel>::value_column().eq(value))
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::identifier_column().eq(identifier),
            )
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Ok(self
            .consume_latest_verification(identifier, Some(value))
            .await?
            .filter(|value| value.expires_at() >= Utc::now()))
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Ok(self
            .consume_latest_verification(identifier, None)
            .await?
            .filter(|value| value.expires_at() >= Utc::now()))
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.consume_latest_verification(identifier, None).await
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let verification_id = <S::Verification as SeaOrmVerificationModel>::parse_id(id)?;
        let verification = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::id_column()
                    .eq(verification_id.clone()),
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        let hook_context = self.hook_context(None);
        if let Some(verification) = &verification {
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(verification, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("verification deletion"));
                }
            }
        }
        let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(<S::Verification as SeaOrmVerificationModel>::id_column().eq(verification_id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        if let Some(verification) = &verification {
            for hook in self.hooks() {
                hook.after_delete_verification(verification, &hook_context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let (count, records) = self
            .delete_expired_verifications_with_connection(self.connection(), None)
            .await?;
        let context = self.hook_context(None);
        for record in &records {
            for hook in self.hooks() {
                hook.after_delete_verification(record, &context).await?;
            }
        }
        Ok(count)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) async fn delete_expired_verifications_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<(usize, Vec<S::Verification>)> {
        let now = Utc::now();
        let filter = <S::Verification as SeaOrmVerificationModel>::expires_at_column().lt(now);
        let records = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(filter.clone())
            .all(connection)
            .await
            .map_err(map_db_err)?;
        let context = self.hook_context(tx);
        for record in &records {
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(record, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok((0, Vec::new()));
                }
            }
        }
        let deleted = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(filter)
            .exec(connection)
            .await
            .map_err(map_db_err)?;
        Ok((deleted.rows_affected as usize, records))
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) async fn before_runtime_verification_in_tx(
        &self,
        verification: &mut CreateVerification,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<()> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_verification(verification, &context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("verification creation"));
            }
        }
        Ok(())
    }

    pub(super) async fn create_verification_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.before_runtime_verification_in_tx(&mut verification, tx)
            .await?;
        S::Verification::new_active(None, verification, Utc::now())
            .insert(connection)
            .await
            .map_err(map_db_err)
    }

    pub(super) async fn find_verification_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::identifier_column().eq(identifier))
            .order_by_desc(S::Verification::created_at_column())
            .one(connection)
            .await
            .map_err(map_db_err)
    }

    async fn consume_latest_verification(
        &self,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<S::Verification>> {
        let transaction = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let hook_transaction = super::SeaOrmTransaction {
            store: self,
            tx: &transaction,
            effects: std::sync::Mutex::new(Vec::new()),
        };
        let result: AuthResult<Option<S::Verification>> = async {
            let Some(model) = <S::Verification as SeaOrmVerificationModel>::Entity::find()
                .filter(
                    <S::Verification as SeaOrmVerificationModel>::identifier_column()
                        .eq(identifier),
                )
                .order_by_desc(<S::Verification as SeaOrmVerificationModel>::created_at_column())
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            if expected_value.is_some_and(|value| model.value() != value) {
                return Ok(None);
            }
            let hook_context = self.hook_context(Some((&transaction, &hook_transaction)));
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(&model, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(None);
                }
            }
            let id = <S::Verification as SeaOrmVerificationModel>::parse_id(model.id().as_ref())?;
            let deleted = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                .filter(<S::Verification as SeaOrmVerificationModel>::id_column().eq(id))
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
            if deleted.rows_affected == 0 {
                return Ok(None);
            }
            let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                .filter(
                    <S::Verification as SeaOrmVerificationModel>::identifier_column()
                        .eq(identifier),
                )
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
            Ok(Some(model))
        }
        .await;
        let effects = hook_transaction.effects.into_inner().map_err(|_| {
            better_auth_core::AuthError::internal("Transaction hook queue lock poisoned")
        })?;
        if result.is_ok() {
            transaction.commit().await.map_err(map_db_err)?;
            self.finish_transaction_effects(effects).await?;
        } else {
            transaction.rollback().await.map_err(map_db_err)?;
        }
        let Some(model) = result? else {
            return Ok(None);
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            hook.after_delete_verification(&model, &hook_context)
                .await?;
        }
        Ok(Some(model))
    }
}
