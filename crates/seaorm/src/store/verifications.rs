use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    SqliteTransactionMode, TransactionOptions, TransactionTrait,
};

use better_auth_core::store::VerificationStore;

use crate::entity::AuthVerification;
use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use crate::types::CreateVerification;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

#[cfg(test)]
#[path = "verification_concurrency_tests.rs"]
mod concurrency_tests;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema> VerificationStore<S> for SeaOrmStore<S, O>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
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
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::identifier_column().eq(identifier))
            .order_by_desc(S::Verification::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let mut query = <S::Verification as SeaOrmVerificationModel>::Entity::update_many()
            .filter(S::Verification::identifier_column().eq(identifier));
        if let Some(value) = value {
            query = query.col_expr(
                S::Verification::value_column(),
                sea_orm::sea_query::Expr::value(value),
            );
        }
        if let Some(expires_at) = expires_at {
            query = query.col_expr(
                S::Verification::expires_at_column(),
                sea_orm::sea_query::Expr::value(expires_at),
            );
        }
        let _ = query.exec(self.connection()).await.map_err(map_db_err)?;
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
        mut verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_create_verification(&mut verification, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("verification creation"));
            }
        }
        let now = Utc::now();
        let verification = S::Verification::new_active(None, verification, now)
            .insert(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_verification(&verification, &hook_context)
                .await?;
        }
        Ok(verification)
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
        self.consume_latest_verification(identifier, Some(value))
            .await
    }

    async fn consume_verification_by_identifier(
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
        <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().lt(Utc::now()),
            )
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema> SeaOrmStore<S, O>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
{
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
            let hook_context = self.hook_context(Some(&transaction));
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
        if result.is_ok() {
            transaction.commit().await.map_err(map_db_err)?;
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
        Ok((model.expires_at() >= Utc::now()).then_some(model))
    }
}
