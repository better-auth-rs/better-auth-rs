use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use better_auth_core::store::VerificationStore;

use crate::entity::AuthVerification;
use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use crate::types::CreateVerification;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

#[async_trait]
impl<S> VerificationStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
{
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
        let Some(model) = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::identifier_column().eq(identifier),
            )
            .filter(<S::Verification as SeaOrmVerificationModel>::value_column().eq(value))
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .order_by_desc(<S::Verification as SeaOrmVerificationModel>::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let verification_id =
            <S::Verification as SeaOrmVerificationModel>::parse_id(model.id().as_ref())?;
        let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(<S::Verification as SeaOrmVerificationModel>::id_column().eq(verification_id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok(Some(model))
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
