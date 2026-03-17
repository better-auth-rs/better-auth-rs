use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::types::{CreateVerification, Verification};

use super::entities::verification::{ActiveModel, Column, Entity};
use super::{AuthStore, cancelled_by_hook, map_db_err};

impl AuthStore {
    pub async fn create_verification(
        &self,
        mut verification: CreateVerification,
    ) -> AuthResult<Verification> {
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
        let verification = ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            identifier: Set(verification.identifier),
            value: Set(verification.value),
            expires_at: Set(verification.expires_at),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(Verification::from)
        .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_verification(&verification, &hook_context)
                .await?;
        }
        Ok(verification)
    }

    pub async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Verification>> {
        Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    pub async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
        Entity::find()
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    pub async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Verification>> {
        Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    pub async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Verification>> {
        let Some(model) = Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(Column::CreatedAt)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let _ = Entity::delete_by_id(model.id.clone())
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok(Some(model.into()))
    }

    pub async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let verification = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(Verification::from);
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
        let _ = Entity::delete_by_id(id.to_owned())
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

    pub async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        Entity::delete_many()
            .filter(Column::ExpiresAt.lt(Utc::now()))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }
}
