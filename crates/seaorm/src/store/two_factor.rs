use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, IntoActiveModel, QueryFilter, Set,
    sea_query::Expr,
};
use uuid::Uuid;

use better_auth_core::store::TwoFactorStore;

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types::{CreateTwoFactor, TwoFactor};
use better_auth_core::UpdateTwoFactor;

use super::entities::two_factor::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema> TwoFactorStore for SeaOrmStore<S, O>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            secret: Set(two_factor.secret),
            backup_codes: Set(two_factor.backup_codes),
            user_id: Set(two_factor.user_id),
            verified: Set(two_factor.verified),
            failed_verification_count: Set(0),
            locked_until: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(|model| TwoFactor::from(&model))
        .map_err(map_db_err)
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| TwoFactor::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let Some(model) = Entity::find()
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found(
                "Two-factor settings not found",
            ));
        };

        let mut active = model.into_active_model();
        active.backup_codes = Set(backup_codes.to_owned());
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(|model| TwoFactor::from(&model))
            .map_err(map_db_err)
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn update_two_factor(&self, id: &str, update: UpdateTwoFactor) -> AuthResult<TwoFactor> {
        let mut active = ActiveModel {
            id: Set(id.to_owned()),
            updated_at: Set(Utc::now()),
            ..Default::default()
        };
        if let Some(secret) = update.secret {
            active.secret = Set(secret);
        }
        if let Some(codes) = update.backup_codes {
            active.backup_codes = Set(codes);
        }
        if let Some(verified) = update.verified {
            active.verified = Set(verified);
        }
        active
            .update(self.connection())
            .await
            .map(|model| TwoFactor::from(&model))
            .map_err(map_db_err)
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &str,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        Entity::update_many()
            .col_expr(Column::BackupCodes, Expr::value(replacement))
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .filter(Column::Id.eq(id))
            .filter(Column::BackupCodes.eq(previous))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn record_two_factor_failure(
        &self,
        id: &str,
        max_attempts: i64,
        locked_until: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        let _ = Entity::update_many()
            .col_expr(
                Column::FailedVerificationCount,
                Expr::col(Column::FailedVerificationCount).add(1),
            )
            .filter(Column::Id.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Entity::update_many()
            .col_expr(Column::LockedUntil, Expr::value(locked_until))
            .filter(Column::Id.eq(id))
            .filter(Column::FailedVerificationCount.gte(max_attempts))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn reset_two_factor_failures(
        &self,
        id: &str,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let mut update = Entity::update_many()
            .col_expr(Column::FailedVerificationCount, Expr::value(0))
            .col_expr(
                Column::LockedUntil,
                Expr::value(None::<chrono::DateTime<Utc>>),
            )
            .filter(Column::Id.eq(id));
        if let Some(expired) = locked_before {
            update = update.filter(Column::LockedUntil.lte(expired));
        }
        update
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
