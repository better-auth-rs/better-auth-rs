use async_trait::async_trait;
use better_auth_core::store::TwoFactorStore;
use better_auth_core::{CreateTwoFactor, TwoFactor};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::TwoFactorRow;
use crate::schema::two_factor;
use crate::sql_types::UtcTimestampValue;

use super::{DieselStore, new_id};

#[async_trait]
impl TwoFactorStore for DieselStore {
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        let row = TwoFactorRow {
            id: new_id(),
            secret: input.secret,
            backup_codes: input.backup_codes,
            user_id: input.user_id,
            created_at: now,
            updated_at: now,
        };

        run_query!(self, |c| {
            diesel::insert_into(two_factor::table)
                .values(row)
                .returning(TwoFactorRow::as_returning())
                .get_result(c)
                .await
        })
        .map(TwoFactor::from)
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        run_query!(self, |c| {
            two_factor::table
                .filter(two_factor::user_id.eq(user_id))
                .select(TwoFactorRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(TwoFactor::from))
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        run_query!(self, |c| {
            diesel::update(two_factor::table.filter(two_factor::user_id.eq(user_id)))
                .set((
                    two_factor::backup_codes.eq(backup_codes),
                    two_factor::updated_at.eq(UtcTimestampValue(Utc::now())),
                ))
                .returning(TwoFactorRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(TwoFactor::from)
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(two_factor::table.filter(two_factor::user_id.eq(user_id)))
                .execute(c)
                .await
        })?;
        Ok(())
    }
}
