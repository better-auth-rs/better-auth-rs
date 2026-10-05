use async_trait::async_trait;
use better_auth_core::store::TwoFactorStore;
use better_auth_core::{CreateTwoFactor, TwoFactor, UpdateTwoFactor};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::{TwoFactorChanges, TwoFactorRow};
use crate::schema::two_factor;
use crate::sql_types::{NullableUtcTimestampValue, UtcTimestampValue};

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
            verified: input.verified,
            failed_verification_count: 0,
            locked_until: None,
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

    async fn update_two_factor(&self, id: &str, update: UpdateTwoFactor) -> AuthResult<TwoFactor> {
        let changes = TwoFactorChanges {
            secret: update.secret,
            backup_codes: update.backup_codes,
            verified: update.verified,
            updated_at: Some(UtcTimestampValue(Utc::now())),
        };
        run_query!(self, |c| {
            diesel::update(two_factor::table.find(id))
                .set(changes)
                .returning(TwoFactorRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(TwoFactor::from)
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &str,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let updated = run_query!(self, |c| {
            diesel::update(
                two_factor::table
                    .find(id)
                    .filter(two_factor::backup_codes.eq(previous)),
            )
            .set((
                two_factor::backup_codes.eq(replacement),
                two_factor::updated_at.eq(UtcTimestampValue(Utc::now())),
            ))
            .execute(c)
            .await
        })?;
        Ok(updated == 1)
    }

    async fn record_two_factor_failure(
        &self,
        id: &str,
        max_attempts: i64,
        locked_until: DateTime<Utc>,
    ) -> AuthResult<()> {
        // The increment and the lock are separate statements, as in the
        // SeaORM store: each is atomic, and a concurrent failure that reaches
        // the budget locks the account either way.
        let _ = run_query!(self, |c| {
            async {
                let _ = diesel::update(two_factor::table.find(id))
                    .set(
                        two_factor::failed_verification_count
                            .eq(two_factor::failed_verification_count + 1),
                    )
                    .execute(c)
                    .await?;
                diesel::update(
                    two_factor::table
                        .find(id)
                        .filter(two_factor::failed_verification_count.ge(max_attempts)),
                )
                .set(two_factor::locked_until.eq(NullableUtcTimestampValue(Some(locked_until))))
                .execute(c)
                .await
            }
            .await
        })?;
        Ok(())
    }

    async fn reset_two_factor_failures(
        &self,
        id: &str,
        locked_before: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        let reset = (
            two_factor::failed_verification_count.eq(0_i64),
            two_factor::locked_until.eq(NullableUtcTimestampValue(None)),
        );
        let _ = run_query!(self, |c| {
            match locked_before {
                Some(expired) => {
                    diesel::update(
                        two_factor::table
                            .find(id)
                            .filter(two_factor::locked_until.le(UtcTimestampValue(expired))),
                    )
                    .set(reset)
                    .execute(c)
                    .await
                }
                None => {
                    diesel::update(two_factor::table.find(id))
                        .set(reset)
                        .execute(c)
                        .await
                }
            }
        })?;
        Ok(())
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
