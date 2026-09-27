use async_trait::async_trait;
use better_auth_core::store::VerificationStore;
use better_auth_core::types::CreateVerification;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::AuthResult;
use crate::hooks::HookConnection;
use crate::models::Verification;
use crate::schema::verifications;
use crate::sql_types::UtcTimestampValue;

use super::{DieselAuthSchema, DieselStore, cancelled_by_hook, new_id};

#[async_trait]
impl VerificationStore<DieselAuthSchema> for DieselStore {
    async fn create_verification(
        &self,
        mut verification: CreateVerification,
    ) -> AuthResult<Verification> {
        let connection = HookConnection::pooled(&self.pool);
        let hook_context = self.hook_context(&connection);
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
        let row = Verification {
            id: new_id(),
            identifier: verification.identifier,
            value: verification.value,
            expires_at: verification.expires_at,
            created_at: now,
            updated_at: now,
        };

        let verification = run_query!(lock connection, |c| {
            diesel::insert_into(verifications::table)
                .values(row)
                .returning(Verification::as_returning())
                .get_result(c)
                .await
        })?;

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
    ) -> AuthResult<Option<Verification>> {
        run_query!(self, |c| {
            verifications::table
                .filter(verifications::identifier.eq(identifier))
                .filter(verifications::value.eq(value))
                .filter(verifications::expires_at.gt(UtcTimestampValue(Utc::now())))
                .select(Verification::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
        run_query!(self, |c| {
            verifications::table
                .filter(verifications::value.eq(value))
                .filter(verifications::expires_at.gt(UtcTimestampValue(Utc::now())))
                .select(Verification::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Verification>> {
        run_query!(self, |c| {
            verifications::table
                .filter(verifications::identifier.eq(identifier))
                .filter(verifications::expires_at.gt(UtcTimestampValue(Utc::now())))
                .select(Verification::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Verification>> {
        let mut connection = self.connection().await?;
        let Some(verification) = run_query!(on &mut connection, |c| {
            verifications::table
                .filter(verifications::identifier.eq(identifier))
                .filter(verifications::value.eq(value))
                .filter(verifications::expires_at.gt(UtcTimestampValue(Utc::now())))
                .order(verifications::created_at.desc())
                .select(Verification::as_select())
                .first(c)
                .await
                .optional()
        })?
        else {
            return Ok(None);
        };

        // Only the caller whose delete removes the row consumes it, so two
        // concurrent consumers cannot both succeed.
        let deleted = run_query!(on &mut connection, |c| {
            diesel::delete(verifications::table.find(&verification.id))
                .execute(c)
                .await
        })?;

        Ok((deleted == 1).then_some(verification))
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let connection = HookConnection::pooled(&self.pool);
        let verification = run_query!(lock connection, |c| {
            verifications::table
                .find(id)
                .select(Verification::as_select())
                .first(c)
                .await
                .optional()
        })?;

        let hook_context = self.hook_context(&connection);
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

        let _ = run_query!(lock connection, |c| {
            diesel::delete(verifications::table.find(id))
                .execute(c)
                .await
        })?;

        if let Some(verification) = &verification {
            for hook in self.hooks() {
                hook.after_delete_verification(verification, &hook_context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        run_query!(self, |c| {
            diesel::delete(
                verifications::table
                    .filter(verifications::expires_at.lt(UtcTimestampValue(Utc::now()))),
            )
            .execute(c)
            .await
        })
    }
}
