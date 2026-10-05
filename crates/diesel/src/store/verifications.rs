use async_trait::async_trait;
use better_auth_core::store::VerificationStore;
use better_auth_core::types::CreateVerification;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::connection::DieselConnection;
use crate::error::{AuthResult, map_query_err};
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
        self.consume_newest_verification(identifier, Some(value))
            .await
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Verification>> {
        self.consume_newest_verification(identifier, None).await
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

impl DieselStore {
    /// Consume the newest verification for `identifier`, and with it every
    /// record for the identifier.
    ///
    /// Nothing is consumed when `expected_value` does not match the newest
    /// record or a hook cancels the deletion. An expired record is consumed
    /// but not returned. Only one concurrent caller consumes a record.
    async fn consume_newest_verification(
        &self,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<Verification>> {
        let mut connection = self.connection().await?;
        connection
            .begin_transaction()
            .await
            .map_err(map_query_err)?;
        let result = self
            .consume_newest_verification_in_transaction(&mut connection, identifier, expected_value)
            .await;
        // Commit only a consumed record. A mismatch or a cancelling hook rolls
        // back, which also discards any rows the hooks wrote.
        let verification = match result {
            Ok(Some(verification)) => connection.finish_transaction(Ok(verification)).await?,
            other => return connection.abort_transaction(other).await,
        };

        let hook_connection = HookConnection::borrowed(&self.pool, &mut connection);
        let hook_context = self.hook_context(&hook_connection);
        for hook in self.hooks() {
            hook.after_delete_verification(&verification, &hook_context)
                .await?;
        }
        Ok((verification.expires_at >= Utc::now()).then_some(verification))
    }

    async fn consume_newest_verification_in_transaction(
        &self,
        connection: &mut DieselConnection,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<Verification>> {
        let Some(verification) = first_for_update!(
            &mut *connection,
            verifications::table
                .filter(verifications::identifier.eq(identifier))
                .order(verifications::created_at.desc())
                .select(Verification::as_select())
        )?
        else {
            return Ok(None);
        };
        if expected_value.is_some_and(|value| verification.value != value) {
            return Ok(None);
        }

        let connection = HookConnection::transaction(&self.pool, connection);
        let hook_context = self.hook_context(&connection);
        for hook in self.hooks() {
            if hook
                .before_delete_verification(&verification, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }

        let deleted = run_query!(lock connection, |c| {
            diesel::delete(verifications::table.find(&verification.id))
                .execute(c)
                .await
        })?;
        if deleted == 0 {
            return Ok(None);
        }
        let _ = run_query!(lock connection, |c| {
            diesel::delete(verifications::table.filter(verifications::identifier.eq(identifier)))
                .execute(c)
                .await
        })?;
        Ok(Some(verification))
    }
}
