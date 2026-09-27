use async_trait::async_trait;
use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};
use better_auth_core::{ApiKey, CreateApiKey, UpdateApiKey};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::connection::DieselConnection;
use crate::error::{AuthError, AuthResult, map_query_err};
use crate::models::{ApiKeyChanges, ApiKeyRow};
use crate::schema::api_keys;
use crate::sql_types::{NullableUtcTimestampValue, UtcTimestampValue};

use super::{DieselStore, new_id, parse_optional_rfc3339, to_i32, to_optional_i32};

fn optional_timestamp(
    value: Option<Option<String>>,
    field: &str,
) -> AuthResult<Option<NullableUtcTimestampValue>> {
    value
        .map(|inner| parse_optional_rfc3339(inner.as_deref(), field).map(NullableUtcTimestampValue))
        .transpose()
}

fn api_key_changes(update: UpdateApiKey, now: DateTime<Utc>) -> AuthResult<ApiKeyChanges> {
    Ok(ApiKeyChanges {
        name: update.name,
        enabled: update.enabled,
        remaining: to_optional_i32(update.remaining, "remaining")?,
        rate_limit_enabled: update.rate_limit_enabled,
        rate_limit_time_window: to_optional_i32(
            update.rate_limit_time_window,
            "rate_limit_time_window",
        )?,
        rate_limit_max: to_optional_i32(update.rate_limit_max, "rate_limit_max")?,
        refill_interval: to_optional_i32(update.refill_interval, "refill_interval")?,
        refill_amount: to_optional_i32(update.refill_amount, "refill_amount")?,
        permissions: update.permissions,
        metadata: update.metadata,
        expires_at: optional_timestamp(update.expires_at, "expires_at")?,
        last_request: optional_timestamp(update.last_request, "last_request")?,
        request_count: to_optional_i32(update.request_count, "request_count")?,
        last_refill_at: optional_timestamp(update.last_refill_at, "last_refill_at")?,
        updated_at: Some(UtcTimestampValue(now)),
    })
}

/// Outcome of one API key use, decided from the locked row.
enum KeyUsage {
    /// The quota is exhausted and never refills: delete the key.
    Delete,
    Exhausted,
    RateLimited,
    Allowed(ApiKeyChanges),
}

/// Decide the effect of one use of `row` at `now`.
///
/// Refill and rate-limit windows are in milliseconds.
fn key_usage(row: &ApiKeyRow, now: DateTime<Utc>, global_rate_limit_enabled: bool) -> KeyUsage {
    let mut changes = ApiKeyChanges {
        updated_at: Some(UtcTimestampValue(now)),
        ..ApiKeyChanges::default()
    };

    if let Some(remaining) = row.remaining {
        let mut current = remaining;
        if let (Some(interval), Some(amount)) = (row.refill_interval, row.refill_amount) {
            let last_refill = row.last_refill_at.unwrap_or(row.created_at);
            if (now - last_refill).num_milliseconds() > i64::from(interval) {
                current = amount;
                changes.last_refill_at = Some(NullableUtcTimestampValue(Some(now)));
            }
        }

        if current <= 0 {
            return if row.refill_amount.is_none() {
                KeyUsage::Delete
            } else {
                KeyUsage::Exhausted
            };
        }
        changes.remaining = Some(current - 1);
    }

    if global_rate_limit_enabled
        && row.rate_limit_enabled
        && let (Some(window), Some(max)) = (row.rate_limit_time_window, row.rate_limit_max)
    {
        let window_expired = row
            .last_request
            .is_none_or(|last| (now - last).num_milliseconds() > i64::from(window));
        let request_count = row.request_count.unwrap_or(0);

        if window_expired {
            changes.request_count = Some(1);
        } else if request_count >= max {
            return KeyUsage::RateLimited;
        } else {
            changes.request_count = Some(request_count + 1);
        }
    }

    changes.last_request = Some(NullableUtcTimestampValue(Some(now)));
    KeyUsage::Allowed(changes)
}

/// Load an API key and lock it until the enclosing transaction ends.
///
/// SQLite has no row locks; its transactions begin with `BEGIN IMMEDIATE`,
/// which already excludes other writers.
async fn lock_api_key(
    connection: &mut DieselConnection,
    id: &str,
) -> AuthResult<Option<ApiKeyRow>> {
    let row = match connection {
        #[cfg(feature = "postgres")]
        DieselConnection::Postgres(object) => api_keys::table
            .find(id)
            .select(ApiKeyRow::as_select())
            .for_update()
            .first(&mut **object)
            .await
            .optional(),
        #[cfg(feature = "sqlite")]
        DieselConnection::Sqlite(object) => api_keys::table
            .find(id)
            .select(ApiKeyRow::as_select())
            .first(&mut **object)
            .await
            .optional(),
    };
    row.map_err(map_query_err)
}

async fn consume_locked(
    connection: &mut DieselConnection,
    id: &str,
    global_rate_limit_enabled: bool,
) -> AuthResult<ConsumeApiKeyResult> {
    let Some(row) = lock_api_key(connection, id).await? else {
        return Err(AuthError::not_found("API Key not found"));
    };

    match key_usage(&row, Utc::now(), global_rate_limit_enabled) {
        KeyUsage::Delete => {
            let _ = run_query!(on connection, |c| {
                diesel::delete(api_keys::table.find(id)).execute(c).await
            })?;
            Ok(ConsumeApiKeyResult::UsageExhausted)
        }
        KeyUsage::Exhausted => Ok(ConsumeApiKeyResult::UsageExhausted),
        KeyUsage::RateLimited => Ok(ConsumeApiKeyResult::RateLimited),
        KeyUsage::Allowed(changes) => {
            let updated = run_query!(on connection, |c| {
                diesel::update(api_keys::table.find(id))
                    .set(changes)
                    .returning(ApiKeyRow::as_returning())
                    .get_result(c)
                    .await
            })?;
            Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
                updated,
            ))))
        }
    }
}

#[async_trait]
impl ApiKeyStore for DieselStore {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now();
        let row = ApiKeyRow {
            id: new_id(),
            name: input.name,
            start: input.start,
            prefix: input.prefix,
            key_hash: input.key_hash,
            reference_id: input.reference_id,
            config_id: input.config_id,
            refill_interval: to_optional_i32(input.refill_interval, "refill_interval")?,
            refill_amount: to_optional_i32(input.refill_amount, "refill_amount")?,
            last_refill_at: None,
            enabled: input.enabled,
            rate_limit_enabled: input.rate_limit_enabled,
            rate_limit_time_window: to_optional_i32(
                input.rate_limit_time_window,
                "rate_limit_time_window",
            )?,
            rate_limit_max: to_optional_i32(input.rate_limit_max, "rate_limit_max")?,
            request_count: Some(0),
            remaining: input
                .remaining
                .map(|remaining| to_i32(remaining, "remaining"))
                .transpose()?,
            last_request: None,
            expires_at: parse_optional_rfc3339(input.expires_at.as_deref(), "expires_at")?,
            created_at: now,
            updated_at: now,
            permissions: input.permissions,
            metadata: input.metadata,
        };

        run_query!(self, |c| {
            diesel::insert_into(api_keys::table)
                .values(row)
                .returning(ApiKeyRow::as_returning())
                .get_result(c)
                .await
        })
        .map(ApiKey::from)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        run_query!(self, |c| {
            api_keys::table
                .find(id)
                .select(ApiKeyRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(ApiKey::from))
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        run_query!(self, |c| {
            api_keys::table
                .filter(api_keys::key_hash.eq(hash))
                .select(ApiKeyRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(ApiKey::from))
    }

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        run_query!(self, |c| {
            api_keys::table
                .filter(api_keys::reference_id.eq(reference_id))
                .order(api_keys::created_at.asc())
                .select(ApiKeyRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(ApiKey::from).collect())
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let changes = api_key_changes(update, Utc::now())?;
        run_query!(self, |c| {
            diesel::update(api_keys::table.find(id))
                .set(changes)
                .returning(ApiKeyRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(ApiKey::from)
        .ok_or_else(|| AuthError::not_found("API Key not found"))
    }

    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let mut connection = self.connection().await?;
        connection
            .begin_transaction()
            .await
            .map_err(map_query_err)?;
        let result = consume_locked(&mut connection, id, global_rate_limit_enabled).await;
        connection.finish_transaction(result).await
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(api_keys::table.find(id)).execute(c).await
        })?;
        Ok(())
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Matches TS: adapter.deleteMany({ where: [{ field: "expiresAt", operator: "lt", value: new Date() }, ...] })
        run_query!(self, |c| {
            diesel::delete(
                api_keys::table
                    .filter(api_keys::expires_at.is_not_null())
                    .filter(api_keys::expires_at.lt(UtcTimestampValue(Utc::now()))),
            )
            .execute(c)
            .await
        })
    }
}
