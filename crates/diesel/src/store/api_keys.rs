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

use super::{DieselStore, new_id, parse_optional_rfc3339};

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
        remaining: update.remaining,
        rate_limit_enabled: update.rate_limit_enabled,
        rate_limit_time_window: update.rate_limit_time_window,
        rate_limit_max: update.rate_limit_max,
        refill_interval: update.refill_interval,
        refill_amount: update.refill_amount,
        permissions: update.permissions,
        metadata: update.metadata,
        expires_at: optional_timestamp(update.expires_at, "expires_at")?,
        last_request: optional_timestamp(update.last_request, "last_request")?,
        request_count: update.request_count,
        last_refill_at: optional_timestamp(update.last_refill_at, "last_refill_at")?,
        updated_at: Some(UtcTimestampValue(now)),
    })
}

/// Outcome of one API key use, decided from the locked row.
enum KeyUsage {
    /// The quota is spent and never refills: delete the key.
    Delete,
    Exhausted,
    /// The rate limit rejects the request. `quota` holds the quota already
    /// consumed by it, which is stored without touching the rate-limit window
    /// or `updated_at`.
    RateLimited {
        try_again_in: f64,
        quota: Option<ApiKeyChanges>,
    },
    Allowed(ApiKeyChanges),
}

fn elapsed_ms(since: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
    (now.timestamp_millis() - since.timestamp_millis()) as f64
}

/// Decide the effect of one use of `row` at `now`.
///
/// Refill and rate-limit windows are in milliseconds.
fn key_usage(row: &ApiKeyRow, now: DateTime<Utc>, global_rate_limit_enabled: bool) -> KeyUsage {
    let mut quota = None;
    if let Some(remaining) = row.remaining {
        if remaining == 0.0 && row.refill_amount.is_none() {
            return KeyUsage::Delete;
        }
        let refill = match (row.refill_interval, row.refill_amount) {
            (Some(interval), Some(amount))
                if interval != 0.0
                    && amount != 0.0
                    && elapsed_ms(row.last_refill_at.unwrap_or(row.created_at), now) > interval =>
            {
                Some(amount)
            }
            _ => None,
        };
        quota = Some(match refill {
            Some(amount) => ApiKeyChanges {
                remaining: Some(amount - 1.0),
                last_refill_at: Some(NullableUtcTimestampValue(Some(now))),
                ..ApiKeyChanges::default()
            },
            None if remaining > 0.0 => ApiKeyChanges {
                remaining: Some(remaining - 1.0),
                ..ApiKeyChanges::default()
            },
            None => return KeyUsage::Exhausted,
        });
    }

    let mut changes = quota.unwrap_or_default();
    if global_rate_limit_enabled && row.rate_limit_enabled {
        if let (Some(window), Some(max)) = (row.rate_limit_time_window, row.rate_limit_max) {
            let elapsed = row.last_request.map(|last| elapsed_ms(last, now));
            if let Some(elapsed) = elapsed
                && elapsed <= window
                && row.request_count.unwrap_or(0.0) >= max
            {
                // TS consumes quota before it rejects a rate-limited request.
                return KeyUsage::RateLimited {
                    try_again_in: (window - elapsed).ceil(),
                    quota: changes.remaining.is_some().then_some(changes),
                };
            }
            changes.request_count = Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
                1.0
            } else {
                row.request_count.unwrap_or(0.0) + 1.0
            });
            changes.last_request = Some(NullableUtcTimestampValue(Some(now)));
        }
    } else {
        changes.last_request = Some(NullableUtcTimestampValue(Some(now)));
    }
    changes.updated_at = Some(UtcTimestampValue(now));
    KeyUsage::Allowed(changes)
}

async fn consume_locked(
    connection: &mut DieselConnection,
    id: &str,
    global_rate_limit_enabled: bool,
) -> AuthResult<ConsumeApiKeyResult> {
    let Some(row) = first_for_update!(
        connection,
        api_keys::table.find(id).select(ApiKeyRow::as_select())
    )?
    else {
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
        KeyUsage::RateLimited {
            try_again_in,
            quota,
        } => {
            if let Some(quota) = quota {
                let _ = run_query!(on connection, |c| {
                    diesel::update(api_keys::table.find(id))
                        .set(quota)
                        .execute(c)
                        .await
                })?;
            }
            Ok(ConsumeApiKeyResult::RateLimited { try_again_in })
        }
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
            refill_interval: input.refill_interval,
            refill_amount: input.refill_amount,
            last_refill_at: None,
            enabled: input.enabled,
            rate_limit_enabled: input.rate_limit_enabled,
            rate_limit_time_window: input.rate_limit_time_window,
            rate_limit_max: input.rate_limit_max,
            request_count: Some(0.0),
            remaining: input.remaining,
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
