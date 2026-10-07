use better_auth_core::store::{ConsumeApiKeyResult, SecondaryStorage};
use better_auth_core::{ApiKey, AuthContext, AuthError, AuthResult};
use chrono::Utc;

use super::{ApiKeyConfig, ApiKeyStorage, cached, now, put, required_backend};

async fn merge_usage(
    storage: &dyn SecondaryStorage,
    snapshot: &ApiKey,
    changed_rate: bool,
    changed_count: bool,
) -> AuthResult<ApiKey> {
    let mut fresh = cached(storage, &format!("api-key:{}", snapshot.key_hash))
        .await?
        .ok_or_else(|| AuthError::internal("Failed to update API key"))?;
    fresh.remaining = snapshot.remaining;
    fresh.last_refill_at.clone_from(&snapshot.last_refill_at);
    fresh.updated_at.clone_from(&snapshot.updated_at);
    if changed_rate {
        fresh.last_request.clone_from(&snapshot.last_request);
    }
    if changed_count {
        fresh.request_count = snapshot.request_count;
    }
    put(storage, &fresh, false).await?;
    Ok(fresh)
}

pub(in crate::plugins::api_key) async fn consume(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    key: &ApiKey,
) -> AuthResult<ConsumeApiKeyResult> {
    if key.remaining == Some(0.0) && key.refill_amount.is_none() {
        super::delete_for_verification(config, ctx, key).await?;
        return Ok(ConsumeApiKeyResult::UsageExhausted);
    }
    if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
        let result = ctx
            .database
            .consume_api_key_usage(key, config.rate_limit.enabled)
            .await?;
        if config.storage == ApiKeyStorage::SecondaryStorage
            && let ConsumeApiKeyResult::Allowed(key) = &result
        {
            put(required_backend(config, ctx)?.as_ref(), key, true).await?;
        }
        return Ok(result);
    }

    let mut snapshot = key.clone();
    let milliseconds = Utc::now().timestamp_millis() as f64;
    let current = now();
    if let Some(mut remaining) = key.remaining {
        if let (Some(interval), Some(amount)) = (key.refill_interval, key.refill_amount)
            && interval != 0.0
            && amount != 0.0
            && (milliseconds
                - key
                    .last_refill_at
                    .as_ref()
                    .unwrap_or(&key.created_at)
                    .milliseconds())
                > interval
        {
            remaining = amount;
            snapshot.last_refill_at = Some(current.clone());
        }
        if remaining == 0.0 {
            return Ok(ConsumeApiKeyResult::UsageExhausted);
        }
        snapshot.remaining = Some(remaining - 1.0);
    }
    let mut changed_rate = false;
    let mut changed_count = false;
    if !config.rate_limit.enabled || !key.rate_limit_enabled.is_truthy()? {
        snapshot.last_request = Some(current.clone());
        changed_rate = true;
    } else if let (Some(window), Some(max)) = (key.rate_limit_time_window, key.rate_limit_max) {
        let elapsed = key
            .last_request
            .as_ref()
            .map(|last| milliseconds - last.milliseconds());
        if let Some(elapsed) = elapsed
            && elapsed <= window
            && key.request_count.unwrap_or(0.0) >= max
        {
            // The secondary-only branch rejects before any quota write, unlike the database branch.
            return Ok(ConsumeApiKeyResult::RateLimited {
                try_again_in: (window - elapsed).ceil(),
            });
        }
        snapshot.request_count = Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
            1.0
        } else {
            key.request_count.unwrap_or(0.0) + 1.0
        });
        snapshot.last_request = Some(current.clone());
        changed_rate = true;
        changed_count = true;
    }
    snapshot.updated_at = current;
    let storage = required_backend(config, ctx)?.clone();
    if config.defer_updates {
        let deferred = snapshot.clone();
        let _task = tokio::spawn(async move {
            if let Err(error) =
                merge_usage(storage.as_ref(), &deferred, changed_rate, changed_count).await
            {
                better_auth_core::observability::logger::current().error(
                    "Deferred API key usage update failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
            }
        });
        return Ok(ConsumeApiKeyResult::Allowed(Box::new(snapshot)));
    }
    Ok(ConsumeApiKeyResult::Allowed(Box::new(
        merge_usage(storage.as_ref(), &snapshot, changed_rate, changed_count).await?,
    )))
}
