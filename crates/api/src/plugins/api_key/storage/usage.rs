use better_auth_core::store::{ConsumeApiKeyResult, SecondaryStorage};
use better_auth_core::{
    ApiKey, AuthContext, AuthError, AuthResult, SchemaValue,
    query::{field_add, field_compare, field_date, field_number},
};
use chrono::Utc;

use super::{ApiKeyConfig, ApiKeyStorage, cached, now, put, required_backend};

async fn merge_usage(
    storage: &dyn SecondaryStorage,
    snapshot: &ApiKey,
    lookup_hash: &str,
    changed_rate: bool,
    changed_count: bool,
) -> AuthResult<ApiKey> {
    let mut fresh = cached(storage, &format!("api-key:{lookup_hash}"))
        .await?
        .ok_or_else(|| AuthError::internal("Failed to update API key"))?;
    fresh.remaining.clone_from(&snapshot.remaining);
    fresh.last_refill_at.clone_from(&snapshot.last_refill_at);
    fresh.updated_at.clone_from(&snapshot.updated_at);
    if changed_rate {
        fresh.last_request.clone_from(&snapshot.last_request);
    }
    if changed_count {
        fresh.request_count.clone_from(&snapshot.request_count);
    }
    put(storage, &fresh, false).await?;
    Ok(fresh)
}

pub(in crate::plugins::api_key) async fn consume(
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    key: &ApiKey,
    lookup_hash: &str,
) -> AuthResult<ConsumeApiKeyResult> {
    if key.remaining.field_value().strict_equals(&0.0.into())
        && key.refill_amount.field_value().is_null()
    {
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
    let mut remaining = key.remaining.field_value();
    if !remaining.is_null() {
        let interval = key.refill_interval.field_value();
        let amount = key.refill_amount.field_value();
        let previous = key.last_refill_at.field_value();
        let previous = if previous.is_null() || previous.is_undefined() {
            key.created_at.field_value()
        } else {
            previous
        };
        let last_time = field_date(&previous)?.milliseconds();
        if interval.is_truthy()
            && amount.is_truthy()
            && milliseconds - last_time > field_number(&interval)?
        {
            remaining = amount;
            snapshot.last_refill_at = Some(current.clone()).into();
        }
        if remaining.strict_equals(&0.0.into()) {
            return Ok(ConsumeApiKeyResult::UsageExhausted);
        }
        snapshot.remaining = Some(field_number(&remaining)? - 1.0).into();
    }
    let mut changed_rate = false;
    let mut changed_count = false;
    let window = key.rate_limit_time_window.field_value();
    let maximum = key.rate_limit_max.field_value();
    if !config.rate_limit.enabled
        || key
            .rate_limit_enabled
            .field_value()
            .strict_equals(&false.into())
    {
        snapshot.last_request = Some(current.clone()).into();
        changed_rate = true;
    } else if !window.is_null() && !maximum.is_null() {
        let last = key.last_request.field_value();
        let elapsed = milliseconds - field_date(&last)?.milliseconds();
        let window = field_number(&window)?;
        let start = last.is_null() || elapsed > window;
        if !start
            && matches!(
                field_compare(&key.request_count.field_value(), &maximum)?,
                Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
            )
        {
            // Secondary storage rejects before the quota write; database consumption writes quota first.
            return Ok(ConsumeApiKeyResult::RateLimited {
                try_again_in: (window - elapsed).ceil(),
            });
        }
        snapshot.request_count = SchemaValue::from_field(if start {
            1.0.into()
        } else {
            field_add(&key.request_count.field_value(), &1.0.into())?
        });
        snapshot.last_request = Some(current.clone()).into();
        changed_rate = true;
        changed_count = true;
    }
    snapshot.updated_at = current.into();
    let storage = required_backend(config, ctx)?.clone();
    if config.defer_updates {
        let deferred = snapshot.clone();
        let lookup_hash = lookup_hash.to_owned();
        let _task = tokio::spawn(async move {
            if let Err(error) = merge_usage(
                storage.as_ref(),
                &deferred,
                &lookup_hash,
                changed_rate,
                changed_count,
            )
            .await
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
        merge_usage(
            storage.as_ref(),
            &snapshot,
            lookup_hash,
            changed_rate,
            changed_count,
        )
        .await?,
    )))
}
