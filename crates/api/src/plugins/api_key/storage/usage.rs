use better_auth_core::store::{ApiKeyRateLimitDecision, ConsumeApiKeyResult, SecondaryStorage};
use better_auth_core::{
    ApiKey, AuthContext, AuthRecordFields, AuthResult, FieldDate, FieldMap, FieldValue,
    SchemaValue,
    background::BackgroundFuture,
    query::{field_add, field_date, field_number},
};
use std::sync::Arc;

use super::{ApiKeyConfig, ApiKeyStorage, cached, put, required_backend};
use crate::plugins::api_key::{ApiKeyErrorCode, api_key_error};

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;

enum RateLimitSnapshot {
    Changes(FieldMap),
    RateLimited { try_again_in: f64 },
}

fn apply_rate_limit_to_snapshot(
    key: &ApiKey,
    enabled: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> AuthResult<RateLimitSnapshot> {
    let changes = match ApiKeyRateLimitDecision::evaluate(key, enabled, now)? {
        ApiKeyRateLimitDecision::Skip(None) => FieldMap::new(),
        ApiKeyRateLimitDecision::Skip(Some(at)) => {
            FieldMap::from([("lastRequest".into(), at.into())])
        }
        ApiKeyRateLimitDecision::Deny { try_again_in } => {
            return Ok(RateLimitSnapshot::RateLimited { try_again_in });
        }
        ApiKeyRateLimitDecision::Start { at, .. } => FieldMap::from([
            ("lastRequest".into(), at.into()),
            ("requestCount".into(), 1.0.into()),
        ]),
        ApiKeyRateLimitDecision::Increment { at, .. } => FieldMap::from([
            ("lastRequest".into(), at.into()),
            (
                "requestCount".into(),
                field_add(&key.request_count.field_value(), &1.0.into())?,
            ),
        ]),
    };
    Ok(RateLimitSnapshot::Changes(changes))
}

async fn merge_usage(
    storage: Arc<dyn SecondaryStorage>,
    snapshot: &ApiKey,
    lookup_hash: &str,
    changed_rate: bool,
    changed_count: bool,
) -> AuthResult<Option<ApiKey>> {
    let Some(mut fresh) = cached(storage.clone(), &format!("api-key:{lookup_hash}")).await? else {
        return Ok(None);
    };
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
    Ok(Some(fresh))
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
            put(required_backend(config, ctx)?.clone(), key, true).await?;
        }
        return Ok(result);
    }

    let mut snapshot = key.clone();
    let mut remaining = key.remaining.field_value();
    if !remaining.is_null() {
        let milliseconds = ctx.now().timestamp_millis() as f64;
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
            snapshot.last_refill_at = Some(FieldDate::from(ctx.now())).into();
        }
        if remaining.strict_equals(&0.0.into()) {
            return Ok(ConsumeApiKeyResult::UsageExhausted);
        }
        snapshot.remaining = Some(field_number(&remaining)? - 1.0).into();
    }
    let changes = match apply_rate_limit_to_snapshot(key, config.rate_limit.enabled, ctx.now())? {
        RateLimitSnapshot::Changes(changes) => changes,
        RateLimitSnapshot::RateLimited { try_again_in } => {
            // Secondary storage rejects before the quota write; database consumption writes quota first.
            return Ok(ConsumeApiKeyResult::RateLimited { try_again_in });
        }
    };
    let changed_rate = changes.contains_key("lastRequest");
    let changed_count = changes.contains_key("requestCount");
    if let Some(value) = changes.get("lastRequest") {
        snapshot.last_request = SchemaValue::from_field(value.clone());
    }
    if let Some(value) = changes.get("requestCount") {
        snapshot.request_count = SchemaValue::from_field(value.clone());
    }
    snapshot.updated_at = FieldDate::from(ctx.now()).into();
    let storage = required_backend(config, ctx)?.clone();
    if config.defer_updates {
        let deferred = snapshot.clone();
        let lookup_hash = lookup_hash.to_owned();
        better_auth_core::background::run_in_background_with_error_message(
            BackgroundFuture::native(async move {
                match merge_usage(
                    storage,
                    &deferred,
                    &lookup_hash,
                    changed_rate,
                    changed_count,
                )
                .await?
                {
                    Some(key) => key.field_values().map(FieldValue::from),
                    None => Ok(FieldValue::Null),
                }
            }),
            ctx.config.advanced.background_tasks.as_ref(),
            ctx.logger(),
            "Failed to update API key:",
        )
        .await?;
        return Ok(ConsumeApiKeyResult::Allowed(Box::new(snapshot)));
    }
    let updated = merge_usage(storage, &snapshot, lookup_hash, changed_rate, changed_count)
        .await?
        .ok_or_else(|| {
            api_key_error(
                "INTERNAL_SERVER_ERROR",
                ApiKeyErrorCode::FailedToUpdateApiKey,
            )
        })?;
    Ok(ConsumeApiKeyResult::Allowed(Box::new(updated)))
}
