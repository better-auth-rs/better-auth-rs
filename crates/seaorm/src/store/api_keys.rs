use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait,
};
use uuid::Uuid;

use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::entities::api_key::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err, parse_optional_rfc3339, to_i32, to_optional_i32};

/// Apply `UpdateApiKey` fields to a SeaORM active model.
fn apply_update_fields(mut active: ActiveModel, update: UpdateApiKey) -> AuthResult<ActiveModel> {
    if let Some(name) = update.name {
        active.name = Set(Some(name));
    }
    if let Some(enabled) = update.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(remaining) = update.remaining {
        active.remaining = Set(Some(to_i32(remaining, "remaining")?));
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        active.rate_limit_enabled = Set(rate_limit_enabled);
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        active.rate_limit_time_window = Set(Some(to_i32(
            rate_limit_time_window,
            "rate_limit_time_window",
        )?));
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        active.rate_limit_max = Set(Some(to_i32(rate_limit_max, "rate_limit_max")?));
    }
    if let Some(refill_interval) = update.refill_interval {
        active.refill_interval = Set(Some(to_i32(refill_interval, "refill_interval")?));
    }
    if let Some(refill_amount) = update.refill_amount {
        active.refill_amount = Set(Some(to_i32(refill_amount, "refill_amount")?));
    }
    if let Some(permissions) = update.permissions {
        active.permissions = Set(Some(permissions));
    }
    if let Some(metadata) = update.metadata {
        active.metadata = Set(Some(metadata));
    }
    if let Some(expires_at) = update.expires_at {
        active.expires_at = Set(parse_optional_rfc3339(expires_at.as_deref(), "expires_at")?);
    }
    if let Some(last_request) = update.last_request {
        active.last_request = Set(parse_optional_rfc3339(
            last_request.as_deref(),
            "last_request",
        )?);
    }
    if let Some(request_count) = update.request_count {
        active.request_count = Set(Some(to_i32(request_count, "request_count")?));
    }
    if let Some(last_refill_at) = update.last_refill_at {
        active.last_refill_at = Set(parse_optional_rfc3339(
            last_refill_at.as_deref(),
            "last_refill_at",
        )?);
    }
    active.updated_at = Set(Utc::now());
    Ok(active)
}

#[async_trait]
impl<S> ApiKeyStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now();
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(input.name),
            start: Set(input.start),
            prefix: Set(input.prefix),
            key_hash: Set(input.key_hash),
            user_id: Set(input.user_id),
            refill_interval: Set(to_optional_i32(input.refill_interval, "refill_interval")?),
            refill_amount: Set(to_optional_i32(input.refill_amount, "refill_amount")?),
            last_refill_at: Set(None),
            enabled: Set(input.enabled),
            rate_limit_enabled: Set(input.rate_limit_enabled),
            rate_limit_time_window: Set(to_optional_i32(
                input.rate_limit_time_window,
                "rate_limit_time_window",
            )?),
            rate_limit_max: Set(to_optional_i32(input.rate_limit_max, "rate_limit_max")?),
            request_count: Set(Some(0)),
            remaining: Set(to_optional_i32(input.remaining, "remaining")?),
            last_request: Set(None),
            expires_at: Set(parse_optional_rfc3339(
                input.expires_at.as_deref(),
                "expires_at",
            )?),
            created_at: Set(now),
            updated_at: Set(now),
            permissions: Set(input.permissions),
            metadata: Set(input.metadata),
        }
        .insert(self.connection())
        .await
        .map(|model| ApiKey::from(&model))
        .map_err(map_db_err)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| ApiKey::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        Entity::find()
            .filter(Column::KeyHash.eq(hash))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| ApiKey::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(ApiKey::from).collect())
            .map_err(map_db_err)
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("API key not found"));
        };

        let active = apply_update_fields(model.into_active_model(), update)?;
        active
            .update(self.connection())
            .await
            .map(|model| ApiKey::from(&model))
            .map_err(map_db_err)
    }

    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let conn = self.connection();
        conn.transaction::<_, ConsumeApiKeyResult, AuthError>(|txn| {
            let id = id.to_owned();
            Box::pin(async move {
                let Some(model) = Entity::find_by_id(id.clone())
                    .lock_exclusive()
                    .one(txn)
                    .await
                    .map_err(map_db_err)?
                else {
                    return Err(AuthError::not_found("API key not found"));
                };

                let now = Utc::now();
                let mut update = UpdateApiKey::default();

                // -- Remaining / refill (from locked row) --
                if let Some(remaining) = model.remaining {
                    let remaining = remaining as i64;
                    let refill_interval = model.refill_interval.map(|v| v as i64);
                    let refill_amount = model.refill_amount.map(|v| v as i64);
                    let mut current = remaining;

                    if let (Some(interval), Some(amount)) = (refill_interval, refill_amount) {
                        let last_refill = model.last_refill_at.or(Some(model.created_at));
                        if let Some(last) = last_refill {
                            let elapsed_ms = (now - last).num_milliseconds();
                            if elapsed_ms > interval {
                                current = amount;
                                update.last_refill_at = Some(Some(now.to_rfc3339()));
                            }
                        }
                    }

                    if current <= 0 && refill_amount.is_none() {
                        // Usage exhausted, no refill — delete the key
                        let _ = Entity::delete_by_id(id)
                            .exec(txn)
                            .await
                            .map_err(map_db_err)?;
                        return Ok(ConsumeApiKeyResult::UsageExhausted);
                    }

                    if current <= 0 {
                        return Ok(ConsumeApiKeyResult::UsageExhausted);
                    }

                    update.remaining = Some(current - 1);
                }

                // -- Rate limiting (from locked row) --
                let rate_limit_active = global_rate_limit_enabled && model.rate_limit_enabled;
                if rate_limit_active {
                    if let (Some(tw), Some(max)) = (
                        model.rate_limit_time_window.map(|v| v as i64),
                        model.rate_limit_max.map(|v| v as i64),
                    ) {
                        let request_count = model.request_count.unwrap_or(0) as i64;

                        let window_expired = model
                            .last_request
                            .map(|lr| (now - lr).num_milliseconds() > tw)
                            .unwrap_or(true);

                        if window_expired {
                            update.request_count = Some(1);
                        } else if request_count >= max {
                            return Ok(ConsumeApiKeyResult::RateLimited);
                        } else {
                            update.request_count = Some(request_count + 1);
                        }

                        update.last_request = Some(Some(now.to_rfc3339()));
                    } else {
                        update.last_request = Some(Some(now.to_rfc3339()));
                    }
                } else {
                    update.last_request = Some(Some(now.to_rfc3339()));
                }

                let active = apply_update_fields(model.into_active_model(), update)?;
                let updated = active.update(txn).await.map_err(map_db_err)?;
                Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
                    &updated,
                ))))
            })
        })
        .await
        .map_err(|e| match e {
            sea_orm::TransactionError::Connection(db_err) => map_db_err(db_err),
            sea_orm::TransactionError::Transaction(auth_err) => auth_err,
        })
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Single query: DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()
        // Matches TS: adapter.deleteMany({ where: [{ field: "expiresAt", operator: "lt", value: new Date() }, ...] })
        Entity::delete_many()
            .filter(Column::ExpiresAt.is_not_null())
            .filter(Column::ExpiresAt.lt(Utc::now()))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }
}
