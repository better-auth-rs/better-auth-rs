use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set, SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use uuid::Uuid;

use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::entities::api_key::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err, parse_optional_rfc3339};

/// Apply `UpdateApiKey` fields to a SeaORM active model.
fn apply_update_fields(mut active: ActiveModel, update: UpdateApiKey) -> AuthResult<ActiveModel> {
    if let Some(name) = update.name {
        active.name = Set(Some(name));
    }
    if let Some(enabled) = update.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(remaining) = update.remaining {
        active.remaining = Set(Some(remaining));
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        active.rate_limit_enabled = Set(rate_limit_enabled);
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        active.rate_limit_time_window = Set(Some(rate_limit_time_window));
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        active.rate_limit_max = Set(Some(rate_limit_max));
    }
    if let Some(refill_interval) = update.refill_interval {
        active.refill_interval = Set(Some(refill_interval));
    }
    if let Some(refill_amount) = update.refill_amount {
        active.refill_amount = Set(Some(refill_amount));
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
        active.request_count = Set(Some(request_count));
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
impl<S, O: crate::SeaOrmOrganizationSchema> ApiKeyStore for SeaOrmStore<S, O>
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
            reference_id: Set(input.reference_id),
            config_id: Set(input.config_id),
            refill_interval: Set(input.refill_interval),
            refill_amount: Set(input.refill_amount),
            last_refill_at: Set(None),
            enabled: Set(input.enabled),
            rate_limit_enabled: Set(input.rate_limit_enabled),
            rate_limit_time_window: Set(input.rate_limit_time_window),
            rate_limit_max: Set(input.rate_limit_max),
            request_count: Set(Some(0.0)),
            remaining: Set(input.remaining),
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

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        Entity::find()
            .filter(Column::ReferenceId.eq(reference_id))
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
            return Err(AuthError::not_found("API Key not found"));
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
        // SQLite must acquire its write reservation before reading usage counters.
        let transaction = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let txn = &transaction;
        let id = id.to_owned();
        let result = async {
            let Some(model) = Entity::find_by_id(id.clone())
                .lock_exclusive()
                .one(txn)
                .await
                .map_err(map_db_err)?
            else {
                return Err(AuthError::not_found("API Key not found"));
            };

            let now = Utc::now();
            let mut update = UpdateApiKey::default();

            if let Some(remaining) = model.remaining {
                if remaining == 0.0 && model.refill_amount.is_none() {
                    let _ = Entity::delete_by_id(id)
                        .exec(txn)
                        .await
                        .map_err(map_db_err)?;
                    return Ok(ConsumeApiKeyResult::UsageExhausted);
                }

                if let (Some(interval), Some(amount)) = (model.refill_interval, model.refill_amount)
                    && interval != 0.0
                    && amount != 0.0
                    && (now.timestamp_millis()
                        - model
                            .last_refill_at
                            .unwrap_or(model.created_at)
                            .timestamp_millis()) as f64
                        > interval
                {
                    update.remaining = Some(amount - 1.0);
                    update.last_refill_at = Some(Some(now.to_rfc3339()));
                } else if remaining > 0.0 {
                    update.remaining = Some(remaining - 1.0);
                } else {
                    return Ok(ConsumeApiKeyResult::UsageExhausted);
                }
            }

            if global_rate_limit_enabled && model.rate_limit_enabled {
                if let (Some(window), Some(max)) =
                    (model.rate_limit_time_window, model.rate_limit_max)
                {
                    let elapsed = model
                        .last_request
                        .map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
                    if let Some(elapsed) = elapsed
                        && elapsed <= window
                        && model.request_count.unwrap_or(0.0) >= max
                    {
                        // TS consumes quota before rejecting a rate-limited request.
                        // A rejection preserves the rate-limit window and updated_at.
                        if update.remaining.is_some() {
                            let updated_at = model.updated_at;
                            let mut active =
                                apply_update_fields(model.into_active_model(), update)?;
                            active.updated_at = Set(updated_at);
                            let _ = active.update(txn).await.map_err(map_db_err)?;
                        }
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }

                    update.request_count =
                        Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
                            1.0
                        } else {
                            model.request_count.unwrap_or(0.0) + 1.0
                        });
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
        }
        .await;
        if result.is_ok() {
            transaction.commit().await.map_err(map_db_err)?;
        } else {
            transaction.rollback().await.map_err(map_db_err)?;
        }
        result
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

#[cfg(test)]
#[path = "api_key_concurrency_tests.rs"]
mod concurrency_tests;
