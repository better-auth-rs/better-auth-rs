use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, QuerySelect, SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use serde_json::{Map, json};
use uuid::Uuid;

use better_auth_core::ApiKeyStart;
use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::{SeaOrmStore, map_db_err, parse_optional_rfc3339, parse_rfc3339};

fn start_for_database(start: ApiKeyStart, backend: DbBackend) -> AuthResult<String> {
    match backend {
        DbBackend::Sqlite => {
            // Bun's SQLite text reader replaces each invalid WTF-8 byte with U+FFFD.
            Ok(String::from_utf8_lossy(&start.to_wtf8()).into_owned())
        }
        // pg and mysql2 encode JS strings through Node's UTF-8 Buffer conversion.
        DbBackend::Postgres | DbBackend::MySql => Ok(String::from_utf16_lossy(start.as_utf16())),
        _ => start.to_utf8().map_err(|error| {
            better_auth_core::DatabaseError::Query(format!(
                "API key start cannot be stored as UTF-8 text: {error}"
            ))
            .into()
        }),
    }
}

/// Apply `UpdateApiKey` fields to a SeaORM active model.
fn apply_update_fields<M: SeaOrmPluginModel>(
    mut active: M::ActiveModel,
    update: UpdateApiKey,
) -> AuthResult<M::ActiveModel> {
    if let Some(name) = update.name {
        set::<M>(&mut active, "name", Some(name))?;
    }
    if let Some(enabled) = update.enabled {
        set::<M>(&mut active, "enabled", enabled)?;
    }
    if let Some(remaining) = update.remaining {
        set::<M>(&mut active, "remaining", Some(remaining))?;
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        set::<M>(&mut active, "rate_limit_enabled", rate_limit_enabled)?;
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        set::<M>(
            &mut active,
            "rate_limit_time_window",
            Some(rate_limit_time_window),
        )?;
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        set::<M>(&mut active, "rate_limit_max", Some(rate_limit_max))?;
    }
    if let Some(refill_interval) = update.refill_interval {
        set::<M>(&mut active, "refill_interval", Some(refill_interval))?;
    }
    if let Some(refill_amount) = update.refill_amount {
        set::<M>(&mut active, "refill_amount", Some(refill_amount))?;
    }
    if let Some(permissions) = update.permissions {
        set::<M>(&mut active, "permissions", Some(permissions))?;
    }
    if let Some(metadata) = update.metadata {
        set::<M>(&mut active, "metadata", Some(metadata))?;
    }
    if let Some(expires_at) = update.expires_at {
        set::<M>(
            &mut active,
            "expires_at",
            parse_optional_rfc3339(expires_at.as_deref(), "expires_at")?,
        )?;
    }
    if let Some(last_request) = update.last_request {
        set::<M>(
            &mut active,
            "last_request",
            parse_optional_rfc3339(last_request.as_deref(), "last_request")?,
        )?;
    }
    if let Some(request_count) = update.request_count {
        set::<M>(&mut active, "request_count", Some(request_count))?;
    }
    if let Some(last_refill_at) = update.last_refill_at {
        set::<M>(
            &mut active,
            "last_refill_at",
            parse_optional_rfc3339(last_refill_at.as_deref(), "last_refill_at")?,
        )?;
    }
    set::<M>(&mut active, "updated_at", Utc::now())?;
    Ok(active)
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> ApiKeyStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now();
        let start = input
            .start
            .map(|start| start_for_database(start, self.connection().get_database_backend()))
            .transpose()?;
        P::ApiKey::active(Map::from_iter([
            ("id".to_owned(), json!(Uuid::new_v4().to_string())),
            ("name".to_owned(), json!(input.name)),
            ("start".to_owned(), json!(start)),
            ("prefix".to_owned(), json!(input.prefix)),
            ("key_hash".to_owned(), json!(input.key_hash)),
            ("reference_id".to_owned(), json!(input.reference_id)),
            ("config_id".to_owned(), json!(input.config_id)),
            ("refill_interval".to_owned(), json!(input.refill_interval)),
            ("refill_amount".to_owned(), json!(input.refill_amount)),
            ("last_refill_at".to_owned(), serde_json::Value::Null),
            ("enabled".to_owned(), json!(input.enabled)),
            (
                "rate_limit_enabled".to_owned(),
                json!(input.rate_limit_enabled),
            ),
            (
                "rate_limit_time_window".to_owned(),
                json!(input.rate_limit_time_window),
            ),
            ("rate_limit_max".to_owned(), json!(input.rate_limit_max)),
            ("request_count".to_owned(), json!(Some(0.0))),
            ("remaining".to_owned(), json!(input.remaining)),
            ("last_request".to_owned(), serde_json::Value::Null),
            (
                "expires_at".to_owned(),
                json!(parse_optional_rfc3339(
                    input.expires_at.as_deref(),
                    "expires_at",
                )?),
            ),
            ("created_at".to_owned(), json!(now)),
            ("updated_at".to_owned(), json!(now)),
            ("permissions".to_owned(), json!(input.permissions)),
            ("metadata".to_owned(), json!(input.metadata)),
        ]))?
        .insert(self.connection())
        .await
        .map_err(map_db_err)?
        .record()
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        Entity::<P::ApiKey>::find()
            .filter(P::ApiKey::column("id")?.eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|model| model.record())
            .transpose()
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        Entity::<P::ApiKey>::find()
            .filter(P::ApiKey::column("key_hash")?.eq(hash))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|model| model.record())
            .transpose()
    }

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        Entity::<P::ApiKey>::find()
            .filter(P::ApiKey::column("reference_id")?.eq(reference_id))
            .order_by_asc(P::ApiKey::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect()
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let Some(model) = Entity::<P::ApiKey>::find()
            .filter(P::ApiKey::column("id")?.eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("API Key not found"));
        };

        let active = apply_update_fields::<P::ApiKey>(model.into_active_model(), update)?;
        active
            .update(self.connection())
            .await
            .map_err(map_db_err)?
            .record()
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
            let Some(model) = Entity::<P::ApiKey>::find()
                .filter(P::ApiKey::column("id")?.eq(id.clone()))
                .lock_exclusive()
                .one(txn)
                .await
                .map_err(map_db_err)?
            else {
                return Err(AuthError::not_found("API Key not found"));
            };

            let now = Utc::now();
            let stored = model.record()?;
            let created_at = parse_rfc3339(&stored.created_at, "created_at")?;
            let last_refill_at =
                parse_optional_rfc3339(stored.last_refill_at.as_deref(), "last_refill_at")?;
            let last_request =
                parse_optional_rfc3339(stored.last_request.as_deref(), "last_request")?;
            let mut update = UpdateApiKey::default();

            if let Some(remaining) = stored.remaining {
                if remaining == 0.0 && stored.refill_amount.is_none() {
                    let _ = Entity::<P::ApiKey>::delete_many()
                        .filter(P::ApiKey::column("id")?.eq(id))
                        .exec(txn)
                        .await
                        .map_err(map_db_err)?;
                    return Ok(ConsumeApiKeyResult::UsageExhausted);
                }

                if let (Some(interval), Some(amount)) =
                    (stored.refill_interval, stored.refill_amount)
                    && interval != 0.0
                    && amount != 0.0
                    && (now.timestamp_millis()
                        - last_refill_at.unwrap_or(created_at).timestamp_millis())
                        as f64
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

            if global_rate_limit_enabled && stored.rate_limit_enabled {
                if let (Some(window), Some(max)) =
                    (stored.rate_limit_time_window, stored.rate_limit_max)
                {
                    let elapsed = last_request
                        .map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
                    if let Some(elapsed) = elapsed
                        && elapsed <= window
                        && stored.request_count.unwrap_or(0.0) >= max
                    {
                        // TS consumes quota before rejecting a rate-limited request.
                        // A rejection preserves the rate-limit window and updated_at.
                        if update.remaining.is_some() {
                            let mut active = apply_update_fields::<P::ApiKey>(
                                model.into_active_model(),
                                update,
                            )?;
                            active.not_set(P::ApiKey::column("updated_at")?);
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
                            stored.request_count.unwrap_or(0.0) + 1.0
                        });
                    update.last_request = Some(Some(now.to_rfc3339()));
                }
            } else {
                update.last_request = Some(Some(now.to_rfc3339()));
            }

            let active = apply_update_fields::<P::ApiKey>(model.into_active_model(), update)?;
            let updated = active.update(txn).await.map_err(map_db_err)?;
            Ok(ConsumeApiKeyResult::Allowed(Box::new(updated.record()?)))
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
        Entity::<P::ApiKey>::delete_many()
            .filter(P::ApiKey::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Single query: DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()
        // Matches TS: adapter.deleteMany({ where: [{ field: "expiresAt", operator: "lt", value: new Date() }, ...] })
        Entity::<P::ApiKey>::delete_many()
            .filter(P::ApiKey::column("expires_at")?.is_not_null())
            .filter(P::ApiKey::column("expires_at")?.lt(Utc::now()))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }
}

#[cfg(test)]
#[path = "api_key_concurrency_tests.rs"]
mod concurrency_tests;

#[cfg(test)]
mod start_tests {
    use super::*;

    #[test]
    fn database_text_conversion_preserves_backend_boundaries() {
        let split = ApiKeyStart::prefix("😀abcdefgh", 1);
        assert_eq!(
            start_for_database(split.clone(), DbBackend::Sqlite).unwrap(),
            "���"
        );
        for backend in [DbBackend::Postgres, DbBackend::MySql] {
            assert_eq!(start_for_database(split.clone(), backend).unwrap(), "�");
        }
        for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
            assert_eq!(
                start_for_database(ApiKeyStart::prefix("😀abcdefgh", 6), backend).unwrap(),
                "😀abcd"
            );
        }
    }
}
