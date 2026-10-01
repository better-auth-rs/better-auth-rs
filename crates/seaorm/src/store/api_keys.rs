use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, ExprTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, sea_query::Expr,
};
use serde_json::{Map, json};

use better_auth_core::ApiKeyStart;
use better_auth_core::store::{ApiKeyStore, ApiKeyUsageWrite, schema::EntityRole};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::{SeaOrmStore, map_db_err, parse_optional_rfc3339};

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
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<M::ActiveModel> {
    if let Some(enabled) = update.enabled {
        set::<M>(&mut active, "enabled", enabled, policy)?;
    }
    if let Some(remaining) = update.remaining {
        set::<M>(&mut active, "remaining", Some(remaining), policy)?;
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        set::<M>(
            &mut active,
            "rate_limit_enabled",
            rate_limit_enabled,
            policy,
        )?;
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        set::<M>(
            &mut active,
            "rate_limit_time_window",
            Some(rate_limit_time_window),
            policy,
        )?;
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        set::<M>(&mut active, "rate_limit_max", Some(rate_limit_max), policy)?;
    }
    if let Some(refill_interval) = update.refill_interval {
        set::<M>(
            &mut active,
            "refill_interval",
            Some(refill_interval),
            policy,
        )?;
    }
    if let Some(refill_amount) = update.refill_amount {
        set::<M>(&mut active, "refill_amount", Some(refill_amount), policy)?;
    }
    if let Some(permissions) = update.permissions {
        set::<M>(&mut active, "permissions", Some(permissions), policy)?;
    }
    if let Some(metadata) = update.metadata {
        set::<M>(&mut active, "metadata", Some(metadata), policy)?;
    }
    if let Some(expires_at) = update.expires_at {
        set::<M>(
            &mut active,
            "expires_at",
            parse_optional_rfc3339(expires_at.as_deref(), "expires_at")?,
            policy,
        )?;
    }
    if let Some(last_request) = update.last_request {
        set::<M>(
            &mut active,
            "last_request",
            parse_optional_rfc3339(last_request.as_deref(), "last_request")?,
            policy,
        )?;
    }
    if let Some(request_count) = update.request_count {
        set::<M>(&mut active, "request_count", Some(request_count), policy)?;
    }
    if let Some(last_refill_at) = update.last_refill_at {
        set::<M>(
            &mut active,
            "last_refill_at",
            parse_optional_rfc3339(last_refill_at.as_deref(), "last_refill_at")?,
            policy,
        )?;
    }
    set::<M>(&mut active, "updated_at", Utc::now(), policy)?;
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
        let fields = Map::from_iter([
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
        ]);
        let fields = self
            .model_fields
            .fields(EntityRole::ApiKey)
            .organization_storage_fields(fields, Map::new(), true)
            .await?;
        let fields = self.create_fields("apikey", None, fields)?;
        let active = super::plugin_models::active::<P::ApiKey>(
            fields,
            self.config().advanced.database.generate_id(),
        )?;
        let row = database_operation::<Entity<P::ApiKey>, _>(self.config(), "create", async {
            active.insert(self.connection()).await.map_err(map_db_err)
        })
        .await?
        .record()?;
        Ok(self
            .model_fields
            .project_api_keys(vec![row])
            .await?
            .remove(0))
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        let row = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findOne", async {
            Entity::<P::ApiKey>::find()
                .filter(
                    P::ApiKey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
        Ok(self
            .model_fields
            .project_api_keys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let row = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findOne", async {
            Entity::<P::ApiKey>::find()
                .filter(P::ApiKey::column("key_hash")?.eq(hash))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
        Ok(self
            .model_fields
            .project_api_keys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let rows = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findMany", async {
            let mut query = Entity::<P::ApiKey>::find()
                .filter(P::ApiKey::column("reference_id")?.eq(reference_id));
            if let Some((field, direction)) = sort {
                query = query.order_by(
                    P::ApiKey::column(field)?,
                    if direction == "desc" {
                        Order::Desc
                    } else {
                        Order::Asc
                    },
                );
            }
            query
                .limit(super::pagination::default_limit(
                    self.config(),
                    self.connection().get_database_backend(),
                )?)
                .all(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .iter()
        .map(SeaOrmPluginModel::record)
        .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields.project_api_keys(rows).await
    }

    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64> {
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "count", async {
            Entity::<P::ApiKey>::find()
                .filter(P::ApiKey::column("reference_id")?.eq(reference_id))
                .count(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await
    }

    async fn update_api_key(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey> {
        self.update_api_key_optional(id, update)
            .await?
            .ok_or_else(|| AuthError::not_found("API Key not found"))
    }

    async fn update_api_key_optional(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        mut update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        let id = id.typed()?;
        let name = self
            .model_fields
            .api_key_name_for_storage(update.name.take().map(Some), false)
            .await?;
        let mut active = apply_update_fields::<P::ApiKey>(
            Default::default(),
            update,
            self.config().advanced.database.generate_id(),
        )?;
        if let Some(name) = name {
            set::<P::ApiKey>(
                &mut active,
                "name",
                name,
                self.config().advanced.database.generate_id(),
            )?;
        }
        let filter =
            P::ApiKey::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let row = database_operation::<Entity<P::ApiKey>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::ApiKey>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
        Ok(self
            .model_fields
            .project_api_keys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn write_api_key_usage(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        write: ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>> {
        let id = id.typed()?;
        // Upstream does not run update policies for an increment without a set patch.
        let name = if matches!(&write, ApiKeyUsageWrite::Decrement) {
            None
        } else {
            self.model_fields
                .api_key_name_for_storage(None, false)
                .await?
        };
        let operation = write.operation();
        let reselect =
            P::ApiKey::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let mut guard = reselect.clone();
        let mut query = Entity::<P::ApiKey>::update_many();
        match write {
            ApiKeyUsageWrite::Refill {
                previous,
                remaining,
                at,
            } => {
                let last = P::ApiKey::column("last_refill_at")?;
                guard = guard.and(match previous {
                    Some(previous) => last.eq(previous),
                    None => last.is_null(),
                });
                query = query
                    .col_expr(P::ApiKey::column("remaining")?, Expr::value(remaining))
                    .col_expr(last, Expr::value(at));
            }
            ApiKeyUsageWrite::Decrement => {
                let remaining = P::ApiKey::column("remaining")?;
                guard = guard.and(remaining.gt(0));
                query = query.col_expr(remaining, Expr::col(remaining).sub(1.0));
            }
            ApiKeyUsageWrite::StartWindow {
                previous_before,
                at,
            } => {
                let last = P::ApiKey::column("last_request")?;
                guard = guard.and(match previous_before {
                    Some(previous) => last.lte(previous),
                    None => last.is_null(),
                });
                query = query
                    .col_expr(P::ApiKey::column("request_count")?, Expr::value(1.0))
                    .col_expr(last, Expr::value(at));
            }
            ApiKeyUsageWrite::IncrementWindow {
                previous_after,
                maximum,
                at,
            } => {
                let last = P::ApiKey::column("last_request")?;
                let count = P::ApiKey::column("request_count")?;
                guard = guard.and(last.gt(previous_after)).and(count.lt(maximum));
                query = query
                    .col_expr(count, Expr::col(count).add(1.0))
                    .col_expr(last, Expr::value(at));
            }
            ApiKeyUsageWrite::LastRequest(at) => {
                query = query.col_expr(P::ApiKey::column("last_request")?, Expr::value(at));
            }
            ApiKeyUsageWrite::UpdatedAt(at) => {
                query = query.col_expr(P::ApiKey::column("updated_at")?, Expr::value(at));
            }
        }
        if let Some(name) = name {
            query = query.col_expr(P::ApiKey::column("name")?, Expr::value(name));
        }
        let query = query.filter(guard.clone());
        let row = database_operation::<Entity<P::ApiKey>, _>(self.config(), operation, async {
            if operation == "incrementOne" {
                super::updates::increment_returning_one::<Entity<P::ApiKey>>(
                    self.connection(),
                    query,
                    guard,
                    reselect,
                )
                .await
            } else {
                super::updates::execute_update_returning_one::<Entity<P::ApiKey>, _>(
                    self.connection(),
                    query,
                    reselect,
                )
                .await
            }
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
        Ok(self
            .model_fields
            .project_api_keys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_api_key(&self, id: &better_auth_core::SchemaValue<String>) -> AuthResult<()> {
        let id = id.typed()?;
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "delete", async {
            Entity::<P::ApiKey>::delete_many()
                .filter(
                    P::ApiKey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "deleteMany", async {
            Entity::<P::ApiKey>::delete_many()
                .filter(P::ApiKey::column("expires_at")?.is_not_null())
                .filter(P::ApiKey::column("expires_at")?.lt(Utc::now()))
                .exec(self.connection())
                .await
                .map(|result| result.rows_affected as usize)
                .map_err(map_db_err)
        })
        .await
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
