use better_auth_core::{FieldMap, FieldValue, SchemaField};
mod fields;

use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, DbBackend, EntityTrait, ExprTrait, Order, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, sea_query::Expr,
};

use better_auth_core::store::{ApiKeyStore, ApiKeyUsageWrite, schema::EntityRole};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::{SeaOrmStore, map_db_err};

/// Apply `UpdateApiKey` fields to a SeaORM active model.
fn apply_update_fields<M: SeaOrmPluginModel>(
    mut active: super::plugin_models::Write<M>,
    update: UpdateApiKey,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<super::plugin_models::Write<M>> {
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
        set::<M>(&mut active, "expires_at", expires_at, policy)?;
    }
    if let Some(last_request) = update.last_request {
        set::<M>(&mut active, "last_request", last_request, policy)?;
    }
    if let Some(request_count) = update.request_count {
        set::<M>(&mut active, "request_count", Some(request_count), policy)?;
    }
    if let Some(last_refill_at) = update.last_refill_at {
        set::<M>(&mut active, "last_refill_at", last_refill_at, policy)?;
    }
    set::<M>(
        &mut active,
        "updated_at",
        better_auth_core::FieldDate::from(Utc::now()),
        policy,
    )?;
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
        let fields = FieldMap::from_iter([
            ("start".to_owned(), input.start.into_field()),
            ("prefix".to_owned(), (input.prefix).into_field()),
            ("key_hash".to_owned(), (input.key_hash).into_field()),
            ("reference_id".to_owned(), (input.reference_id).into_field()),
            ("config_id".to_owned(), (input.config_id).into_field()),
            (
                "refill_interval".to_owned(),
                (input.refill_interval).into_field(),
            ),
            (
                "refill_amount".to_owned(),
                (input.refill_amount).into_field(),
            ),
            ("last_refill_at".to_owned(), FieldValue::Null),
            ("enabled".to_owned(), (input.enabled).into_field()),
            (
                "rate_limit_enabled".to_owned(),
                (input.rate_limit_enabled).into_field(),
            ),
            (
                "rate_limit_time_window".to_owned(),
                (input.rate_limit_time_window).into_field(),
            ),
            (
                "rate_limit_max".to_owned(),
                (input.rate_limit_max).into_field(),
            ),
            ("request_count".to_owned(), (Some(0.0)).into_field()),
            ("remaining".to_owned(), (input.remaining).into_field()),
            ("last_request".to_owned(), FieldValue::Null),
            ("expires_at".to_owned(), (input.expires_at).into_field()),
            (
                "created_at".to_owned(),
                better_auth_core::FieldValue::Date((now).into()),
            ),
            (
                "updated_at".to_owned(),
                better_auth_core::FieldValue::Date((now).into()),
            ),
            ("permissions".to_owned(), (input.permissions).into_field()),
            ("metadata".to_owned(), (input.metadata).into_field()),
        ]);
        let mut active = self
            .prepare_api_key_fields(Some(input.name), input.additional_fields, true)
            .await?;
        let fields = self.create_fields("apikey", None, fields)?;
        super::plugin_models::apply::<P::ApiKey>(
            &mut active,
            fields,
            self.config().advanced.database.generate_id(),
        )?;
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), "create", async {
            active.insert(self.connection()).await
        })
        .await?;
        Ok(self.project_api_key_models(vec![model]).await?.remove(0))
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findOne", async {
            Entity::<P::ApiKey>::find()
                .filter(
                    P::ApiKey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findOne", async {
            Entity::<P::ApiKey>::find()
                .filter(P::ApiKey::column("key_hash")?.eq(hash))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let models = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findMany", async {
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
        .await?;
        self.project_api_key_models(models).await
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
        let active = self
            .prepare_api_key_fields(
                update.name.take(),
                std::mem::take(&mut update.additional_fields),
                false,
            )
            .await?;
        let active = apply_update_fields::<P::ApiKey>(
            active,
            update,
            self.config().advanced.database.generate_id(),
        )?;
        let filter =
            P::ApiKey::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), "update", async {
            super::updates::update_record_returning_one::<Entity<P::ApiKey>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
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
        let fields = if matches!(&write, ApiKeyUsageWrite::Decrement) {
            Default::default()
        } else {
            self.prepare_api_key_fields(None, FieldMap::new(), false)
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
        query = fields.apply_to(query, self.connection().get_database_backend())?;
        let query = query.filter(guard.clone());
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), operation, async {
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
        .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
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
    use super::super::record_bindings::utf16_string;
    use super::*;
    use better_auth_core::ApiKeyStart;

    #[test]
    fn database_text_conversion_preserves_backend_boundaries() {
        let split = ApiKeyStart::prefix("😀abcdefgh", 1);
        assert_eq!(utf16_string(&split, DbBackend::Sqlite), "���");
        for backend in [DbBackend::Postgres, DbBackend::MySql] {
            assert_eq!(utf16_string(&split, backend), "�");
        }
        for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
            assert_eq!(
                utf16_string(&ApiKeyStart::prefix("😀abcdefgh", 6), backend),
                "😀abcd"
            );
        }
    }
}
