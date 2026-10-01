use async_trait::async_trait;
use better_auth_core::middleware::{EndpointRateLimit, RateLimitDecision};
use better_auth_core::store::{RateLimitRecord, RateLimitStore};
use better_auth_core::{AuthResult, AuthSchema};
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Map, json};

use super::plugin_models::Entity;
use super::{SeaOrmStore, entities::rate_limit, map_db_err};
use crate::{SeaOrmOrganizationSchema, SeaOrmPluginModel, SeaOrmPluginSchema};

pub(super) struct RateLimitCounters;

impl sea_orm_migration::MigrationName for RateLimitCounters {
    fn name(&self) -> &str {
        "m20261001_000001_rate_limit_counters"
    }
}

#[async_trait]
impl sea_orm_migration::MigrationTrait for RateLimitCounters {
    async fn up(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .create_table(
                sea_orm::Schema::new(manager.get_database_backend())
                    .create_table_from_entity(rate_limit::Entity)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .drop_table(
                sea_orm::sea_query::Table::drop()
                    .table(rate_limit::Entity)
                    .to_owned(),
            )
            .await
    }
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P> {
    async fn rate_limit_record(&self, key: &str) -> AuthResult<Option<RateLimitRecord>> {
        Entity::<P::RateLimit>::find()
            .filter(P::RateLimit::column("key")?.eq(key))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .as_ref()
            .map(SeaOrmPluginModel::record)
            .transpose()
    }
}

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> RateLimitStore
    for SeaOrmStore<S, O, P>
{
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<RateLimitDecision> {
        let window = rule.window * 1000.0;
        loop {
            let row = self.rate_limit_record(key).await?;
            let now = Utc::now().timestamp_millis();
            let Some(row) = row else {
                let insert = P::RateLimit::active(Map::from_iter([
                    ("id".to_owned(), json!(uuid::Uuid::new_v4().to_string())),
                    ("key".to_owned(), json!(key)),
                    ("count".to_owned(), json!(1)),
                    ("last_request".to_owned(), json!(now)),
                ]))?
                .insert(self.connection())
                .await;
                if let Err(error) = insert {
                    // Upstream retries a competing creation only when the key now exists.
                    if self.rate_limit_record(key).await?.is_none() {
                        return Err(map_db_err(error));
                    }
                    continue;
                }
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            };
            if now as f64 - row.last_request as f64 >= window {
                let result = Entity::<P::RateLimit>::update_many()
                    .col_expr(P::RateLimit::column("count")?, Expr::value(1))
                    .col_expr(P::RateLimit::column("last_request")?, Expr::value(now))
                    .filter(P::RateLimit::column("key")?.eq(key))
                    .filter(P::RateLimit::column("last_request")?.lte(row.last_request))
                    .exec(self.connection())
                    .await
                    .map_err(map_db_err)?;
                if result.rows_affected == 0 {
                    continue;
                }
                // The upstream adapter logs pruning failures after a successful reset.
                // Counter reads and writes still propagate their original errors.
                if let Err(error) = Entity::<P::RateLimit>::delete_many()
                    .filter(
                        P::RateLimit::column("last_request")?
                            .lt(now as f64 - cleanup_window * 1000.0),
                    )
                    .exec(self.connection())
                    .await
                {
                    tracing::error!(%error, "Error pruning rate limit rows");
                }
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            }
            let result = Entity::<P::RateLimit>::update_many()
                .col_expr(
                    P::RateLimit::column("count")?,
                    Expr::col(P::RateLimit::column("count")?).add(1),
                )
                .col_expr(P::RateLimit::column("last_request")?, Expr::value(now))
                .filter(P::RateLimit::column("key")?.eq(key))
                .filter(P::RateLimit::column("last_request")?.gt(now as f64 - window))
                .filter(P::RateLimit::column("count")?.lt(rule.max_requests))
                .exec(self.connection())
                .await
                .map_err(map_db_err)?;
            if result.rows_affected != 0 {
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            }
            let Some(fresh) = self.rate_limit_record(key).await? else {
                continue;
            };
            if now as f64 - fresh.last_request as f64 >= window {
                continue;
            }
            return Ok(RateLimitDecision {
                allowed: false,
                retry_after: Some(
                    ((fresh.last_request as f64 + window - Utc::now().timestamp_millis() as f64)
                        / 1000.0)
                        .ceil(),
                ),
            });
        }
    }
}
