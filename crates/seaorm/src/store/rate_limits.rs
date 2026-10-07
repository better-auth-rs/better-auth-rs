use async_trait::async_trait;
use better_auth_core::middleware::{EndpointRateLimit, RateLimitDecision};
use better_auth_core::store::{RateLimitRecord, RateLimitStore};
use better_auth_core::{AuthResult, AuthSchema};
use better_auth_core::{FieldMap, SchemaField};
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

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
                let insert = super::plugin_models::active::<P::RateLimit>(
                    self.create_fields(
                        "rateLimit",
                        None,
                        FieldMap::from_iter([
                            ("key".to_owned(), key.to_owned().into_field()),
                            ("count".to_owned(), (1).into_field()),
                            ("last_request".to_owned(), (now).into_field()),
                        ]),
                    )?,
                    self.config().advanced.database.generate_id(),
                )?
                .insert(self.connection())
                .await;
                if let Err(error) = insert {
                    // Upstream retries a competing creation only when the key now exists.
                    if self.rate_limit_record(key).await?.is_none() {
                        return Err(error);
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
                let connection = self.connection().clone();
                // Only pruning failures use this catch. Counter writes already committed.
                better_auth_core::background::run_or_await_with_error_message(
                    Some(Box::pin(async move {
                        let _ = Entity::<P::RateLimit>::delete_many()
                            .filter(
                                P::RateLimit::column("last_request")?
                                    .lt(now as f64 - cleanup_window * 1000.0),
                            )
                            .exec(&connection)
                            .await
                            .map_err(map_db_err)?;
                        Ok(())
                    })),
                    self.config.advanced.background_tasks.as_ref(),
                    &self.config.logger,
                    "Error pruning rate limit rows",
                )
                .await;
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
