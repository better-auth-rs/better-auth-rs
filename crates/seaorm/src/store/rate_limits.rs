use crate::store::query_compile::{Compile, Execute};
use async_trait::async_trait;
use better_auth_core::background::BackgroundFuture;
use better_auth_core::middleware::{EndpointRateLimit, RateLimitDecision};
use better_auth_core::query::{field_add, field_number};
use better_auth_core::store::{RateLimitStore, schema::EntityRole};
use better_auth_core::{AuthResult, AuthSchema, FieldMap, WhereMode, WhereOperator};
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

use super::plugin_models::Entity;
use super::value_filter::QueryPredicate;
use super::{SeaOrmStore, entities::rate_limit, instrumentation::database_operation, map_db_err};
use crate::{SeaOrmOrganizationSchema, SeaOrmPluginSchema};

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
    async fn rate_limit_record(&self, key: &str) -> AuthResult<Option<FieldMap>> {
        let filter =
            self.plugin_equals::<P::RateLimit>(EntityRole::RateLimit, "key", key.into())?;
        let rows =
            database_operation::<Entity<P::RateLimit>, _>(self.config(), "findMany", async {
                self.connection()
                    .query_all_raw(
                        super::plugin_rows::select_all::<Entity<P::RateLimit>>()
                            .filter(filter)
                            .limit(super::pagination::default_limit(
                                self.config(),
                                self.connection().get_database_backend(),
                            )?)
                            .compile_find(self.connection().get_database_backend())?,
                    )
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        Ok(self
            .project_plugin_rows::<P::RateLimit, FieldMap>(EntityRole::RateLimit, &rows)
            .await?
            .into_iter()
            .next())
    }

    async fn prune_rate_limits(&self, now: i64, cleanup_window: f64) -> AuthResult<()> {
        let bound = self.bind_plugin_query_field(
            EntityRole::RateLimit,
            "lastRequest",
            (now as f64 - cleanup_window * 1000.0).into(),
        )?;
        let (last_request, cutoff) =
            self.resolve_plugin_query_field::<P::RateLimit>(EntityRole::RateLimit, bound)?;
        let filter = QueryPredicate::new(
            last_request,
            WhereOperator::Lt,
            WhereMode::Sensitive,
            cutoff,
        )
        .with_save_as()
        .bind(self.connection().get_database_backend())?;
        database_operation::<Entity<P::RateLimit>, _>(self.config(), "deleteMany", async {
            let _ = Entity::<P::RateLimit>::delete_many()
                .filter(filter)
                .exec_native(self.connection())
                .await?;
            Ok(())
        })
        .await
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
                let insert = self
                    .create_plugin_record::<P::RateLimit>(
                        self.connection(),
                        super::create_readback::ReadbackScope::Direct(self.connection()),
                        EntityRole::RateLimit,
                        "rateLimit",
                        FieldMap::from_iter([
                            ("key".to_owned(), key.into()),
                            ("count".to_owned(), 1.into()),
                            ("lastRequest".to_owned(), now.into()),
                        ]),
                    )
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
            let previous = row.get("lastRequest").cloned().unwrap_or_default();
            let reset = now as f64 - field_number(&previous)? >= window;
            let by_key = self.bind_plugin_query_field(EntityRole::RateLimit, "key", key.into())?;
            let previous = self.bind_plugin_query_field(
                EntityRole::RateLimit,
                "lastRequest",
                if reset {
                    previous
                } else {
                    (now as f64 - window).into()
                },
            )?;
            let maximum = if reset {
                None
            } else {
                Some(self.bind_plugin_query_field(
                    EntityRole::RateLimit,
                    "count",
                    rule.max_requests.into(),
                )?)
            };
            let increment = if reset {
                None
            } else {
                Some(self.plugin_column::<P::RateLimit>(EntityRole::RateLimit, "count")?)
            };
            let mut set = FieldMap::new();
            if reset {
                let _ = set.insert("count".to_owned(), 1.into());
            }
            let _ = set.insert("lastRequest".to_owned(), now.into());
            let mut fields = self
                .prepare_plugin_fields::<P::RateLimit>(
                    EntityRole::RateLimit,
                    "rateLimit",
                    set,
                    false,
                )
                .await?;
            better_auth_core::store::validate_increment_one_update(
                increment.is_some(),
                !fields.is_empty(),
            )?;
            let row = database_operation::<Entity<P::RateLimit>, _>(
                self.config(),
                "incrementOne",
                async {
                    let (key_column, key_value) = self.resolve_plugin_query_field::<P::RateLimit>(
                        EntityRole::RateLimit,
                        by_key,
                    )?;
                    let (last_request, previous) = self
                        .resolve_plugin_query_field::<P::RateLimit>(
                            EntityRole::RateLimit,
                            previous,
                        )?;
                    let maximum = maximum
                        .map(|bound| {
                            self.resolve_plugin_query_field::<P::RateLimit>(
                                EntityRole::RateLimit,
                                bound,
                            )
                        })
                        .transpose()?;
                    let mut predicates = vec![
                        QueryPredicate::equals(key_column, key_value),
                        QueryPredicate::new(
                            last_request,
                            if reset {
                                WhereOperator::Lte
                            } else {
                                WhereOperator::Gt
                            },
                            WhereMode::Sensitive,
                            previous,
                        )
                        .with_save_as(),
                    ];
                    if let Some((column, value)) = maximum {
                        predicates.push(
                            QueryPredicate::new(
                                column,
                                WhereOperator::Lt,
                                WhereMode::Sensitive,
                                value,
                            )
                            .with_save_as(),
                        );
                    }
                    if let Some(count) = increment {
                        fields.expression(count, Expr::col(count).add(1));
                    }
                    super::updates::increment_returning_raw::<Entity<P::RateLimit>>(
                        self.connection(),
                        fields,
                        predicates,
                    )
                    .await
                },
            )
            .await?;
            let updated = self
                .project_plugin_rows::<P::RateLimit, FieldMap>(
                    EntityRole::RateLimit,
                    row.as_slice(),
                )
                .await?;
            if !updated.is_empty() {
                if reset {
                    let store = self.clone();
                    // Only pruning failures use this catch. Counter writes already committed.
                    better_auth_core::background::run_or_await_with_error_message(
                        Some(BackgroundFuture::new(async move {
                            store.prune_rate_limits(now, cleanup_window).await
                        })),
                        self.config.advanced.background_tasks.as_ref(),
                        &self.config.logger()?,
                        "Error pruning rate limit rows",
                    )
                    .await?;
                }
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            }
            if reset {
                continue;
            }
            let Some(fresh) = self.rate_limit_record(key).await? else {
                continue;
            };
            let last_request = fresh.get("lastRequest").cloned().unwrap_or_default();
            if now as f64 - field_number(&last_request)? >= window {
                continue;
            }
            let expires = field_number(&field_add(&last_request, &window.into())?)?;
            return Ok(RateLimitDecision {
                allowed: false,
                retry_after: Some(
                    ((expires - Utc::now().timestamp_millis() as f64) / 1000.0).ceil(),
                ),
            });
        }
    }
}
