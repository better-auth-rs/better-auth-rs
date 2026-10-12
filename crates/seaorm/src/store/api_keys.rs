use crate::store::query_compile::{Compile, Execute};
use better_auth_core::{FieldMap, FieldValue, FromFieldMap};
#[cfg(test)]
mod cleanup_tests;
mod fields;

use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::value_filter::QueryPredicate;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ConnectionTrait, EntityTrait, ExprTrait, Order, QueryFilter, QueryOrder, QuerySelect,
    sea_query::Expr,
};

use better_auth_core::store::{
    ApiKeyStore, ApiKeyUsageWrite, schema::EntityRole, validate_increment_one_update,
};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{ApiKey, CreateApiKey, UpdateApiKey};

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> ApiKeyStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let mut fields = input.into_adapter_fields()?;
        fields.extend([
            ("lastRefillAt".to_owned(), FieldValue::Null),
            ("lastRequest".to_owned(), FieldValue::Null),
            (
                "createdAt".to_owned(),
                better_auth_core::FieldValue::Date(Utc::now().into()),
            ),
            (
                "updatedAt".to_owned(),
                better_auth_core::FieldValue::Date(Utc::now().into()),
            ),
        ]);
        ApiKey::from_field_values(
            self.create_api_key_record(fields)
                .await?
                .ok_or_else(|| AuthError::internal("API key creation returned no record"))?,
        )
    }

    async fn create_api_key_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.create_plugin_record::<P::ApiKey>(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            EntityRole::ApiKey,
            "apikey",
            input,
        )
        .await
    }

    async fn get_api_key_record(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record::<P::ApiKey>(self.connection(), EntityRole::ApiKey, id)
            .await
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        self.get_api_key_record(&id.to_owned().into())
            .await?
            .map(ApiKey::from_field_values)
            .transpose()
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findOne", async {
            self.connection()
                .query_one_raw(
                    super::plugin_rows::select_all::<Entity<P::ApiKey>>()
                        .filter(self.plugin_equals::<P::ApiKey>(
                            EntityRole::ApiKey,
                            "key",
                            hash.into(),
                        )?)
                        .compile_find(self.connection().get_database_backend())?,
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn find_api_keys_by_reference_value(
        &self,
        reference_id: &FieldValue,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let models = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findMany", async {
            let mut query = super::plugin_rows::select_all::<Entity<P::ApiKey>>().filter(
                self.plugin_equals::<P::ApiKey>(
                    EntityRole::ApiKey,
                    "referenceId",
                    reference_id.clone(),
                )?,
            );
            if let Some((field, direction)) = sort {
                query = query.order_by(
                    self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, field)?,
                    if direction == "desc" {
                        Order::Desc
                    } else {
                        Order::Asc
                    },
                );
            }
            self.connection()
                .query_all_raw(
                    query
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
        self.project_api_key_models(models).await
    }

    async fn count_api_keys_by_reference_value(
        &self,
        reference_id: &FieldValue,
    ) -> AuthResult<u64> {
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "count", async {
            let query = Entity::<P::ApiKey>::find().filter(self.plugin_equals::<P::ApiKey>(
                EntityRole::ApiKey,
                "referenceId",
                reference_id.clone(),
            )?);
            super::plugin_rows::count(self.connection(), query).await
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
        update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        self.update_api_key_record(id, update.into_adapter_fields()?)
            .await?
            .map(ApiKey::from_field_values)
            .transpose()
    }

    async fn update_api_key_record(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record::<P::ApiKey>(
            self.connection(),
            EntityRole::ApiKey,
            "apikey",
            id,
            input,
        )
        .await
    }

    async fn write_api_key_usage(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        write: ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>> {
        let set = write.set_fields();
        if write.operation() == "update" {
            return self
                .update_api_key_record(id, set)
                .await?
                .map(ApiKey::from_field_values)
                .transpose();
        }
        // Upstream does not run update policies for an increment without a set patch.
        let has_set = !matches!(&write, ApiKeyUsageWrite::Decrement);
        let by_id = self.bind_plugin_query_field(EntityRole::ApiKey, "id", id.field_value())?;
        let mut comparisons = Vec::new();
        let mut increment = None;
        match write {
            ApiKeyUsageWrite::Refill { previous, .. } => {
                comparisons.push((
                    self.bind_plugin_query_field(EntityRole::ApiKey, "lastRefillAt", previous)?,
                    None,
                ));
            }
            ApiKeyUsageWrite::Decrement => {
                comparisons.push((
                    self.bind_plugin_query_field(EntityRole::ApiKey, "remaining", 0.0.into())?,
                    Some(better_auth_core::WhereOperator::Gt),
                ));
                increment = Some(("remaining", -1.0));
            }
            ApiKeyUsageWrite::StartWindow {
                previous_before, ..
            } => {
                comparisons.push(match previous_before {
                    Some(previous) => (
                        self.bind_plugin_query_field(
                            EntityRole::ApiKey,
                            "lastRequest",
                            previous.into(),
                        )?,
                        Some(better_auth_core::WhereOperator::Lte),
                    ),
                    None => (
                        self.bind_plugin_query_field(
                            EntityRole::ApiKey,
                            "lastRequest",
                            FieldValue::Null,
                        )?,
                        None,
                    ),
                });
            }
            ApiKeyUsageWrite::IncrementWindow {
                previous_after,
                maximum,
                ..
            } => {
                comparisons.push((
                    self.bind_plugin_query_field(
                        EntityRole::ApiKey,
                        "lastRequest",
                        previous_after.into(),
                    )?,
                    Some(better_auth_core::WhereOperator::Gt),
                ));
                comparisons.push((
                    self.bind_plugin_query_field(EntityRole::ApiKey, "requestCount", maximum)?,
                    Some(better_auth_core::WhereOperator::Lt),
                ));
                increment = Some(("requestCount", 1.0));
            }
            ApiKeyUsageWrite::LastRequest(_) | ApiKeyUsageWrite::UpdatedAt(_) => {}
        }
        let increment = increment
            .map(|(name, amount)| {
                let column = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, name)?;
                let expression = if amount < 0.0 {
                    Expr::col(column).sub(-amount)
                } else {
                    Expr::col(column).add(amount)
                };
                Ok::<_, AuthError>((column, expression))
            })
            .transpose()?;
        let mut fields = if has_set {
            self.prepare_plugin_fields::<P::ApiKey>(EntityRole::ApiKey, "apikey", set, false)
                .await?
        } else {
            Default::default()
        };
        validate_increment_one_update(increment.is_some(), !fields.is_empty())?;
        let model =
            database_operation::<Entity<P::ApiKey>, _>(self.config(), "incrementOne", async {
                let (column, id) =
                    self.resolve_plugin_query_field::<P::ApiKey>(EntityRole::ApiKey, by_id)?;
                let mut predicates = vec![QueryPredicate::equals(column, id)];
                for (bound, operator) in comparisons {
                    let (column, value) =
                        self.resolve_plugin_query_field::<P::ApiKey>(EntityRole::ApiKey, bound)?;
                    predicates.push(match operator {
                        Some(operator) => QueryPredicate::new(
                            column,
                            operator,
                            better_auth_core::WhereMode::Sensitive,
                            value,
                        )
                        .with_save_as(),
                        None => QueryPredicate::equals(column, value),
                    });
                }
                if let Some((column, expression)) = increment {
                    fields.expression(column, expression);
                }
                super::updates::increment_returning_raw::<Entity<P::ApiKey>>(
                    self.connection(),
                    fields,
                    predicates,
                )
                .await
            })
            .await?;
        Ok(self
            .project_api_key_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_api_key(&self, id: &better_auth_core::SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_record::<P::ApiKey>(self.connection(), EntityRole::ApiKey, id)
            .await
    }

    async fn delete_expired_api_keys_before(
        &self,
        cutoff: better_auth_core::FieldDate,
    ) -> AuthResult<usize> {
        let expired =
            self.bind_plugin_query_field(EntityRole::ApiKey, "expiresAt", cutoff.into())?;
        let present =
            self.bind_plugin_query_field(EntityRole::ApiKey, "expiresAt", FieldValue::Null)?;
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "deleteMany", async {
            let (expires_at, current) =
                self.resolve_plugin_query_field::<P::ApiKey>(EntityRole::ApiKey, expired)?;
            let (present_column, null_operand) =
                self.resolve_plugin_query_field::<P::ApiKey>(EntityRole::ApiKey, present)?;
            let predicates = super::value_filter::all(
                [
                    QueryPredicate::new(
                        expires_at,
                        better_auth_core::WhereOperator::Lt,
                        better_auth_core::WhereMode::Sensitive,
                        current,
                    )
                    .with_save_as(),
                    QueryPredicate::new(
                        present_column,
                        better_auth_core::WhereOperator::Ne,
                        better_auth_core::WhereMode::Sensitive,
                        null_operand,
                    )
                    .with_save_as(),
                ],
                self.connection().get_database_backend(),
            )?;
            Entity::<P::ApiKey>::delete_many()
                .filter(predicates)
                .exec_native(self.connection())
                .await
                .map(|result| result.rows_affected as usize)
        })
        .await
    }
}

#[cfg(test)]
#[path = "api_key_concurrency_tests.rs"]
mod concurrency_tests;

#[cfg(test)]
#[path = "api_key_record_tests.rs"]
mod record_tests;

#[cfg(test)]
mod start_tests {
    use super::super::record_bindings::utf16_string;
    use better_auth_core::ApiKeyStart;
    use sea_orm::DbBackend;

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
