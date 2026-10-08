use better_auth_core::{FieldMap, FieldValue, FromFieldMap};
mod fields;

use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, Order, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, sea_query::Expr,
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
        let now = Utc::now();
        let mut fields = input.into_adapter_fields()?;
        fields.extend([
            ("lastRefillAt".to_owned(), FieldValue::Null),
            ("lastRequest".to_owned(), FieldValue::Null),
            (
                "createdAt".to_owned(),
                better_auth_core::FieldValue::Date((now).into()),
            ),
            (
                "updatedAt".to_owned(),
                better_auth_core::FieldValue::Date((now).into()),
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
                    Entity::<P::ApiKey>::find()
                        .filter(self.plugin_equals::<P::ApiKey>(
                            EntityRole::ApiKey,
                            "key",
                            hash.into(),
                        )?)
                        .build(self.connection().get_database_backend()),
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

    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let models = database_operation::<Entity<P::ApiKey>, _>(self.config(), "findMany", async {
            let mut query = Entity::<P::ApiKey>::find().filter(self.plugin_equals::<P::ApiKey>(
                EntityRole::ApiKey,
                "referenceId",
                reference_id.into(),
            )?);
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
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        self.project_api_key_models(models).await
    }

    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64> {
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "count", async {
            Entity::<P::ApiKey>::find()
                .filter(self.plugin_equals::<P::ApiKey>(
                    EntityRole::ApiKey,
                    "referenceId",
                    reference_id.into(),
                )?)
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
        update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        let mut fields = update.into_adapter_fields()?;
        let _ = fields.insert("updatedAt".into(), Utc::now().into());
        self.update_api_key_record(id, fields)
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
        // Upstream does not run update policies for an increment without a set patch.
        let set = write.set_fields();
        let has_set = !matches!(&write, ApiKeyUsageWrite::Decrement);
        let operation = write.operation();
        let backend = self.connection().get_database_backend();
        let reselect = self.plugin_id_filter::<P::ApiKey>(EntityRole::ApiKey, id)?;
        let mut guard = reselect.clone();
        let mut increment = None;
        match write {
            ApiKeyUsageWrite::Refill { previous, .. } => {
                guard = guard.and(self.plugin_equals::<P::ApiKey>(
                    EntityRole::ApiKey,
                    "lastRefillAt",
                    previous,
                )?);
            }
            ApiKeyUsageWrite::Decrement => {
                let remaining = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, "remaining")?;
                guard = guard.and(remaining.into_expr().gt(remaining.save_as(
                    self.plugin_parameter(EntityRole::ApiKey, "remaining", 0.0.into())?,
                )));
                increment = Some((remaining, Expr::col(remaining).sub(1.0)));
            }
            ApiKeyUsageWrite::StartWindow {
                previous_before, ..
            } => {
                let last = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, "lastRequest")?;
                guard = guard.and(match previous_before {
                    Some(previous) => last.into_expr().lte(last.save_as(self.plugin_parameter(
                        EntityRole::ApiKey,
                        "lastRequest",
                        previous.into(),
                    )?)),
                    None => self.plugin_equals::<P::ApiKey>(
                        EntityRole::ApiKey,
                        "lastRequest",
                        FieldValue::Null,
                    )?,
                });
            }
            ApiKeyUsageWrite::IncrementWindow {
                previous_after,
                maximum,
                ..
            } => {
                let last = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, "lastRequest")?;
                let count = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, "requestCount")?;
                guard = guard
                    .and(last.into_expr().gt(last.save_as(self.plugin_parameter(
                        EntityRole::ApiKey,
                        "lastRequest",
                        previous_after.into(),
                    )?)))
                    .and(count.into_expr().lt(count.save_as(self.plugin_parameter(
                        EntityRole::ApiKey,
                        "requestCount",
                        maximum,
                    )?)));
                increment = Some((count, Expr::col(count).add(1.0)));
            }
            ApiKeyUsageWrite::LastRequest(_) | ApiKeyUsageWrite::UpdatedAt(_) => {}
        }
        let mut fields = if has_set {
            self.prepare_plugin_fields::<P::ApiKey>(EntityRole::ApiKey, "apikey", set, false)
                .await?
        } else {
            Default::default()
        };
        if operation == "incrementOne" {
            validate_increment_one_update(increment.is_some(), !fields.is_empty())?;
        }
        if let Some((column, _)) = &increment {
            // Kysely evaluates set policies, then replaces colliding assignments with increments.
            fields.not_set(*column);
        }
        let mut query = fields.update(backend)?;
        if let Some((column, expression)) = increment {
            query = query.col_expr(column, expression);
        }
        let query = query.filter(guard.clone());
        let model = database_operation::<Entity<P::ApiKey>, _>(self.config(), operation, async {
            if operation == "incrementOne" {
                super::updates::increment_returning_raw::<Entity<P::ApiKey>>(
                    self.connection(),
                    query,
                    guard,
                    reselect,
                )
                .await
            } else {
                super::updates::execute_update_returning_raw::<Entity<P::ApiKey>, _>(
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
        self.delete_plugin_record::<P::ApiKey>(self.connection(), EntityRole::ApiKey, id)
            .await
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        database_operation::<Entity<P::ApiKey>, _>(self.config(), "deleteMany", async {
            let now = self.plugin_parameter(EntityRole::ApiKey, "expiresAt", Utc::now().into())?;
            let expires_at = self.plugin_column::<P::ApiKey>(EntityRole::ApiKey, "expiresAt")?;
            Entity::<P::ApiKey>::delete_many()
                .filter(expires_at.is_not_null())
                .filter(expires_at.into_expr().lt(expires_at.save_as(now)))
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
