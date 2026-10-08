use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::{SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, CreateTwoFactor, FieldDate, FieldMap, FieldValue, FromFieldMap,
    SchemaValue, TwoFactor, TwoFactorStorage, UpdateTwoFactor,
    store::{TwoFactorStore, schema::EntityRole, validate_increment_one_update},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, IdenStatic, QueryFilter, QueryResult,
    QueryTrait,
    sea_query::{Expr, SimpleExpr},
};

#[cfg(test)]
#[path = "two_factor_record_tests.rs"]
mod record_tests;

enum WriteOperation {
    Create,
    Update,
    Increment,
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_two_factor_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::TwoFactor>(EntityRole::TwoFactor)
    }

    fn two_factor_timestamps(&self, fields: &mut FieldMap, create: bool) {
        if P::TwoFactor::two_factor_storage() != TwoFactorStorage::Legacy {
            return;
        }
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let now = FieldDate::from(chrono::Utc::now());
        for name in if create {
            &["createdAt", "updatedAt"][..]
        } else {
            &["updatedAt"][..]
        } {
            if !schema.fields().contains_key(*name) {
                let _ = fields
                    .entry((*name).into())
                    .or_insert_with(|| now.clone().into());
            }
        }
    }

    async fn prepare_two_factor_fields(
        &self,
        mut input: FieldMap,
        operation: WriteOperation,
    ) -> AuthResult<super::plugin_models::Write<P::TwoFactor>> {
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let mut legacy = FieldMap::new();
        if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
            for name in ["createdAt", "updatedAt"] {
                if !schema.fields().contains_key(name)
                    && let Some(value) = input.remove(name)
                {
                    let _ = legacy.insert(name.into(), value);
                }
            }
        }
        let mut active = self
            .prepare_plugin_fields::<P::TwoFactor>(
                EntityRole::TwoFactor,
                "twoFactor",
                input,
                matches!(operation, WriteOperation::Create),
            )
            .await?;
        if matches!(operation, WriteOperation::Increment) {
            // Legacy timestamps must not make an empty declared SET valid.
            validate_increment_one_update(false, !active.is_empty())?;
        }
        super::plugin_models::apply::<P::TwoFactor>(
            &mut active,
            legacy,
            self.config().advanced.database.generate_id(),
        )?;
        Ok(active)
    }

    async fn project_two_factor_models(
        &self,
        rows: Vec<QueryResult>,
    ) -> AuthResult<Vec<TwoFactor>> {
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let legacy = rows
            .iter()
            .map(|row| {
                let mut fields = FieldMap::new();
                if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
                    for name in ["createdAt", "updatedAt"] {
                        if !schema.fields().contains_key(name) {
                            let column = P::TwoFactor::column(name)?;
                            let value = super::plugin_rows::value(row, column.as_str())?;
                            let _ = fields.insert(
                                name.into(),
                                better_auth_core::query::field_date(&value)?.into(),
                            );
                        }
                    }
                }
                Ok(fields)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_plugin_rows::<P::TwoFactor, FieldMap>(EntityRole::TwoFactor, rows)
            .await?
            .into_iter()
            .zip(legacy)
            .map(|(mut fields, legacy)| {
                fields.extend(legacy);
                TwoFactor::from_field_values(fields)
            })
            .collect()
    }

    async fn insert_two_factor(&self, mut input: FieldMap) -> AuthResult<Option<QueryResult>> {
        self.two_factor_timestamps(&mut input, true);
        let active = self
            .prepare_two_factor_fields(input, WriteOperation::Create)
            .await?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "create", async {
            active
                .insert_raw(
                    self.connection(),
                    super::create_readback::CreateReadback {
                        schema: &self.model_fields.plugin_fields(EntityRole::TwoFactor),
                        policy: self.config().advanced.database.generate_id(),
                        scope: super::create_readback::ReadbackScope::Direct(self.connection()),
                        column: P::TwoFactor::column,
                    },
                )
                .await
        })
        .await
    }

    async fn get_two_factor_row(&self, filter: SimpleExpr) -> AuthResult<Option<QueryResult>> {
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "findOne", async {
            self.connection()
                .query_one_raw(
                    Entity::<P::TwoFactor>::find()
                        .filter(filter)
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await
    }

    async fn update_two_factor_row(
        &self,
        filter: SimpleExpr,
        mut input: FieldMap,
    ) -> AuthResult<Option<QueryResult>> {
        self.two_factor_timestamps(&mut input, false);
        let active = self
            .prepare_two_factor_fields(input, WriteOperation::Update)
            .await?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "update", async {
            super::updates::execute_update_returning_raw::<Entity<P::TwoFactor>, _>(
                self.connection(),
                active
                    .update(self.connection().get_database_backend())?
                    .filter(filter.clone()),
                filter,
            )
            .await
        })
        .await
    }
}

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> TwoFactorStore
    for SeaOrmStore<S, O, P>
{
    async fn create_two_factor_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        let row = self.insert_two_factor(input).await?;
        Ok(self
            .project_plugin_rows::<P::TwoFactor, FieldMap>(
                EntityRole::TwoFactor,
                row.into_iter().collect(),
            )
            .await?
            .pop())
    }

    async fn get_two_factor_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record::<P::TwoFactor>(self.connection(), EntityRole::TwoFactor, id)
            .await
    }

    async fn update_two_factor_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let filter = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
        let row = self.update_two_factor_row(filter, input).await?;
        Ok(self
            .project_plugin_rows::<P::TwoFactor, FieldMap>(
                EntityRole::TwoFactor,
                row.into_iter().collect(),
            )
            .await?
            .pop())
    }

    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let row = self.insert_two_factor(input.into_adapter_fields()?).await?;
        self.project_two_factor_models(row.into_iter().collect())
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Two-factor creation returned no record"))
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.get_two_factor_by_user_id_value(&user_id.to_owned().into())
            .await
    }

    async fn get_two_factor_by_user_id_value(
        &self,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<Option<TwoFactor>> {
        let filter = self.plugin_equals::<P::TwoFactor>(
            EntityRole::TwoFactor,
            "userId",
            user_id.field_value(),
        )?;
        let row = self.get_two_factor_row(filter).await?;
        Ok(self
            .project_two_factor_models(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let filter =
            self.plugin_equals::<P::TwoFactor>(EntityRole::TwoFactor, "userId", user_id.into())?;
        let row = self
            .update_two_factor_row(
                filter,
                FieldMap::from([("backupCodes".into(), backup_codes.into())]),
            )
            .await?
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        self.project_two_factor_models(vec![row])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Two-factor creation returned no record"))
    }

    async fn update_two_factor(
        &self,
        id: &SchemaValue<String>,
        update: UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        let filter = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
        let row = self
            .update_two_factor_row(filter, update.into_adapter_fields()?)
            .await?
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        self.project_two_factor_models(vec![row])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Two-factor creation returned no record"))
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.delete_two_factor_by_user_id_value(&user_id.to_owned().into())
            .await
    }

    async fn delete_two_factor_by_user_id_value(
        &self,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        let filter = self.plugin_equals::<P::TwoFactor>(
            EntityRole::TwoFactor,
            "userId",
            user_id.field_value(),
        )?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "delete", async {
            Entity::<P::TwoFactor>::delete_many()
                .filter(filter)
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &SchemaValue<String>,
        previous: &FieldValue,
        replacement: FieldValue,
    ) -> AuthResult<bool> {
        let by_id = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
        let guard = by_id.clone().and(self.plugin_equals::<P::TwoFactor>(
            EntityRole::TwoFactor,
            "backupCodes",
            previous.clone(),
        )?);
        let mut input = FieldMap::from([("backupCodes".into(), replacement)]);
        self.two_factor_timestamps(&mut input, false);
        let active = self
            .prepare_two_factor_fields(input, WriteOperation::Increment)
            .await?;
        let row =
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
                super::updates::increment_returning_raw::<Entity<P::TwoFactor>>(
                    self.connection(),
                    active
                        .update(self.connection().get_database_backend())?
                        .filter(guard.clone()),
                    guard,
                    by_id,
                )
                .await
            })
            .await?;
        Ok(!self
            .project_two_factor_models(row.into_iter().collect())
            .await?
            .is_empty())
    }

    async fn record_two_factor_failure(
        &self,
        id: &SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<FieldDate> + Send + Sync),
    ) -> AuthResult<()> {
        let by_id = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
        let counter =
            self.plugin_column::<P::TwoFactor>(EntityRole::TwoFactor, "failedVerificationCount")?;
        // An increment without SET does not run input transforms or update factories.
        let query = Entity::<P::TwoFactor>::update_many()
            .col_expr(counter, Expr::col(counter).add(1))
            .filter(by_id.clone());
        let row =
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
                super::updates::increment_returning_raw::<Entity<P::TwoFactor>>(
                    self.connection(),
                    query,
                    by_id.clone(),
                    by_id.clone(),
                )
                .await
            })
            .await?;
        let failures = self
            .project_two_factor_models(row.into_iter().collect())
            .await?
            .pop()
            .map(|row| row.failed_verification_count.field_value())
            .unwrap_or_default();
        let failures = if failures.is_null() || failures.is_undefined() {
            0.0
        } else {
            better_auth_core::query::field_number(&failures)?
        };
        if failures >= max_attempts as f64 {
            let until = locked_until()?;
            let by_id = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
            let guard = by_id.clone().and(counter.into_expr().gte(counter.save_as(
                self.plugin_parameter(
                    EntityRole::TwoFactor,
                    "failedVerificationCount",
                    (max_attempts as f64).into(),
                )?,
            )));
            let active = self
                .prepare_two_factor_fields(
                    FieldMap::from([("lockedUntil".into(), until.into())]),
                    WriteOperation::Increment,
                )
                .await?;
            let row = database_operation::<Entity<P::TwoFactor>, _>(
                self.config(),
                "incrementOne",
                async {
                    super::updates::increment_returning_raw::<Entity<P::TwoFactor>>(
                        self.connection(),
                        active
                            .update(self.connection().get_database_backend())?
                            .filter(guard.clone()),
                        guard,
                        by_id,
                    )
                    .await
                },
            )
            .await?;
            let _ = self
                .project_two_factor_models(row.into_iter().collect())
                .await?;
        }
        Ok(())
    }

    async fn reset_two_factor_failures(
        &self,
        id: &SchemaValue<String>,
        locked_before: Option<FieldDate>,
    ) -> AuthResult<()> {
        let by_id = self.plugin_id_filter::<P::TwoFactor>(EntityRole::TwoFactor, id)?;
        let guarded = locked_before.is_some();
        let mut guard = by_id.clone();
        if let Some(expired) = locked_before {
            let column =
                self.plugin_column::<P::TwoFactor>(EntityRole::TwoFactor, "lockedUntil")?;
            guard = guard.and(column.into_expr().lte(column.save_as(self.plugin_parameter(
                EntityRole::TwoFactor,
                "lockedUntil",
                expired.into(),
            )?)));
        }
        let active = self
            .prepare_two_factor_fields(
                FieldMap::from([
                    ("failedVerificationCount".into(), 0.0.into()),
                    ("lockedUntil".into(), FieldValue::Null),
                ]),
                if guarded {
                    WriteOperation::Increment
                } else {
                    WriteOperation::Update
                },
            )
            .await?;
        let row = database_operation::<Entity<P::TwoFactor>, _>(
            self.config(),
            if guarded { "incrementOne" } else { "update" },
            async {
                let query = active
                    .update(self.connection().get_database_backend())?
                    .filter(guard.clone());
                if guarded {
                    super::updates::increment_returning_raw::<Entity<P::TwoFactor>>(
                        self.connection(),
                        query,
                        guard,
                        by_id,
                    )
                    .await
                } else {
                    super::updates::execute_update_returning_raw::<Entity<P::TwoFactor>, _>(
                        self.connection(),
                        query,
                        by_id,
                    )
                    .await
                }
            },
        )
        .await?;
        let _ = self
            .project_two_factor_models(row.into_iter().collect())
            .await?;
        Ok(())
    }
}
