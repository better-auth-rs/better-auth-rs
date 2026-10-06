use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, ExprTrait, QueryFilter, sea_query::Expr,
};
use serde_json::{Map, json};

use better_auth_core::store::{TwoFactorStore, schema::EntityRole};

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types::{CreateTwoFactor, TwoFactor};
use better_auth_core::{TwoFactorStorage, UpdateTwoFactor};

use super::{SeaOrmStore, map_db_err};

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_two_factor_fields(&self) -> AuthResult<()> {
        super::plugin_models::validate_additional_field_columns::<P::TwoFactor>(
            EntityRole::TwoFactor,
            self.model_fields.fields(EntityRole::TwoFactor),
        )
    }

    async fn prepare_two_factor_fields(
        &self,
        input: Map<String, serde_json::Value>,
        create: bool,
    ) -> AuthResult<<P::TwoFactor as SeaOrmPluginModel>::ActiveModel> {
        let config = self.model_fields.fields(EntityRole::TwoFactor);
        super::plugin_models::additional_fields::<P::TwoFactor>(
            config,
            input,
            self.config().advanced.database.generate_id(),
            self.connection().get_database_backend(),
            create,
        )
        .await
    }

    async fn project_two_factor_models(
        &self,
        models: Vec<P::TwoFactor>,
    ) -> AuthResult<Vec<TwoFactor>> {
        let fields = self.model_fields.fields(EntityRole::TwoFactor);
        let records = models
            .iter()
            .map(|model| model.record_fields(fields))
            .collect::<AuthResult<Vec<_>>>()?;
        let mut rows = models
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect::<AuthResult<Vec<_>>>()?;
        let output = fields
            .project_adapter_records(
                records,
                self.connection().get_database_backend() == DbBackend::Postgres,
                true,
            )
            .await?;
        for (row, output) in rows.iter_mut().zip(output) {
            row.additional_fields = output
                .into_iter()
                .map(|(name, value)| Ok(value.json()?.map(|value| (name, value))))
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect();
        }
        Ok(rows)
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> TwoFactorStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let mut fields = Map::from_iter([
            ("secret".to_owned(), json!(two_factor.secret)),
            ("backup_codes".to_owned(), json!(two_factor.backup_codes)),
            ("user_id".to_owned(), json!(two_factor.user_id)),
            ("verified".to_owned(), json!(two_factor.verified)),
            ("failed_verification_count".to_owned(), json!(0)),
            ("locked_until".to_owned(), serde_json::Value::Null),
        ]);
        if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
            let now = Utc::now();
            let _ = fields.insert("created_at".to_owned(), json!(now));
            let _ = fields.insert("updated_at".to_owned(), json!(now));
        }
        let mut active = self
            .prepare_two_factor_fields(two_factor.additional_fields, true)
            .await?;
        super::plugin_models::apply::<P::TwoFactor>(
            &mut active,
            self.create_fields("twoFactor", None, fields)?,
            self.config().advanced.database.generate_id(),
        )?;
        let model = database_operation::<Entity<P::TwoFactor>, _>(self.config(), "create", async {
            active.insert(self.connection()).await.map_err(map_db_err)
        })
        .await?;
        Ok(self.project_two_factor_models(vec![model]).await?.remove(0))
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        let model =
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "findOne", async {
                Entity::<P::TwoFactor>::find()
                    .filter(
                        P::TwoFactor::column("user_id")?
                            .eq_id(user_id, self.config().advanced.database.generate_id())?,
                    )
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        Ok(self
            .project_two_factor_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut active = self.prepare_two_factor_fields(Map::new(), false).await?;
        set::<P::TwoFactor>(
            &mut active,
            "backup_codes",
            backup_codes.to_owned(),
            self.config().advanced.database.generate_id(),
        )?;
        if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
            set::<P::TwoFactor>(
                &mut active,
                "updated_at",
                Utc::now(),
                self.config().advanced.database.generate_id(),
            )?;
        }
        let filter = P::TwoFactor::column("user_id")?
            .eq_id(user_id, self.config().advanced.database.generate_id())?;
        let model = database_operation::<Entity<P::TwoFactor>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::TwoFactor>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| crate::error::AuthError::not_found("Two-factor settings not found"))?;
        Ok(self.project_two_factor_models(vec![model]).await?.remove(0))
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "delete", async {
            Entity::<P::TwoFactor>::delete_many()
                .filter(
                    P::TwoFactor::column("user_id")?
                        .eq_id(user_id, self.config().advanced.database.generate_id())?,
                )
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }

    async fn update_two_factor(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        let id = id.typed()?;
        let mut fields = Map::from_iter([("id".to_owned(), json!(id.to_owned()))]);
        if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
            let _ = fields.insert("updated_at".to_owned(), json!(Utc::now()));
        }
        let mut active = self
            .prepare_two_factor_fields(update.additional_fields, false)
            .await?;
        super::plugin_models::apply::<P::TwoFactor>(
            &mut active,
            fields,
            self.config().advanced.database.generate_id(),
        )?;
        if let Some(secret) = update.secret {
            set::<P::TwoFactor>(
                &mut active,
                "secret",
                secret,
                self.config().advanced.database.generate_id(),
            )?;
        }
        if let Some(codes) = update.backup_codes {
            set::<P::TwoFactor>(
                &mut active,
                "backup_codes",
                codes,
                self.config().advanced.database.generate_id(),
            )?;
        }
        if let Some(verified) = update.verified {
            set::<P::TwoFactor>(
                &mut active,
                "verified",
                verified,
                self.config().advanced.database.generate_id(),
            )?;
        }
        let filter =
            P::TwoFactor::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let model = database_operation::<Entity<P::TwoFactor>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::TwoFactor>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| crate::error::AuthError::not_found("Two-factor settings not found"))?;
        Ok(self.project_two_factor_models(vec![model]).await?.remove(0))
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        let active = self.prepare_two_factor_fields(Map::new(), false).await?;
        let by_id =
            P::TwoFactor::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let filter = by_id
            .clone()
            .and(P::TwoFactor::column("backup_codes")?.eq(previous));
        let row =
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
                let mut query = Entity::<P::TwoFactor>::update_many().set(active).col_expr(
                    P::TwoFactor::column("backup_codes")?,
                    Expr::value(replacement),
                );
                if P::TwoFactor::two_factor_storage() == TwoFactorStorage::Legacy {
                    query = query
                        .col_expr(P::TwoFactor::column("updated_at")?, Expr::value(Utc::now()));
                }
                super::updates::increment_returning_one(
                    self.connection(),
                    query.filter(filter.clone()),
                    filter,
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
        id: &better_auth_core::SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<chrono::DateTime<Utc>> + Send + Sync),
    ) -> AuthResult<()> {
        let id = id.typed()?;
        let filter =
            P::TwoFactor::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let query = Entity::<P::TwoFactor>::update_many()
            .col_expr(
                P::TwoFactor::column("failed_verification_count")?,
                Expr::col(P::TwoFactor::column("failed_verification_count")?).add(1),
            )
            .filter(filter.clone());
        let row =
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
                super::updates::increment_returning_one(
                    self.connection(),
                    query,
                    filter.clone(),
                    filter.clone(),
                )
                .await
            })
            .await?;
        let failures = self
            .project_two_factor_models(row.into_iter().collect())
            .await?
            .pop()
            .and_then(|row| row.failed_verification_count)
            .unwrap_or(0);
        if failures >= max_attempts {
            let locked_until = locked_until()?;
            let active = self.prepare_two_factor_fields(Map::new(), false).await?;
            let filter =
                filter.and(P::TwoFactor::column("failed_verification_count")?.gte(max_attempts));
            let row = database_operation::<Entity<P::TwoFactor>, _>(
                self.config(),
                "incrementOne",
                async {
                    let query = Entity::<P::TwoFactor>::update_many()
                        .set(active)
                        .col_expr(
                            P::TwoFactor::column("locked_until")?,
                            Expr::value(locked_until),
                        )
                        .filter(filter.clone());
                    let by_id = P::TwoFactor::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?;
                    super::updates::increment_returning_one(self.connection(), query, filter, by_id)
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
        id: &better_auth_core::SchemaValue<String>,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let id = id.typed()?;
        let active = self.prepare_two_factor_fields(Map::new(), false).await?;
        let by_id =
            P::TwoFactor::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?;
        let mut filter = by_id.clone();
        if let Some(expired) = locked_before {
            filter = filter.and(P::TwoFactor::column("locked_until")?.lte(expired));
        }
        let update = Entity::<P::TwoFactor>::update_many()
            .set(active)
            .col_expr(
                P::TwoFactor::column("failed_verification_count")?,
                Expr::value(0),
            )
            .col_expr(
                P::TwoFactor::column("locked_until")?,
                Expr::value(None::<chrono::DateTime<Utc>>),
            )
            .filter(filter.clone());
        let row = database_operation::<Entity<P::TwoFactor>, _>(
            self.config(),
            if locked_before.is_some() {
                "incrementOne"
            } else {
                "update"
            },
            async {
                if locked_before.is_some() {
                    super::updates::increment_returning_one(
                        self.connection(),
                        update,
                        filter,
                        by_id,
                    )
                    .await
                } else {
                    super::updates::execute_update_returning_one(self.connection(), update, by_id)
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
