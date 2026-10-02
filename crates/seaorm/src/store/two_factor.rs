use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, QueryFilter, sea_query::Expr,
};
use serde_json::{Map, json};

use better_auth_core::store::TwoFactorStore;

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types::{CreateTwoFactor, TwoFactor};
use better_auth_core::UpdateTwoFactor;

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> TwoFactorStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        let active = super::plugin_models::active::<P::TwoFactor>(
            self.create_fields(
                "twoFactor",
                None,
                Map::from_iter([
                    ("secret".to_owned(), json!(two_factor.secret)),
                    ("backup_codes".to_owned(), json!(two_factor.backup_codes)),
                    ("user_id".to_owned(), json!(two_factor.user_id)),
                    ("verified".to_owned(), json!(two_factor.verified)),
                    ("failed_verification_count".to_owned(), json!(0)),
                    ("locked_until".to_owned(), serde_json::Value::Null),
                    ("created_at".to_owned(), json!(now)),
                    ("updated_at".to_owned(), json!(now)),
                ]),
            )?,
            self.config().advanced.database.generate_id(),
        )?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "create", async {
            active.insert(self.connection()).await.map_err(map_db_err)
        })
        .await?
        .record()
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
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
        .await?
        .map(|model| model.record())
        .transpose()
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut active = <<P::TwoFactor as SeaOrmPluginModel>::ActiveModel as Default>::default();
        set::<P::TwoFactor>(
            &mut active,
            "backup_codes",
            backup_codes.to_owned(),
            self.config().advanced.database.generate_id(),
        )?;
        set::<P::TwoFactor>(
            &mut active,
            "updated_at",
            Utc::now(),
            self.config().advanced.database.generate_id(),
        )?;
        let filter = P::TwoFactor::column("user_id")?
            .eq_id(user_id, self.config().advanced.database.generate_id())?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::TwoFactor>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| crate::error::AuthError::not_found("Two-factor settings not found"))?
        .record()
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
        let mut active = super::plugin_models::active::<P::TwoFactor>(
            Map::from_iter([
                ("id".to_owned(), json!(id.to_owned())),
                ("updated_at".to_owned(), json!(Utc::now())),
            ]),
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
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::TwoFactor>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| crate::error::AuthError::not_found("Two-factor settings not found"))?
        .record()
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
            Entity::<P::TwoFactor>::update_many()
                .col_expr(
                    P::TwoFactor::column("backup_codes")?,
                    Expr::value(replacement),
                )
                .col_expr(P::TwoFactor::column("updated_at")?, Expr::value(Utc::now()))
                .filter(
                    P::TwoFactor::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .filter(P::TwoFactor::column("backup_codes")?.eq(previous))
                .exec(self.connection())
                .await
                .map(|result| result.rows_affected == 1)
                .map_err(map_db_err)
        })
        .await
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
                    filter,
                )
                .await
            })
            .await?;
        let failures = row
            .map(|row| row.record())
            .transpose()?
            .map_or(0, |row| row.failed_verification_count);
        if failures >= max_attempts {
            let locked_until = locked_until()?;
            database_operation::<Entity<P::TwoFactor>, _>(self.config(), "incrementOne", async {
                Entity::<P::TwoFactor>::update_many()
                    .col_expr(
                        P::TwoFactor::column("locked_until")?,
                        Expr::value(locked_until),
                    )
                    .filter(
                        P::TwoFactor::column("id")?
                            .eq_id(id, self.config().advanced.database.generate_id())?,
                    )
                    .filter(P::TwoFactor::column("failed_verification_count")?.gte(max_attempts))
                    .exec(self.connection())
                    .await
                    .map(|_| ())
                    .map_err(map_db_err)
            })
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
        let mut update = Entity::<P::TwoFactor>::update_many()
            .col_expr(
                P::TwoFactor::column("failed_verification_count")?,
                Expr::value(0),
            )
            .col_expr(
                P::TwoFactor::column("locked_until")?,
                Expr::value(None::<chrono::DateTime<Utc>>),
            )
            .filter(
                P::TwoFactor::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            );
        if let Some(expired) = locked_before {
            update = update.filter(P::TwoFactor::column("locked_until")?.lte(expired));
        }
        database_operation::<Entity<P::TwoFactor>, _>(
            self.config(),
            if locked_before.is_some() {
                "incrementOne"
            } else {
                "update"
            },
            async {
                update
                    .exec(self.connection())
                    .await
                    .map(|_| ())
                    .map_err(map_db_err)
            },
        )
        .await
    }
}
