use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Map, json};

use better_auth_core::store::DeviceCodeStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> DeviceCodeStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let active = P::DeviceCode::active(self.create_fields(
            "deviceCode",
            None,
            Map::from_iter([
                ("device_code".to_owned(), json!(input.device_code)),
                ("user_code".to_owned(), json!(input.user_code)),
                ("user_id".to_owned(), json!(input.user_id)),
                ("expires_at".to_owned(), json!(input.expires_at)),
                ("status".to_owned(), json!(input.status)),
                ("last_polled_at".to_owned(), json!(input.last_polled_at)),
                ("polling_interval".to_owned(), json!(input.polling_interval)),
                ("client_id".to_owned(), json!(input.client_id)),
                ("scope".to_owned(), json!(input.scope)),
            ]),
        )?)?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "create", async {
            active.insert(self.connection()).await.map_err(map_db_err)
        })
        .await?
        .record()
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "findOne", async {
            Entity::<P::DeviceCode>::find()
                .filter(P::DeviceCode::column("device_code")?.eq(device_code))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "findOne", async {
            Entity::<P::DeviceCode>::find()
                .filter(P::DeviceCode::column("user_code")?.eq(user_code))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()
    }

    async fn update_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let id = id.typed()?;
        let mut active = <<P::DeviceCode as SeaOrmPluginModel>::ActiveModel as Default>::default();

        if let Some(status) = update.status {
            set::<P::DeviceCode>(&mut active, "status", status)?;
        }
        if let Some(user_id) = update.user_id {
            set::<P::DeviceCode>(&mut active, "user_id", user_id)?;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            set::<P::DeviceCode>(&mut active, "last_polled_at", last_polled_at)?;
        }

        let filter = P::DeviceCode::column("id")?.eq(id);
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            super::updates::update_returning_one::<Entity<P::DeviceCode>, _>(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Device code not found"))?
        .record()
    }

    async fn update_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        let mut update_many = Entity::<P::DeviceCode>::update_many();
        if let Some(status) = update.status {
            update_many =
                update_many.col_expr(P::DeviceCode::column("status")?, Expr::value(status));
        }
        if let Some(user_id) = update.user_id {
            update_many =
                update_many.col_expr(P::DeviceCode::column("user_id")?, Expr::value(user_id));
        }
        if let Some(last_polled_at) = update.last_polled_at {
            update_many = update_many.col_expr(
                P::DeviceCode::column("last_polled_at")?,
                Expr::value(last_polled_at),
            );
        }

        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            update_many
                .filter(P::DeviceCode::column("id")?.eq(id))
                .filter(P::DeviceCode::column("status")?.eq(current_status))
                .exec(self.connection())
                .await
                .map(|result| result.rows_affected == 1)
                .map_err(map_db_err)
        })
        .await
    }

    async fn claim_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "incrementOne", async {
            Entity::<P::DeviceCode>::update_many()
                .col_expr(P::DeviceCode::column("user_id")?, Expr::value(user_id))
                .filter(P::DeviceCode::column("id")?.eq(id))
                .filter(P::DeviceCode::column("status")?.eq("pending"))
                .filter(P::DeviceCode::column("user_id")?.is_null())
                .exec(self.connection())
                .await
                .map(|result| result.rows_affected == 1)
                .map_err(map_db_err)
        })
        .await
    }

    async fn delete_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<()> {
        let id = id.typed()?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(P::DeviceCode::column("id")?.eq(id))
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(P::DeviceCode::column("id")?.eq(id))
                .filter(P::DeviceCode::column("status")?.eq(status))
                .exec(self.connection())
                .await
                .map(|result| result.rows_affected == 1)
                .map_err(map_db_err)
        })
        .await
    }
}
