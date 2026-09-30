use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter};
use serde_json::{Map, json};
use uuid::Uuid;

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
        P::DeviceCode::active(Map::from_iter([
            ("id".to_owned(), json!(Uuid::new_v4().to_string())),
            ("device_code".to_owned(), json!(input.device_code)),
            ("user_code".to_owned(), json!(input.user_code)),
            ("user_id".to_owned(), json!(input.user_id)),
            ("expires_at".to_owned(), json!(input.expires_at)),
            ("status".to_owned(), json!(input.status)),
            ("last_polled_at".to_owned(), json!(input.last_polled_at)),
            ("polling_interval".to_owned(), json!(input.polling_interval)),
            ("client_id".to_owned(), json!(input.client_id)),
            ("scope".to_owned(), json!(input.scope)),
        ]))?
        .insert(self.connection())
        .await
        .map_err(map_db_err)?
        .record()
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::<P::DeviceCode>::find()
            .filter(P::DeviceCode::column("device_code")?.eq(device_code))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|model| model.record())
            .transpose()
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::<P::DeviceCode>::find()
            .filter(P::DeviceCode::column("user_code")?.eq(user_code))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|model| model.record())
            .transpose()
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let Some(model) = Entity::<P::DeviceCode>::find()
            .filter(P::DeviceCode::column("id")?.eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Device code not found"));
        };

        let mut active = model.into_active_model();
        if let Some(status) = update.status {
            set::<P::DeviceCode>(&mut active, "status", status)?;
        }
        if let Some(user_id) = update.user_id {
            set::<P::DeviceCode>(&mut active, "user_id", user_id)?;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            set::<P::DeviceCode>(&mut active, "last_polled_at", last_polled_at)?;
        }

        active
            .update(self.connection())
            .await
            .map_err(map_db_err)?
            .record()
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
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

        update_many
            .filter(P::DeviceCode::column("id")?.eq(id))
            .filter(P::DeviceCode::column("status")?.eq(current_status))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        Entity::<P::DeviceCode>::update_many()
            .col_expr(P::DeviceCode::column("user_id")?, Expr::value(user_id))
            .filter(P::DeviceCode::column("id")?.eq(id))
            .filter(P::DeviceCode::column("status")?.eq("pending"))
            .filter(P::DeviceCode::column("user_id")?.is_null())
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        Entity::<P::DeviceCode>::delete_many()
            .filter(P::DeviceCode::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        Entity::<P::DeviceCode>::delete_many()
            .filter(P::DeviceCode::column("id")?.eq(id))
            .filter(P::DeviceCode::column("status")?.eq(status))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }
}
