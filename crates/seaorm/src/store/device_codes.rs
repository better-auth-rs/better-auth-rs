use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use uuid::Uuid;

use better_auth_core::store::DeviceCodeStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};

use super::entities::device_code::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S> DeviceCodeStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            device_code: Set(input.device_code),
            user_code: Set(input.user_code),
            user_id: Set(input.user_id),
            expires_at: Set(input.expires_at),
            status: Set(input.status),
            last_polled_at: Set(input.last_polled_at),
            polling_interval: Set(input.polling_interval),
            client_id: Set(input.client_id),
            scope: Set(input.scope),
        }
        .insert(self.connection())
        .await
        .map(|model| DeviceCode::from(&model))
        .map_err(map_db_err)
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::find()
            .filter(Column::DeviceCode.eq(device_code))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| DeviceCode::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::find()
            .filter(Column::UserCode.eq(user_code))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| DeviceCode::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Device code not found"));
        };

        let mut active = model.into_active_model();
        if let Some(status) = update.status {
            active.status = Set(status);
        }
        if let Some(user_id) = update.user_id {
            active.user_id = Set(user_id);
        }
        if let Some(last_polled_at) = update.last_polled_at {
            active.last_polled_at = Set(last_polled_at);
        }

        active
            .update(self.connection())
            .await
            .map(|model| DeviceCode::from(&model))
            .map_err(map_db_err)
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut update_many = Entity::update_many();
        if let Some(status) = update.status {
            update_many = update_many.col_expr(Column::Status, Expr::value(status));
        }
        if let Some(user_id) = update.user_id {
            update_many = update_many.col_expr(Column::UserId, Expr::value(user_id));
        }
        if let Some(last_polled_at) = update.last_polled_at {
            update_many = update_many.col_expr(Column::LastPolledAt, Expr::value(last_polled_at));
        }

        update_many
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq(current_status))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        Entity::delete_many()
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq(status))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }
}
