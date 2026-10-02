use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::{SeaOrmTransaction, map_db_err};
use crate::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult,
    store::{DeviceCodeStore, schema::EntityRole},
};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    DeviceCodeStore for SeaOrmTransaction<S, O, P>
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.store
            .create_device_code_with_connection(&self.tx, input)
            .await
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store
            .get_device_code_by_device_code_with_connection(&self.tx, device_code)
            .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store
            .get_device_code_by_user_code_with_connection(&self.tx, user_code)
            .await
    }

    async fn update_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.store
            .update_device_code_with_connection(&self.tx, id, update)
            .await
    }

    async fn update_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.store
            .update_device_code_if_status_with_connection(&self.tx, id, current_status, update)
            .await
    }

    async fn delete_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<()> {
        self.store
            .delete_device_code_with_connection(&self.tx, id)
            .await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.store
            .delete_device_code_if_status_with_connection(&self.tx, id, status)
            .await
    }

    async fn claim_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        let (query, guard, reselect) = self.store.prepare_device_code_claim(id, user_id).await?;
        if self
            .store
            .model_fields
            .fields(EntityRole::DeviceCode)
            .fields()
            .is_empty()
        {
            return database_operation::<Entity<P::DeviceCode>, _>(
                self.store.config(),
                "incrementOne",
                async {
                    query
                        .filter(guard)
                        .exec(&self.tx)
                        .await
                        .map(|result| result.rows_affected == 1)
                        .map_err(map_db_err)
                },
            )
            .await;
        }
        let row = database_operation::<Entity<P::DeviceCode>, _>(
            self.store.config(),
            "incrementOne",
            async {
                if self.tx.get_database_backend() == sea_orm::DbBackend::MySql
                    && Entity::<P::DeviceCode>::find()
                        .filter(guard.clone())
                        .lock_exclusive()
                        .one(&self.tx)
                        .await
                        .map_err(map_db_err)?
                        .is_none()
                {
                    return Ok(None);
                }
                super::updates::execute_update_returning_one::<Entity<P::DeviceCode>, _>(
                    &self.tx,
                    query.filter(guard),
                    reselect,
                )
                .await
            },
        )
        .await?
        .map(|row| row.record())
        .transpose()?;
        Ok(!self
            .store
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .is_empty())
    }

    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &better_auth_core::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        let row = self
            .store
            .consume_device_code_row(&self.tx, expected, ownership)
            .await?;
        self.store.project_consumed_device_code(row).await
    }
}
