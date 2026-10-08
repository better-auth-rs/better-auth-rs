use super::SeaOrmTransaction;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::schema::AuthSchema;
use crate::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, FieldMap, SchemaValue,
    store::{DeviceCodeStore, schema::EntityRole},
};
use sea_orm::QueryFilter;

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    DeviceCodeStore for SeaOrmTransaction<S, O, P>
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.store
            .create_device_code_with_connection(
                &self.tx,
                super::create_readback::ReadbackScope::Transaction,
                input,
            )
            .await
    }

    async fn create_device_code_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.store
            .create_plugin_record::<P::DeviceCode>(
                &self.tx,
                super::create_readback::ReadbackScope::Transaction,
                EntityRole::DeviceCode,
                "deviceCode",
                input,
            )
            .await
    }

    async fn get_device_code_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.store
            .get_plugin_record::<P::DeviceCode>(&self.tx, EntityRole::DeviceCode, id)
            .await
    }

    async fn update_device_code_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.store
            .update_plugin_record::<P::DeviceCode>(
                &self.tx,
                EntityRole::DeviceCode,
                "deviceCode",
                id,
                input,
            )
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
        user_id: &SchemaValue<String>,
    ) -> AuthResult<bool> {
        let (query, guard, reselect) = self.store.prepare_device_code_claim(id, user_id).await?;
        let row =
            database_operation::<Entity<P::DeviceCode>, _>(
                self.store.config(),
                "incrementOne",
                async {
                    super::updates::increment_returning_raw_with_connection::<
                        Entity<P::DeviceCode>,
                        _,
                    >(&self.tx, query.filter(guard.clone()), guard, reselect)
                    .await
                },
            )
            .await?;
        Ok(!self
            .store
            .project_device_code_models(row.into_iter().collect())
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
