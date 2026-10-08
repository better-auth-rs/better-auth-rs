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
            .create_device_code_with_connection(&self.tx, input)
            .await
    }

    async fn create_device_code_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        let row = self.store.insert_device_code(&self.tx, input).await?;
        Ok(self
            .store
            .project_plugin_rows::<P::DeviceCode, FieldMap>(EntityRole::DeviceCode, vec![row])
            .await?
            .remove(0))
    }

    async fn get_device_code_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        let filter = self
            .store
            .plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        let row = self.store.get_device_code_row(&self.tx, filter).await?;
        Ok(self
            .store
            .project_plugin_rows::<P::DeviceCode, FieldMap>(
                EntityRole::DeviceCode,
                row.into_iter().collect(),
            )
            .await?
            .pop())
    }

    async fn update_device_code_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let row = self
            .store
            .update_device_code_row(&self.tx, id, input)
            .await?;
        Ok(self
            .store
            .project_plugin_rows::<P::DeviceCode, FieldMap>(
                EntityRole::DeviceCode,
                row.into_iter().collect(),
            )
            .await?
            .pop())
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
