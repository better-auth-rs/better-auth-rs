use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use async_trait::async_trait;
use better_auth_core::{FieldMap, SchemaValue};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QueryResult, QueryTrait,
    TransactionTrait, sea_query::SimpleExpr,
};

use better_auth_core::store::{DeviceCodeStore, schema::EntityRole, validate_increment_one_update};

use crate::SeaOrmPluginModel;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};

use super::{SeaOrmStore, map_db_err};

#[cfg(test)]
#[path = "device_code_record_tests.rs"]
mod record_tests;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> DeviceCodeStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.create_device_code_with_connection(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            input,
        )
        .await
    }

    async fn create_device_code_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.create_plugin_record::<P::DeviceCode>(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
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
        self.get_plugin_record::<P::DeviceCode>(self.connection(), EntityRole::DeviceCode, id)
            .await
    }

    async fn update_device_code_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record::<P::DeviceCode>(
            self.connection(),
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
        self.get_device_code_by_device_code_with_connection(self.connection(), device_code)
            .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.get_device_code_by_user_code_with_connection(self.connection(), user_code)
            .await
    }

    async fn update_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.update_device_code_with_connection(self.connection(), id, update)
            .await
    }

    async fn update_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.update_device_code_if_status_with_connection(
            self.connection(),
            id,
            current_status,
            update,
        )
        .await
    }

    async fn claim_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<bool> {
        let (query, guard, reselect) = self.prepare_device_code_claim(id, user_id).await?;
        let row =
            database_operation::<Entity<P::DeviceCode>, _>(self.config(), "incrementOne", async {
                super::updates::increment_returning_raw::<Entity<P::DeviceCode>>(
                    self.connection(),
                    query.filter(guard.clone()),
                    guard,
                    reselect,
                )
                .await
            })
            .await?;
        Ok(!self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .is_empty())
    }

    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &better_auth_core::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        let row = if self.connection().support_returning() {
            self.consume_device_code_row(self.connection(), expected, ownership)
                .await?
        } else {
            let tx = self.connection().begin().await.map_err(map_db_err)?;
            match self.consume_device_code_row(&tx, expected, ownership).await {
                Ok(row) => {
                    tx.commit().await.map_err(map_db_err)?;
                    row
                }
                Err(error) => {
                    tx.rollback().await.map_err(map_db_err)?;
                    return Err(error);
                }
            }
        };
        self.project_consumed_device_code(row).await
    }

    async fn delete_device_code(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<()> {
        self.delete_device_code_with_connection(self.connection(), id)
            .await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.delete_device_code_if_status_with_connection(self.connection(), id, status)
            .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) async fn create_device_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        input: CreateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let row = self
            .insert_device_code(connection, scope, input.into_adapter_fields()?)
            .await?;
        self.project_device_code_models(row.into_iter().collect())
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Device code creation returned no record"))
    }

    pub(super) async fn insert_device_code(
        &self,
        connection: &impl ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        input: FieldMap,
    ) -> AuthResult<Option<QueryResult>> {
        let active = self
            .prepare_plugin_fields::<P::DeviceCode>(
                EntityRole::DeviceCode,
                "deviceCode",
                input,
                true,
            )
            .await?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "create", async {
            active
                .insert_raw(
                    connection,
                    super::create_readback::CreateReadback {
                        schema: &self.model_fields.plugin_fields(EntityRole::DeviceCode),
                        policy: self.config().advanced.database.generate_id(),
                        scope,
                        column: P::DeviceCode::column,
                    },
                )
                .await
        })
        .await
    }

    pub(super) async fn get_device_code_row(
        &self,
        connection: &impl ConnectionTrait,
        filter: SimpleExpr,
    ) -> AuthResult<Option<QueryResult>> {
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "findOne", async {
            connection
                .query_one_raw(
                    Entity::<P::DeviceCode>::find()
                        .filter(filter)
                        .build(connection.get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await
    }

    pub(super) async fn get_device_code_by_device_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        let filter = self.plugin_equals::<P::DeviceCode>(
            EntityRole::DeviceCode,
            "deviceCode",
            device_code.into(),
        )?;
        let row = self.get_device_code_row(connection, filter).await?;
        Ok(self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn get_device_code_by_user_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        let filter = self.plugin_equals::<P::DeviceCode>(
            EntityRole::DeviceCode,
            "userCode",
            user_code.into(),
        )?;
        let row = self.get_device_code_row(connection, filter).await?;
        Ok(self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn update_device_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let row = self
            .update_device_code_row(connection, id, update.into_adapter_fields()?)
            .await?
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        self.project_device_code_models(vec![row])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Device code creation returned no record"))
    }

    pub(super) async fn update_device_code_row(
        &self,
        connection: &impl ConnectionTrait,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<QueryResult>> {
        let filter = self.plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        let active = self
            .prepare_plugin_fields::<P::DeviceCode>(
                EntityRole::DeviceCode,
                "deviceCode",
                input,
                false,
            )
            .await?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            super::updates::execute_update_returning_raw(
                connection,
                active
                    .update_returning(connection.get_database_backend())?
                    .filter(filter.clone()),
                filter,
            )
            .await
        })
        .await
    }

    pub(super) async fn update_device_code_if_status_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let active = self.prepare_device_code_update(update).await?;
        let reselect = self.plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        let query = active
            .update_returning(connection.get_database_backend())?
            .filter(reselect.clone())
            .filter(self.plugin_equals::<P::DeviceCode>(
                EntityRole::DeviceCode,
                "status",
                current_status.into(),
            )?);
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            super::updates::execute_update_returning_raw::<Entity<P::DeviceCode>, _>(
                connection, query, reselect,
            )
            .await
        })
        .await?;
        // Successful boolean writes still await the adapter output policy.
        Ok(!self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .is_empty())
    }

    pub(super) async fn delete_device_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<()> {
        let filter = self.plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(filter)
                .exec(connection)
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }

    pub(super) async fn delete_device_code_if_status_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        let filter = self.plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        let status =
            self.plugin_equals::<P::DeviceCode>(EntityRole::DeviceCode, "status", status.into())?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(filter)
                .filter(status)
                .exec(connection)
                .await
                .map(|result| result.rows_affected == 1)
                .map_err(map_db_err)
        })
        .await
    }

    pub(super) async fn prepare_device_code_claim(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<(
        sea_orm::UpdateMany<Entity<P::DeviceCode>>,
        sea_orm::sea_query::SimpleExpr,
        sea_orm::sea_query::SimpleExpr,
    )> {
        let active = self
            .prepare_device_code_update(UpdateDeviceCode {
                user_id: Some(user_id.clone().map(Some)),
                ..Default::default()
            })
            .await?;
        validate_increment_one_update(false, !active.is_empty())?;
        let column = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, "userId")?;
        let reselect = self.plugin_id_filter::<P::DeviceCode>(EntityRole::DeviceCode, id)?;
        let guard = reselect
            .clone()
            .and(self.plugin_equals::<P::DeviceCode>(
                EntityRole::DeviceCode,
                "status",
                "pending".into(),
            )?)
            .and(column.is_null());
        let query = active.update(self.connection().get_database_backend())?;
        Ok((query, guard, reselect))
    }

    async fn prepare_device_code_update(
        &self,
        update: UpdateDeviceCode,
    ) -> AuthResult<super::plugin_models::Write<P::DeviceCode>> {
        self.prepare_plugin_fields::<P::DeviceCode>(
            EntityRole::DeviceCode,
            "deviceCode",
            update.into_adapter_fields()?,
            false,
        )
        .await
    }
}
