use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::value_filter::{BoundQueryField, QueryPredicate, all};
use crate::store::query_compile::{Compile, Execute};
use async_trait::async_trait;
use better_auth_core::{FieldMap, FieldValue, SchemaValue};
use sea_orm::{
    ConnectionTrait, EntityTrait, QueryFilter, QueryResult, TransactionTrait, sea_query::SimpleExpr,
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
        let (write, selectors) = self.prepare_device_code_claim(id, user_id).await?;
        let row =
            database_operation::<Entity<P::DeviceCode>, _>(self.config(), "incrementOne", async {
                let predicates = selectors
                    .into_iter()
                    .map(|selector| {
                        let (column, value) = self.resolve_plugin_query_field::<P::DeviceCode>(
                            EntityRole::DeviceCode,
                            selector,
                        )?;
                        Ok(QueryPredicate::equals(column, value))
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                super::updates::increment_returning_raw::<Entity<P::DeviceCode>>(
                    self.connection(),
                    write,
                    predicates,
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
                    super::plugin_rows::select_all::<Entity<P::DeviceCode>>()
                        .filter(filter)
                        .compile_find(connection.get_database_backend())?,
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
        let selector =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let active = self
            .prepare_plugin_fields::<P::DeviceCode>(
                EntityRole::DeviceCode,
                "deviceCode",
                input,
                false,
            )
            .await?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            let (column, value) =
                self.resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, selector)?;
            let predicate = QueryPredicate::equals(column, value);
            let (query, reselect) =
                active.update_where_returning(connection.get_database_backend(), [predicate])?;
            super::updates::execute_update_returning_raw(connection, query, reselect).await
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
        let selector =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let status =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "status", current_status.into())?;
        let active = self.prepare_device_code_update(update).await?;
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            let (column, selector) =
                self.resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, selector)?;
            let (status_column, status) =
                self.resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, status)?;
            let (query, reselect) = active.update_where_returning(
                connection.get_database_backend(),
                [
                    QueryPredicate::equals(column, selector),
                    QueryPredicate::equals(status_column, status),
                ],
            )?;
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
                .exec_native(connection)
                .await
                .map(|_| ())
        })
        .await
    }

    pub(super) async fn delete_device_code_if_status_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        let selector =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let status =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "status", status.into())?;
        let predicates = [selector, status]
            .into_iter()
            .map(|field| {
                let (column, value) = self
                    .resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, field)?;
                Ok(QueryPredicate::equals(column, value))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let filter = all(predicates, connection.get_database_backend())?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(filter)
                .exec_native(connection)
                .await
                .map(|result| result.rows_affected == 1)
        })
        .await
    }

    pub(super) async fn prepare_device_code_claim(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<(
        super::plugin_models::Write<P::DeviceCode>,
        [BoundQueryField; 3],
    )> {
        let selector =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let status =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "status", "pending".into())?;
        let owner =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "userId", FieldValue::Null)?;
        let active = self
            .prepare_device_code_update(UpdateDeviceCode {
                user_id: Some(user_id.clone().map(Some)),
                ..Default::default()
            })
            .await?;
        validate_increment_one_update(false, !active.is_empty())?;
        Ok((active, [selector, status, owner]))
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
