use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::{FieldMap, SchemaField};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, TransactionTrait,
};

use better_auth_core::store::{DeviceCodeStore, schema::EntityRole};

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
        self.create_device_code_with_connection(self.connection(), input)
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
        user_id: &str,
    ) -> AuthResult<bool> {
        let (query, guard, reselect) = self.prepare_device_code_claim(id, user_id).await?;
        if self
            .model_fields
            .fields(EntityRole::DeviceCode)
            .fields()
            .is_empty()
        {
            return database_operation::<Entity<P::DeviceCode>, _>(
                self.config(),
                "incrementOne",
                async {
                    query
                        .filter(guard)
                        .exec(self.connection())
                        .await
                        .map(|result| result.rows_affected == 1)
                        .map_err(map_db_err)
                },
            )
            .await;
        }
        let row =
            database_operation::<Entity<P::DeviceCode>, _>(self.config(), "incrementOne", async {
                super::updates::increment_returning_one::<Entity<P::DeviceCode>>(
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
        input: CreateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut active = self
            .prepare_device_code_fields(input.scope, input.additional_fields, true)
            .await?;
        let fields = FieldMap::from_iter([
            ("device_code".to_owned(), (input.device_code).into_field()),
            ("user_code".to_owned(), (input.user_code).into_field()),
            ("user_id".to_owned(), (input.user_id).into_field()),
            ("expires_at".to_owned(), (input.expires_at).into_field()),
            ("status".to_owned(), (input.status).into_field()),
            (
                "last_polled_at".to_owned(),
                (input.last_polled_at).into_field(),
            ),
            (
                "polling_interval".to_owned(),
                (input.polling_interval).into_field(),
            ),
            ("client_id".to_owned(), (input.client_id).into_field()),
        ]);
        super::plugin_models::apply::<P::DeviceCode>(
            &mut active,
            self.create_fields("deviceCode", None, fields)?,
            self.config().advanced.database.generate_id(),
        )?;
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "create", async {
            active.insert(connection).await
        })
        .await?;
        Ok(self.project_device_code_models(vec![row]).await?.remove(0))
    }

    pub(super) async fn get_device_code_by_device_code_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "findOne", async {
            Entity::<P::DeviceCode>::find()
                .filter(P::DeviceCode::column("device_code")?.eq(device_code))
                .one(connection)
                .await
                .map_err(map_db_err)
        })
        .await?;
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
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "findOne", async {
            Entity::<P::DeviceCode>::find()
                .filter(P::DeviceCode::column("user_code")?.eq(user_code))
                .one(connection)
                .await
                .map_err(map_db_err)
        })
        .await?;
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
        let id = id.typed()?;
        let active = self.prepare_device_code_update(update).await?;

        let filter = P::DeviceCode::column("id")?
            .eq_id(id, self.config().advanced.database.generate_id())?;
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            super::updates::update_record_returning_one::<Entity<P::DeviceCode>, _>(
                connection,
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        Ok(self.project_device_code_models(vec![row]).await?.remove(0))
    }

    pub(super) async fn update_device_code_if_status_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        id: &better_auth_core::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let id = id.typed()?;
        let active = self.prepare_device_code_update(update).await?;
        let reselect = P::DeviceCode::column("id")?
            .eq_id(id, self.config().advanced.database.generate_id())?;
        let query = active
            .update(self.connection().get_database_backend())?
            .filter(reselect.clone())
            .filter(P::DeviceCode::column("status")?.eq(current_status));
        if self
            .model_fields
            .fields(EntityRole::DeviceCode)
            .fields()
            .is_empty()
        {
            return database_operation::<Entity<P::DeviceCode>, _>(
                self.config(),
                "update",
                async {
                    query
                        .exec(connection)
                        .await
                        .map(|result| result.rows_affected == 1)
                        .map_err(map_db_err)
                },
            )
            .await;
        }
        let row = database_operation::<Entity<P::DeviceCode>, _>(self.config(), "update", async {
            super::updates::execute_update_returning_one::<Entity<P::DeviceCode>, _>(
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
        let id = id.typed()?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(
                    P::DeviceCode::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
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
        let id = id.typed()?;
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "delete", async {
            Entity::<P::DeviceCode>::delete_many()
                .filter(
                    P::DeviceCode::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .filter(P::DeviceCode::column("status")?.eq(status))
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
        user_id: &str,
    ) -> AuthResult<(
        sea_orm::UpdateMany<Entity<P::DeviceCode>>,
        sea_orm::sea_query::SimpleExpr,
        sea_orm::sea_query::SimpleExpr,
    )> {
        let id = id.typed()?;
        let active = self
            .prepare_device_code_update(UpdateDeviceCode {
                user_id: Some(Some(user_id.to_owned())),
                ..Default::default()
            })
            .await?;
        let column = P::DeviceCode::column("user_id")?;
        let reselect = P::DeviceCode::column("id")?
            .eq_id(id, self.config().advanced.database.generate_id())?;
        let guard = reselect
            .clone()
            .and(P::DeviceCode::column("status")?.eq("pending"))
            .and(column.is_null());
        let query = active.update(self.connection().get_database_backend())?;
        Ok((query, guard, reselect))
    }

    async fn prepare_device_code_update(
        &self,
        update: UpdateDeviceCode,
    ) -> AuthResult<super::plugin_models::Write<P::DeviceCode>> {
        let mut active = self
            .prepare_device_code_fields(update.scope, update.additional_fields, false)
            .await?;

        if let Some(status) = update.status {
            set::<P::DeviceCode>(
                &mut active,
                "status",
                status,
                self.config().advanced.database.generate_id(),
            )?;
        }
        if let Some(user_id) = update.user_id {
            set::<P::DeviceCode>(
                &mut active,
                "user_id",
                user_id,
                self.config().advanced.database.generate_id(),
            )?;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            set::<P::DeviceCode>(
                &mut active,
                "last_polled_at",
                last_polled_at,
                self.config().advanced.database.generate_id(),
            )?;
        }

        Ok(active)
    }
}
