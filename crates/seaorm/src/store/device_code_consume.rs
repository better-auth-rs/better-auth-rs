use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::{SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::store::schema::resolve_field_name;
use better_auth_core::{AuthResult, DeviceCode, DeviceCodeOwnership};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, sea_query::Condition,
};

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) async fn consume_device_code_row(
        &self,
        connection: &impl ConnectionTrait,
        expected: &DeviceCode,
        ownership: &DeviceCodeOwnership,
    ) -> AuthResult<Option<P::DeviceCode>> {
        let policy = self.config().advanced.database.generate_id();
        let user = P::DeviceCode::column("user_id")?;
        let client = P::DeviceCode::column("client_id")?;
        let ownership = match ownership {
            DeviceCodeOwnership::ClientId(client_id) => client.eq(client_id),
            DeviceCodeOwnership::FieldEquals { field, value } => {
                let (name, field) = self
                    .model_fields
                    .device_code_ownership_field(field, value)?;
                let value = better_auth_core::user_query::bind_filter(field, value)?;
                super::value_filter::equals(
                    P::DeviceCode::column(resolve_field_name(field.field_name.as_deref(), name))?,
                    &value,
                )
            }
        };
        let filter = Condition::all()
            .add(P::DeviceCode::column("id")?.eq_id(expected.id.typed()?, policy)?)
            .add(P::DeviceCode::column("device_code")?.eq(&expected.device_code))
            .add(super::value_filter::equals(
                client,
                &expected
                    .client_id
                    .json()?
                    .unwrap_or(serde_json::Value::Null),
            ))
            .add(match &expected.user_id {
                Some(id) => user.eq_id(id, policy)?,
                None => user.is_null(),
            })
            .add(user.is_not_null())
            .add(P::DeviceCode::column("status")?.eq(&expected.status))
            .add(P::DeviceCode::column("status")?.eq("approved"))
            .add(ownership);
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "consumeOne", async {
            let query = Entity::<P::DeviceCode>::delete_many().filter(filter.clone());
            if connection.support_returning() {
                return query
                    .exec_with_returning(connection)
                    .await
                    .map(|rows| rows.into_iter().next())
                    .map_err(map_db_err);
            }
            // Callers keep the MySQL row lock and deletion in the same transaction.
            let row = Entity::<P::DeviceCode>::find()
                .filter(filter)
                .lock_exclusive()
                .one(connection)
                .await
                .map_err(map_db_err)?;
            if row.is_none() {
                return Ok(None);
            }
            let deleted = query.exec(connection).await.map_err(map_db_err)?;
            Ok(if deleted.rows_affected == 1 {
                row
            } else {
                None
            })
        })
        .await
    }

    pub(super) async fn project_consumed_device_code(
        &self,
        row: Option<P::DeviceCode>,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .pop())
    }
}
