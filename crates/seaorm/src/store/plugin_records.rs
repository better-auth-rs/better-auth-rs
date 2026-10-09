use super::{SeaOrmStore, instrumentation::database_operation, map_db_err, plugin_models::Entity};
use crate::{SeaOrmOrganizationSchema, SeaOrmPluginModel, SeaOrmPluginSchema};
use better_auth_core::{AuthResult, AuthSchema, FieldMap, SchemaValue, store::schema::EntityRole};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait};

#[cfg(test)]
#[path = "plugin_record_tests.rs"]
mod tests;

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P> {
    pub(super) async fn create_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        role: EntityRole,
        model: &str,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let active = self
            .prepare_plugin_fields::<M>(role, model, input, true)
            .await?;
        let row = database_operation::<Entity<M>, _>(self.config(), "create", async {
            active
                .insert_raw(
                    connection,
                    super::create_readback::CreateReadback {
                        schema: &self.model_fields.plugin_fields(role),
                        policy: self.config().advanced.database.generate_id(),
                        scope,
                        column: M::column,
                    },
                )
                .await
        })
        .await?;
        Ok(self
            .project_plugin_rows::<M, FieldMap>(role, row.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn get_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        let filter = self.plugin_id_filter::<M>(role, id)?;
        let row = database_operation::<Entity<M>, _>(self.config(), "findOne", async {
            connection
                .query_one_raw(
                    Entity::<M>::find()
                        .filter(filter)
                        .build(connection.get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_plugin_rows::<M, FieldMap>(role, row.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn update_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        model: &str,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let selector = self.bind_plugin_query_field(role, "id", id.field_value())?;
        let active = self
            .prepare_plugin_fields::<M>(role, model, input, false)
            .await?;
        let filter = self.resolve_plugin_equals::<M>(role, selector)?;
        let row = database_operation::<Entity<M>, _>(self.config(), "update", async {
            super::updates::execute_update_returning_raw::<Entity<M>, _>(
                connection,
                active
                    .update_returning(connection.get_database_backend())?
                    .filter(filter.clone()),
                filter,
            )
            .await
        })
        .await?;
        Ok(self
            .project_plugin_rows::<M, FieldMap>(role, row.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn delete_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        let filter = self.plugin_id_filter::<M>(role, id)?;
        database_operation::<Entity<M>, _>(self.config(), "delete", async {
            let _ = Entity::<M>::delete_many()
                .filter(filter)
                .exec(connection)
                .await
                .map_err(map_db_err)?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list_plugin_records<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
    ) -> AuthResult<Vec<FieldMap>> {
        let rows = database_operation::<Entity<M>, _>(self.config(), "findMany", async {
            connection
                .query_all_raw(
                    Entity::<M>::find()
                        .limit(super::pagination::default_limit(
                            self.config(),
                            connection.get_database_backend(),
                        )?)
                        .build(connection.get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        self.project_plugin_rows::<M, FieldMap>(role, rows).await
    }
}
