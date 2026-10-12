use super::SeaOrmStore;
use crate::{SeaOrmOrganizationSchema, SeaOrmPluginModel, SeaOrmPluginSchema};
use better_auth_core::{AuthResult, AuthSchema, FieldMap, SchemaValue, store::schema::EntityRole};
use sea_orm::ConnectionTrait;

#[cfg(test)]
#[path = "plugin_record_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "shared_column_contract_tests.rs"]
mod shared_column_contract_tests;

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P> {
    pub(super) async fn create_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        role: EntityRole,
        model: &str,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let force_allow_id = input.contains_key("id");
        self.plugin_record_model::<M>(role)
            .create(connection, scope, model, input.into(), force_allow_id)
            .await
    }

    pub(super) async fn get_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.plugin_record_model::<M>(role)
            .find_by_id(connection, &id.field_value())
            .await
    }

    pub(super) async fn update_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.plugin_record_model::<M>(role)
            .update_by_id(connection, &id.field_value(), input.into())
            .await
    }

    pub(super) async fn delete_plugin_record<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        self.plugin_record_model::<M>(role)
            .delete_by_id(connection, &id.field_value())
            .await
    }

    pub(super) async fn list_plugin_records<M: SeaOrmPluginModel>(
        &self,
        connection: &impl ConnectionTrait,
        role: EntityRole,
    ) -> AuthResult<Vec<FieldMap>> {
        self.plugin_record_model::<M>(role).list(connection).await
    }
}
