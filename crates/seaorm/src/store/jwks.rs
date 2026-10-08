use super::{SeaOrmStore, entities::jwk};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, AuthSchema, FieldMap, SchemaValue,
    store::{JwksStore, schema::EntityRole},
};

pub(super) struct JwtKeys;

impl sea_orm_migration::MigrationName for JwtKeys {
    fn name(&self) -> &str {
        "m20260930_000001_jwt_keys"
    }
}

#[async_trait]
impl sea_orm_migration::MigrationTrait for JwtKeys {
    async fn up(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .create_table(
                sea_orm::Schema::new(manager.get_database_backend())
                    .create_table_from_entity(jwk::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .drop_table(
                sea_orm::sea_query::Table::drop()
                    .table(jwk::Entity)
                    .to_owned(),
            )
            .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_jwk_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::Jwk>(EntityRole::Jwk)
    }
}

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> JwksStore
    for SeaOrmStore<S, O, P>
{
    async fn create_jwk_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record::<P::Jwk>(self.connection(), EntityRole::Jwk, "jwks", input)
            .await
    }

    async fn get_jwk_record(&self, id: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record::<P::Jwk>(self.connection(), EntityRole::Jwk, id)
            .await
    }

    async fn update_jwk_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record::<P::Jwk>(self.connection(), EntityRole::Jwk, "jwks", id, input)
            .await
    }

    async fn delete_jwk_record(&self, id: &SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_record::<P::Jwk>(self.connection(), EntityRole::Jwk, id)
            .await
    }

    async fn list_jwk_records(&self) -> AuthResult<Vec<FieldMap>> {
        self.list_plugin_records::<P::Jwk>(self.connection(), EntityRole::Jwk)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> JwksStore
    for super::SeaOrmTransaction<S, O, P>
{
    async fn create_jwk_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.store
            .create_plugin_record::<P::Jwk>(&self.tx, EntityRole::Jwk, "jwks", input)
            .await
    }

    async fn get_jwk_record(&self, id: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        self.store
            .get_plugin_record::<P::Jwk>(&self.tx, EntityRole::Jwk, id)
            .await
    }

    async fn update_jwk_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.store
            .update_plugin_record::<P::Jwk>(&self.tx, EntityRole::Jwk, "jwks", id, input)
            .await
    }

    async fn delete_jwk_record(&self, id: &SchemaValue<String>) -> AuthResult<()> {
        self.store
            .delete_plugin_record::<P::Jwk>(&self.tx, EntityRole::Jwk, id)
            .await
    }

    async fn list_jwk_records(&self) -> AuthResult<Vec<FieldMap>> {
        self.store
            .list_plugin_records::<P::Jwk>(&self.tx, EntityRole::Jwk)
            .await
    }
}
