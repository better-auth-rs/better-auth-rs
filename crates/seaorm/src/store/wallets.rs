use super::{SeaOrmStore, instrumentation::database_operation, map_db_err, plugin_models::Entity};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, AuthSchema, FieldMap, FieldValue, SchemaValue, WalletAddress,
    store::{WalletStore, schema::EntityRole},
};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QueryTrait};

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> WalletStore
    for SeaOrmStore<S, O, P>
{
    async fn create_wallet_address_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record::<P::WalletAddress>(
            self.connection(),
            EntityRole::WalletAddress,
            "walletAddress",
            input,
        )
        .await
    }

    async fn get_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record::<P::WalletAddress>(self.connection(), EntityRole::WalletAddress, id)
            .await
    }

    async fn update_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record::<P::WalletAddress>(
            self.connection(),
            EntityRole::WalletAddress,
            "walletAddress",
            id,
            input,
        )
        .await
    }

    async fn delete_wallet_address_record(&self, id: &SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_record::<P::WalletAddress>(
            self.connection(),
            EntityRole::WalletAddress,
            id,
        )
        .await
    }

    async fn get_wallet_address_value(
        &self,
        address: &FieldValue,
        chain_id: Option<&FieldValue>,
    ) -> AuthResult<Option<WalletAddress>> {
        self.get_wallet_address_with_connection(self.connection(), address, chain_id)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> WalletStore
    for super::SeaOrmTransaction<S, O, P>
{
    async fn create_wallet_address_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.store
            .create_plugin_record::<P::WalletAddress>(
                &self.tx,
                EntityRole::WalletAddress,
                "walletAddress",
                input,
            )
            .await
    }

    async fn get_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.store
            .get_plugin_record::<P::WalletAddress>(&self.tx, EntityRole::WalletAddress, id)
            .await
    }

    async fn update_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.store
            .update_plugin_record::<P::WalletAddress>(
                &self.tx,
                EntityRole::WalletAddress,
                "walletAddress",
                id,
                input,
            )
            .await
    }

    async fn delete_wallet_address_record(&self, id: &SchemaValue<String>) -> AuthResult<()> {
        self.store
            .delete_plugin_record::<P::WalletAddress>(&self.tx, EntityRole::WalletAddress, id)
            .await
    }

    async fn get_wallet_address_value(
        &self,
        address: &FieldValue,
        chain_id: Option<&FieldValue>,
    ) -> AuthResult<Option<WalletAddress>> {
        self.store
            .get_wallet_address_with_connection(&self.tx, address, chain_id)
            .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    async fn get_wallet_address_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        address: &FieldValue,
        chain_id: Option<&FieldValue>,
    ) -> AuthResult<Option<WalletAddress>> {
        let query =
            Entity::<P::WalletAddress>::find().filter(self.plugin_equals::<P::WalletAddress>(
                EntityRole::WalletAddress,
                "address",
                address.clone(),
            )?);
        let query = match chain_id {
            Some(value) => query.filter(self.plugin_equals::<P::WalletAddress>(
                EntityRole::WalletAddress,
                "chainId",
                value.clone(),
            )?),
            None => query,
        };
        let row =
            database_operation::<Entity<P::WalletAddress>, _>(self.config(), "findOne", async {
                connection
                    .query_one_raw(query.build(connection.get_database_backend()))
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        Ok(self
            .project_plugin_rows::<P::WalletAddress, WalletAddress>(
                EntityRole::WalletAddress,
                row.into_iter().collect(),
            )
            .await?
            .pop())
    }

    pub(super) fn validate_wallet_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::WalletAddress>(EntityRole::WalletAddress)
    }
}
