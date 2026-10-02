use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::store::WalletStore;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::types::{CreateWalletAddress, WalletAddress};
use better_auth_core::{AuthResult, AuthSchema};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter,
};
use serde_json::{Map, json};

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> WalletStore
    for SeaOrmStore<S, O, P>
{
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<WalletAddress>> {
        self.get_wallet_address_with_connection(self.connection(), address, chain_id)
            .await
    }

    async fn create_wallet_address(&self, value: CreateWalletAddress) -> AuthResult<WalletAddress> {
        self.create_wallet_address_with_connection(self.connection(), value)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> WalletStore
    for super::SeaOrmTransaction<S, O, P>
{
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<WalletAddress>> {
        self.store
            .get_wallet_address_with_connection(&self.tx, address, chain_id)
            .await
    }

    async fn create_wallet_address(&self, value: CreateWalletAddress) -> AuthResult<WalletAddress> {
        self.store
            .create_wallet_address_with_connection(&self.tx, value)
            .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    async fn get_wallet_address_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<WalletAddress>> {
        let query = Entity::<P::WalletAddress>::find()
            .filter(P::WalletAddress::column("address")?.eq(address));
        let query = match chain_id {
            Some(id) => query.filter(P::WalletAddress::column("chain_id")?.eq(id)),
            None => query,
        };
        let model =
            database_operation::<Entity<P::WalletAddress>, _>(self.config(), "findOne", async {
                query.one(connection).await.map_err(map_db_err)
            })
            .await?;
        match model {
            Some(model) => self.project_wallet_model(model).await.map(Some),
            None => Ok(None),
        }
    }
    async fn create_wallet_address_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        value: CreateWalletAddress,
    ) -> AuthResult<WalletAddress> {
        let native = Map::from_iter([
            ("user_id".to_owned(), json!(value.user_id)),
            ("address".to_owned(), json!(value.address)),
            ("chain_id".to_owned(), json!(value.chain_id)),
            ("is_primary".to_owned(), json!(value.is_primary)),
            ("created_at".to_owned(), json!(value.created_at)),
        ]);
        let mut active = super::plugin_models::additional_fields::<P::WalletAddress>(
            self.model_fields.fields(EntityRole::WalletAddress),
            value.additional_fields,
            self.config().advanced.database.generate_id(),
            connection.get_database_backend(),
        )
        .await?;
        super::plugin_models::apply::<P::WalletAddress>(
            &mut active,
            self.create_fields("walletAddress", None, native)?,
            self.config().advanced.database.generate_id(),
        )?;
        let model =
            database_operation::<Entity<P::WalletAddress>, _>(self.config(), "create", async {
                active.insert(connection).await.map_err(map_db_err)
            })
            .await?;
        self.project_wallet_model(model).await
    }

    pub(super) fn validate_wallet_fields(&self) -> AuthResult<()> {
        super::plugin_models::validate_additional_field_columns::<P::WalletAddress>(
            EntityRole::WalletAddress,
            self.model_fields.fields(EntityRole::WalletAddress),
        )
    }

    async fn project_wallet_model(&self, model: P::WalletAddress) -> AuthResult<WalletAddress> {
        let fields = self.model_fields.fields(EntityRole::WalletAddress);
        let record = model.record_fields(fields)?;
        let mut row = model.record()?;
        let output = fields
            .project_adapter_records(
                vec![record],
                self.connection().get_database_backend() == DbBackend::Postgres,
                true,
            )
            .await?
            .remove(0);
        row.additional_fields = output
            .into_iter()
            .map(|(name, value)| Ok(value.json()?.map(|value| (name, value))))
            .collect::<AuthResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(row)
    }
}
