use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::id::AdapterIdInput;
use better_auth_core::store::WalletStore;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::types::{CreateWalletAddress, WalletAddress};
use better_auth_core::{AuthResult, AuthSchema};
use better_auth_core::{FieldMap, SchemaField};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter};

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
        self.model_fields
            .begin_id_query(EntityRole::WalletAddress)?;
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
        self.model_fields.begin_id_input(
            EntityRole::WalletAddress,
            AdapterIdInput {
                force_allow_id: false,
                supports_native_uuid: connection.get_database_backend() == DbBackend::Postgres,
            },
        )?;
        let mut native = FieldMap::from_iter([
            ("user_id".to_owned(), (value.user_id).into_field()),
            ("address".to_owned(), (value.address).into_field()),
            ("chain_id".to_owned(), (value.chain_id).into_field()),
            ("is_primary".to_owned(), (value.is_primary).into_field()),
            ("created_at".to_owned(), (value.created_at).into_field()),
        ]);
        let (mut active, id) = super::plugin_models::create_additional_fields::<P::WalletAddress>(
            self.model_fields.fields(EntityRole::WalletAddress),
            value.additional_fields,
            self.config().advanced.database.generate_id(),
            connection.get_database_backend(),
            || {
                if let Some(policy) = self
                    .model_fields
                    .id_input_policy(EntityRole::WalletAddress)?
                {
                    self.generated_id_with_policy("walletAddress", None, policy)
                } else {
                    Ok(None)
                }
            },
        )
        .await?;
        if let Some(id) = id {
            let _ = native.insert("id".into(), id.into());
        }
        super::plugin_models::apply::<P::WalletAddress>(
            &mut active,
            native,
            self.config().advanced.database.generate_id(),
        )?;
        let model =
            database_operation::<Entity<P::WalletAddress>, _>(self.config(), "create", async {
                active.insert(connection).await
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
        self.model_fields
            .begin_id_output(EntityRole::WalletAddress)?;
        let fields = self
            .model_fields
            .fields(EntityRole::WalletAddress)
            .adapter_fields(&[]);
        let record = super::plugin_models::record_fields(
            &model,
            &fields,
            self.connection().get_database_backend(),
        )?;
        let mut row = model.record()?;
        let output = fields
            .project_adapter_records_with_capabilities(
                vec![record],
                super::field_output::capabilities(self.connection().get_database_backend()),
                self.connection().get_database_backend() != DbBackend::Sqlite,
            )
            .await?
            .remove(0);
        row.additional_fields = output;
        Ok(row)
    }
}
