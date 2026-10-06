use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::store::WalletStore;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::types::{CreateWalletAddress, WalletAddress};
use better_auth_core::{AuthResult, AuthSchema};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DbBackend,
    EntityName, EntityTrait, Iden, Iterable, QueryFilter, QueryTrait,
    sea_query::{Expr, Query, Value},
};
use serde_json::{Map, json};

use super::{SeaOrmStore, map_db_err};

async fn insert_wallet<M: SeaOrmPluginModel>(
    connection: &impl ConnectionTrait,
    active: M::ActiveModel,
) -> AuthResult<M> {
    if connection.get_database_backend() != DbBackend::Sqlite {
        return active.insert(connection).await.map_err(map_db_err);
    }
    let active = active
        .before_save(connection, true)
        .await
        .map_err(map_db_err)?;
    let created_at = M::column("created_at")?;
    let mut insert = Entity::<M>::insert(active.clone());
    if let ActiveValue::Set(Value::ChronoDateTimeUtc(value))
    | ActiveValue::Unchanged(Value::ChronoDateTimeUtc(value)) = active.get(created_at)
    {
        use super::record_bindings::{self, Binding};

        let date =
            better_auth_core::utils::date::serialize_option(&value, serde_json::value::Serializer)?;
        let mut columns = Vec::new();
        let mut bindings = Vec::new();
        for column in <M::Entity as EntityTrait>::Column::iter() {
            if let ActiveValue::Set(value) | ActiveValue::Unchanged(value) = active.get(column) {
                columns.push(column);
                bindings.push(if column.to_string() == created_at.to_string() {
                    Binding::Raw(date.clone())
                } else {
                    Binding::Native(value)
                });
            }
        }
        let values = record_bindings::bind(DbBackend::Sqlite, bindings)?;
        let values = columns
            .iter()
            .zip(values)
            .map(|(column, value)| column.save_as(Expr::val(value)));
        // Keep SeaORM's insert executor and primary-key metadata; only replace the native date binding.
        *insert.query() = Query::insert()
            .into_table(Entity::<M>::default().table_ref())
            .columns(columns.iter().copied())
            .values_panic(values)
            .to_owned();
    }
    let model = insert
        .exec_with_returning(connection)
        .await
        .map_err(map_db_err)?;
    M::ActiveModel::after_save(model, connection, true)
        .await
        .map_err(map_db_err)
}

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
            true,
        )
        .await?;
        super::plugin_models::apply::<P::WalletAddress>(
            &mut active,
            self.create_fields("walletAddress", None, native)?,
            self.config().advanced.database.generate_id(),
        )?;
        let model =
            database_operation::<Entity<P::WalletAddress>, _>(self.config(), "create", async {
                insert_wallet::<P::WalletAddress>(connection, active).await
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
        let record = super::plugin_models::record_fields(
            &model,
            fields,
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
