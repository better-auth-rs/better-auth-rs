use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::store::WalletStore;
use better_auth_core::types::WalletAddress;
use better_auth_core::{AuthResult, AuthSchema};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
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
        let query = Entity::<P::WalletAddress>::find()
            .filter(P::WalletAddress::column("address")?.eq(address));
        let query = match chain_id {
            Some(id) => query.filter(P::WalletAddress::column("chain_id")?.eq(id)),
            None => query,
        };
        database_operation::<Entity<P::WalletAddress>, _>(self.config(), "findOne", async {
            query.one(self.connection()).await.map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()
    }
    async fn create_wallet_address(&self, value: WalletAddress) -> AuthResult<WalletAddress> {
        let model = P::WalletAddress::active(Map::from_iter([
            ("id".to_owned(), json!(value.id)),
            ("user_id".to_owned(), json!(value.user_id)),
            ("address".to_owned(), json!(value.address)),
            ("chain_id".to_owned(), json!(value.chain_id)),
            ("is_primary".to_owned(), json!(value.is_primary)),
            ("created_at".to_owned(), json!(value.created_at)),
        ]))?;
        database_operation::<Entity<P::WalletAddress>, _>(self.config(), "create", async {
            model.insert(self.connection()).await.map_err(map_db_err)
        })
        .await?
        .record()
    }
}
