use async_trait::async_trait;
use better_auth_core::store::WalletStore;
use better_auth_core::types::WalletAddress;
use better_auth_core::{AuthResult, AuthSchema};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use super::{SeaOrmStore, entities::wallet_address, map_db_err};

impl From<wallet_address::Model> for WalletAddress {
    fn from(value: wallet_address::Model) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            address: value.address,
            chain_id: value.chain_id,
            is_primary: value.is_primary,
            created_at: value.created_at,
        }
    }
}
#[async_trait]
impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema> WalletStore for SeaOrmStore<S, O> {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<WalletAddress>> {
        let query =
            wallet_address::Entity::find().filter(wallet_address::Column::Address.eq(address));
        let query = match chain_id {
            Some(id) => query.filter(wallet_address::Column::ChainId.eq(id)),
            None => query,
        };
        Ok(query
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }
    async fn create_wallet_address(&self, value: WalletAddress) -> AuthResult<WalletAddress> {
        let model = wallet_address::ActiveModel {
            id: Set(value.id),
            user_id: Set(value.user_id),
            address: Set(value.address),
            chain_id: Set(value.chain_id),
            is_primary: Set(value.is_primary),
            created_at: Set(value.created_at),
        };
        Ok(model
            .insert(self.connection())
            .await
            .map_err(map_db_err)?
            .into())
    }
}
