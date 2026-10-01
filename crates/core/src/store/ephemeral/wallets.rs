use super::*;

#[async_trait]
impl crate::store::WalletStore for EphemeralStore {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>> {
        self.raw("walletAddress", "findOne", |state| {
            Ok(state
                .wallets
                .snapshot()?
                .iter()
                .find(|wallet| {
                    wallet.address == address
                        && chain_id.is_none_or(|chain| chain == wallet.chain_id)
                })
                .cloned())
        })
        .await
    }
    async fn create_wallet_address(
        &self,
        value: crate::types::CreateWalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        let value = crate::types::WalletAddress {
            id: self
                .generated_id("walletAddress", None, self.lock()?.wallets.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            user_id: value.user_id,
            address: value.address,
            chain_id: value.chain_id,
            is_primary: value.is_primary,
            created_at: value.created_at,
        };
        self.raw("walletAddress", "create", |state| {
            state.wallets.push(value.clone());
            Ok(value)
        })
        .await
    }
}
