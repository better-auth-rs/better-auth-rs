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
        value: crate::types::WalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        self.raw("walletAddress", "create", |state| {
            state.wallets.push(value.clone());
            Ok(value)
        })
        .await
    }
}
