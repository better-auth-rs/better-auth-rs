use super::*;

#[async_trait]
impl crate::store::WalletStore for EphemeralStore {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>> {
        Ok(self
            .lock()?
            .wallets
            .iter()
            .find(|wallet| {
                wallet.address == address && chain_id.is_none_or(|chain| chain == wallet.chain_id)
            })
            .cloned())
    }
    async fn create_wallet_address(
        &self,
        value: crate::types::WalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        self.lock()?.wallets.push(value.clone());
        Ok(value)
    }
}
