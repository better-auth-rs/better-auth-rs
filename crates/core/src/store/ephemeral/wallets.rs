use super::*;
use crate::store::schema::EntityRole;
use crate::{FieldValue, FromFieldMap, SchemaValue, WalletAddress};

#[async_trait]
impl crate::store::WalletStore for EphemeralStore {
    async fn create_wallet_address_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record(EntityRole::WalletAddress, input, Default::default())
            .await
    }

    async fn get_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::WalletAddress, id).await
    }

    async fn update_wallet_address_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::WalletAddress, id, input, Default::default())
            .await
    }

    async fn delete_wallet_address_record(&self, id: &SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_records(EntityRole::WalletAddress, id)
            .await
    }

    async fn get_wallet_address_value(
        &self,
        address: &FieldValue,
        chain_id: Option<&FieldValue>,
    ) -> AuthResult<Option<WalletAddress>> {
        let address =
            self.plugin_query_value(EntityRole::WalletAddress, "address", address.clone())?;
        let chain_id = chain_id
            .map(|chain| {
                self.plugin_query_value(EntityRole::WalletAddress, "chainId", chain.clone())
            })
            .transpose()?;
        let schema = self.model_fields.plugin_fields(EntityRole::WalletAddress);
        let address_column = schema.record_storage_key("address");
        let chain_column = schema.record_storage_key("chainId");
        let selected = self
            .raw("walletAddress", "findOne", |state| {
                state.wallets.first_ref(|row| {
                    crate::query::field_matches_equality(
                        row.get(address_column).unwrap_or(&FieldValue::Undefined),
                        &address,
                    ) && chain_id.as_ref().is_none_or(|chain| {
                        crate::query::field_matches_equality(
                            row.get(chain_column).unwrap_or(&FieldValue::Undefined),
                            chain,
                        )
                    })
                })
            })
            .await?;
        self.project_plugin_refs(EntityRole::WalletAddress, selected.into_iter().collect())
            .await?
            .pop()
            .map(WalletAddress::from_field_values)
            .transpose()
    }
}
