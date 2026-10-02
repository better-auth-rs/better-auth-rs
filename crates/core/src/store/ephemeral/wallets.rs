use super::rows::RowRef;
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::project_adapter_value;

impl EphemeralStore {
    async fn project_wallet(
        &self,
        mut snapshot: crate::types::WalletAddress,
        source: RowRef<crate::types::WalletAddress>,
    ) -> AuthResult<crate::types::WalletAddress> {
        let mut output = Map::new();
        for (name, field) in self.model_fields.fields(EntityRole::WalletAddress).fields() {
            let value = source.read(|row| {
                Ok(row
                    .additional_fields
                    .get(resolve_field_name(field.field_name.as_deref(), name))
                    .cloned())
            })?;
            if let Some(value) = project_adapter_value(value, field, field.references_id(), true)
                .await?
                .json()?
            {
                let _ = output.insert(name.to_owned(), value);
            }
        }
        snapshot.additional_fields = output;
        Ok(snapshot)
    }
}

#[async_trait]
impl crate::store::WalletStore for EphemeralStore {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>> {
        let selected = self
            .raw("walletAddress", "findOne", |state| {
                state
                    .wallets
                    .first_ref(|wallet| {
                        wallet.address == address
                            && chain_id.is_none_or(|chain| chain == wallet.chain_id)
                    })?
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        match selected {
            Some((snapshot, source)) => self.project_wallet(snapshot, source).await.map(Some),
            None => Ok(None),
        }
    }
    async fn create_wallet_address(
        &self,
        value: crate::types::CreateWalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        let additional_fields = self
            .model_fields
            .fields(EntityRole::WalletAddress)
            .storage_fields_with_binding(value.additional_fields, true, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        let value = crate::types::WalletAddress {
            additional_fields,
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
        let (snapshot, source) = self
            .raw("walletAddress", "create", |state| {
                let source = state.wallets.push_ref(value.clone());
                Ok((value, source))
            })
            .await?;
        self.project_wallet(snapshot, source).await
    }
}
