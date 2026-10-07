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
        self.model_fields
            .begin_id_output(EntityRole::WalletAddress)?;
        let fields = self
            .model_fields
            .fields(EntityRole::WalletAddress)
            .adapter_fields(&[]);
        let mut output = FieldMap::new();
        for (name, field) in fields.fields() {
            if name == "id" {
                snapshot.id = source.read(|row| Self::project_id(&row.id))?;
                continue;
            }
            let value = source.read(|row| {
                Ok(row
                    .additional_fields
                    .get(resolve_field_name(field.field_name.as_deref(), name))
                    .cloned())
            })?;
            let value = project_adapter_value(
                value.unwrap_or_default(),
                field,
                field.references_id(),
                true,
            )
            .await?;
            let _ = output.insert(name.to_owned(), value);
        }
        snapshot.additional_fields = output;
        snapshot.user_id = Self::project_id(&snapshot.user_id)?;
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
        self.model_fields
            .begin_id_input(EntityRole::WalletAddress)?;
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
        self.model_fields
            .begin_id_input(EntityRole::WalletAddress)?;
        let (additional_fields, id) = self
            .model_fields
            .fields(EntityRole::WalletAddress)
            .create_adapter_storage_fields(
                value.additional_fields,
                || {
                    if !self
                        .model_fields
                        .id_input_active(EntityRole::WalletAddress)?
                    {
                        return Ok(None);
                    }
                    self.config.advanced.database.generate_id().adapter_id(
                        "walletAddress",
                        None,
                        false,
                    )
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let mut value = crate::types::WalletAddress {
            additional_fields,
            id: id.map(crate::SchemaValue::Typed).unwrap_or_default(),
            user_id: self.memory_reference_id_input(value.user_id.into())?,
            address: value.address,
            chain_id: value.chain_id,
            is_primary: value.is_primary,
            created_at: value.created_at,
        };
        let (snapshot, source) = self
            .raw("walletAddress", "create", |state| {
                if let Some(id) = self.next_serial_id(state.wallets.len()) {
                    value.id = crate::SchemaValue::from_field(id);
                }
                let source = state.wallets.push_ref(value.clone());
                Ok((value, source))
            })
            .await?;
        self.project_wallet(snapshot, source).await
    }
}
