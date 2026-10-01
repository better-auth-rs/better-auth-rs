use async_trait::async_trait;
use chrono::Utc;

use super::EphemeralStore;
use crate::store::{PasskeyStore, schema::EntityRole};
use crate::{AuthError, AuthResult, CreatePasskey, Passkey, UpdatePasskeyAuthentication};

#[async_trait]
impl PasskeyStore for EphemeralStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let now = Utc::now();
        let name = self
            .model_fields
            .name_for_storage(EntityRole::Passkey, Some(input.name), true)
            .await?
            .flatten();
        let mut passkey = Passkey {
            id: self
                .generated_id("passkey", None, self.lock()?.passkeys.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            user_id: input.user_id,
            name,
            credential_id: input.credential_id,
            public_key: input.public_key,
            counter: input.counter,
            device_type: input.device_type,
            backed_up: input.backed_up,
            transports: input.transports,
            credential: input.credential,
            aaguid: input.aaguid,
            created_at: now,
            updated_at: now,
        };
        let row = self
            .raw("passkey", "create", |state| {
                self.assign_insert_serial_id(&mut passkey.id, state.passkeys.len());
                state.passkeys.push(passkey.clone());
                Ok(passkey)
            })
            .await?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let row = self
            .raw("passkey", "findOne", |state| state.passkeys.get(id))
            .await?;
        Ok(self
            .model_fields
            .project_passkeys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let row = self
            .raw("passkey", "findOne", |state| {
                Ok(state
                    .passkeys
                    .snapshot()?
                    .iter()
                    .find(|passkey| passkey.credential_id == credential_id)
                    .cloned())
            })
            .await?;
        Ok(self
            .model_fields
            .project_passkeys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let rows = self
            .raw("passkey", "findMany", |state| {
                let passkeys: Vec<_> = state
                    .passkeys
                    .snapshot()?
                    .iter()
                    .filter(|passkey| passkey.user_id == user_id)
                    .cloned()
                    .collect();
                Ok(crate::query::paginate_memory(
                    passkeys,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.model_fields.project_passkeys(rows).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let name = self
            .model_fields
            .name_for_storage(EntityRole::Passkey, None, false)
            .await?;
        let row = self
            .raw("passkey", "update", |state| {
                let Some(mut passkey) = state.passkeys.get_mut(id)? else {
                    return Ok(None);
                };
                if let Some(name) = name {
                    passkey.name = name;
                }
                passkey.credential = update.credential;
                passkey.counter = update.counter;
                passkey.backed_up = update.backed_up;
                passkey.device_type = update.device_type;
                passkey.updated_at = Utc::now();
                Ok(Some(passkey.clone()))
            })
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let name = self
            .model_fields
            .name_for_storage(EntityRole::Passkey, Some(Some(name.to_owned())), false)
            .await?;
        let row = self
            .raw("passkey", "update", |state| {
                let Some(mut passkey) = state.passkeys.get_mut(id)? else {
                    return Ok(None);
                };
                if let Some(name) = name {
                    passkey.name = name;
                }
                passkey.updated_at = Utc::now();
                Ok(Some(passkey.clone()))
            })
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.raw("passkey", "delete", |state| {
            let _ = state.passkeys.remove(id)?;
            Ok(())
        })
        .await
    }
}
