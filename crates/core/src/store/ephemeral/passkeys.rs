use std::cmp::Reverse;

use async_trait::async_trait;
use chrono::Utc;

use super::EphemeralStore;
use crate::store::PasskeyStore;
use crate::{AuthError, AuthResult, CreatePasskey, Passkey, UpdatePasskeyAuthentication};

#[async_trait]
impl PasskeyStore for EphemeralStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let now = Utc::now();
        let passkey = Passkey {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: input.user_id,
            name: input.name,
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
        let _ = self
            .lock()?
            .passkeys
            .insert(passkey.id.clone(), passkey.clone());
        Ok(passkey)
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        Ok(self.lock()?.passkeys.get(id).cloned())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Ok(self
            .lock()?
            .passkeys
            .values()
            .find(|passkey| passkey.credential_id == credential_id)
            .cloned())
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let mut passkeys: Vec<_> = self
            .lock()?
            .passkeys
            .values()
            .filter(|passkey| passkey.user_id == user_id)
            .cloned()
            .collect();
        passkeys.sort_by_key(|passkey| Reverse(passkey.created_at.timestamp_millis()));
        Ok(passkeys)
    }

    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let mut state = self.lock()?;
        let passkey = state
            .passkeys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        passkey.credential = update.credential;
        passkey.counter = update.counter;
        passkey.backed_up = update.backed_up;
        passkey.device_type = update.device_type;
        passkey.updated_at = Utc::now();
        Ok(passkey.clone())
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let mut state = self.lock()?;
        let passkey = state
            .passkeys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        passkey.name = Some(name.to_owned());
        passkey.updated_at = Utc::now();
        Ok(passkey.clone())
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        let _ = self.lock()?.passkeys.shift_remove(id);
        Ok(())
    }
}
