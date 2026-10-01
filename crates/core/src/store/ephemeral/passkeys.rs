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
        self.raw("passkey", "create", |state| {
            let _ = state.passkeys.insert(passkey.id.clone(), passkey.clone());
            Ok(passkey)
        })
        .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        self.raw("passkey", "findOne", |state| {
            Ok(state.passkeys.get(id).cloned())
        })
        .await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        self.raw("passkey", "findOne", |state| {
            Ok(state
                .passkeys
                .values()
                .find(|passkey| passkey.credential_id == credential_id)
                .cloned())
        })
        .await
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        self.raw("passkey", "findMany", |state| {
            let mut passkeys: Vec<_> = state
                .passkeys
                .values()
                .filter(|passkey| passkey.user_id == user_id)
                .cloned()
                .collect();
            passkeys.sort_by_key(|passkey| Reverse(passkey.created_at.timestamp_millis()));
            Ok(passkeys)
        })
        .await
    }

    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        self.raw("passkey", "update", |state| {
            let Some(passkey) = state.passkeys.get_mut(id) else {
                return Ok(None);
            };
            passkey.credential = update.credential;
            passkey.counter = update.counter;
            passkey.backed_up = update.backed_up;
            passkey.device_type = update.device_type;
            passkey.updated_at = Utc::now();
            Ok(Some(passkey.clone()))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        self.raw("passkey", "update", |state| {
            let Some(passkey) = state.passkeys.get_mut(id) else {
                return Ok(None);
            };
            passkey.name = Some(name.to_owned());
            passkey.updated_at = Utc::now();
            Ok(Some(passkey.clone()))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.raw("passkey", "delete", |state| {
            let _ = state.passkeys.shift_remove(id);
            Ok(())
        })
        .await
    }
}
