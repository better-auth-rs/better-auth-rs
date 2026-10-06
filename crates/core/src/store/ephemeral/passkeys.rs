use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::{PasskeyStore, schema::EntityRole};
use crate::user_fields::{project_adapter_value, project_source_fields_then};
use crate::{
    AuthError, AuthResult, CreatePasskey, Passkey, PasskeyCredentialState,
    UpdatePasskeyAuthentication,
};

impl EphemeralStore {
    async fn project_passkey_refs(
        &self,
        mut rows: Vec<(Passkey, RowRef<Passkey>)>,
    ) -> AuthResult<Vec<Passkey>> {
        let configured = self.model_fields.fields(EntityRole::Passkey).fields();
        // Unconfigured display fields still read after earlier callbacks; credential fields retain their snapshot.
        let fields = ["name", "aaguid"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    configured.get(name).cloned().unwrap_or_default(),
                )
            })
            .collect();
        project_source_fields_then(
            &mut rows,
            &fields,
            |(_, source), name, _| {
                source.read(|row| match name {
                    "name" => row.name.json(),
                    _ => row.aaguid.json(),
                })
            },
            |(snapshot, _), name, field, value| {
                Box::pin(async move {
                    let value = project_adapter_value(value, field, false, true)
                        .await?
                        .json()?
                        .map(serde_json::from_value)
                        .transpose()?
                        .map(crate::SchemaValue::Typed)
                        .unwrap_or_default();
                    match name {
                        "name" => snapshot.name = value,
                        _ => snapshot.aaguid = value,
                    }
                    Ok(())
                })
            },
            |_, (snapshot, _)| Ok(snapshot.clone()),
        )
        .await
    }

    async fn find_passkey(
        &self,
        predicate: impl Fn(&Passkey) -> bool + Send,
    ) -> AuthResult<Option<Passkey>> {
        let selected = self
            .raw("passkey", "findOne", |state| {
                state
                    .passkeys
                    .first_ref(predicate)?
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        Ok(self
            .project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop())
    }
}

#[async_trait]
impl PasskeyStore for EphemeralStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let PasskeyCredentialState::Legacy(credential) = input.credential else {
            return Err(AuthError::config(
                "Native passkey creation requires Native storage",
            ));
        };
        let now = Utc::now();
        let fields = self
            .model_fields
            .passkey_fields_for_storage(input.name, input.aaguid, true)
            .await?;
        let mut passkey = Passkey {
            id: self
                .generated_id("passkey", None, self.lock()?.passkeys.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            user_id: input.user_id,
            name: fields.name.map(Into::into).unwrap_or_default(),
            credential_id: input.credential_id,
            public_key: input.public_key,
            counter: input.counter,
            device_type: input.device_type,
            backed_up: input.backed_up,
            transports: input.transports,
            credential: credential.into(),
            aaguid: fields.aaguid.map(Into::into).unwrap_or_default(),
            created_at: Some(now).into(),
            updated_at: now.into(),
        };
        let selected = self
            .raw("passkey", "create", |state| {
                self.assign_insert_serial_id(&mut passkey.id, state.passkeys.len());
                let source = state.passkeys.push_ref(passkey.clone());
                Ok((passkey, source))
            })
            .await?;
        Ok(self.project_passkey_refs(vec![selected]).await?.remove(0))
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        self.find_passkey(|row| row.id == id).await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        self.find_passkey(|row| row.credential_id == credential_id)
            .await
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let selected = self
            .raw("passkey", "findMany", |state| {
                crate::query::paginate_memory(
                    state.passkeys.select_refs(|row| row.user_id == user_id)?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                )
                .into_iter()
                .map(|source| {
                    let snapshot = source.read(|row| Ok(row.clone()))?;
                    Ok((snapshot, source))
                })
                .collect()
            })
            .await?;
        self.project_passkey_refs(selected).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let UpdatePasskeyAuthentication::Legacy {
            credential,
            counter,
            backed_up,
            device_type,
        } = update
        else {
            return Err(AuthError::config(
                "Native passkey authentication updates require Native storage",
            ));
        };
        let fields = self
            .model_fields
            .passkey_fields_for_storage(Default::default(), Default::default(), false)
            .await?;
        let selected = self
            .raw("passkey", "update", |state| {
                let Some(source) = state.passkeys.first_ref(|row| &row.id == id)? else {
                    return Ok(None);
                };
                let snapshot = source.write(|passkey| {
                    fields.apply(passkey);
                    passkey.credential = credential.into();
                    passkey.counter = counter;
                    passkey.backed_up = backed_up;
                    passkey.device_type = device_type;
                    passkey.updated_at = Utc::now().into();
                    Ok(passkey.clone())
                })?;
                Ok(Some((snapshot, source)))
            })
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_refs(vec![selected]).await?.remove(0))
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let fields = self
            .model_fields
            .passkey_fields_for_storage(Some(name.to_owned()).into(), Default::default(), false)
            .await?;
        let selected = self
            .raw("passkey", "update", |state| {
                let Some(source) = state.passkeys.first_ref(|row| row.id == id)? else {
                    return Ok(None);
                };
                let snapshot = source.write(|passkey| {
                    fields.apply(passkey);
                    passkey.updated_at = Utc::now().into();
                    Ok(passkey.clone())
                })?;
                Ok(Some((snapshot, source)))
            })
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_refs(vec![selected]).await?.remove(0))
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.raw("passkey", "delete", |state| {
            let _ = state.passkeys.remove(id)?;
            Ok(())
        })
        .await
    }
}
