use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::{
    PasskeyStore,
    schema::{EntityRole, resolve_field_name},
};
use crate::user_fields::{project_adapter_value, project_source_fields_then};
use crate::{
    AuthError, AuthResult, CreatePasskey, Passkey, PasskeyCredentialState, UpdatePasskey,
    UpdatePasskeyAuthentication,
};

impl EphemeralStore {
    async fn project_passkey_refs(
        &self,
        mut rows: Vec<(Passkey, RowRef<Passkey>)>,
    ) -> AuthResult<Vec<Passkey>> {
        let configured = self.model_fields.fields(EntityRole::Passkey).fields();
        // Unconfigured display fields still read after earlier callbacks; credential fields retain their snapshot.
        let mut fields: indexmap::IndexMap<_, _> = ["name", "aaguid"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    configured.get(name).cloned().unwrap_or_default(),
                )
            })
            .collect();
        fields.extend(configured.clone());
        for (snapshot, _) in &mut rows {
            snapshot.additional_fields.clear();
            snapshot.user_id = Self::project_id(&snapshot.user_id)?;
        }
        project_source_fields_then(
            &mut rows,
            &fields,
            |(_, source), name, field| {
                source.read(|row| match name {
                    "name" => Ok(row.name.field_value()),
                    "aaguid" => Ok(row.aaguid.field_value()),
                    _ => Ok(row
                        .additional_fields
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned()
                        .unwrap_or_default()),
                })
            },
            |(snapshot, _), name, field, value| {
                Box::pin(async move {
                    let value =
                        project_adapter_value(value, field, field.references_id(), true).await?;
                    if matches!(name, "name" | "aaguid") {
                        let value = crate::SchemaValue::from_field(value);
                        if name == "name" {
                            snapshot.name = value;
                        } else {
                            snapshot.aaguid = value;
                        }
                    } else {
                        let _ = snapshot.additional_fields.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
            |_, (snapshot, source)| {
                snapshot.id = source.read(|row| Self::project_id(&row.id))?;
                Ok(snapshot.clone())
            },
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
        let now = crate::FieldDate::from(Utc::now());
        let fields = self
            .model_fields
            .passkey_fields_for_storage(
                input.name,
                input.aaguid,
                input.additional_fields,
                true,
                |field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let mut passkey = Passkey {
            additional_fields: fields.additional_fields,
            id: self
                .generated_id("passkey", None, self.lock()?.passkeys.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            user_id: self.memory_reference_id_input(input.user_id.into())?,
            name: fields.name.unwrap_or_default(),
            credential_id: input.credential_id,
            public_key: input.public_key,
            counter: input.counter,
            device_type: input.device_type,
            backed_up: input.backed_up,
            transports: input.transports,
            credential: credential.into(),
            aaguid: fields.aaguid.unwrap_or_default(),
            created_at: Some(now.clone()).into(),
            updated_at: now.into(),
        };
        let selected = self
            .raw("passkey", "create", |state| {
                if let Some(id) = self.next_serial_id(state.passkeys.len()) {
                    passkey.id = crate::SchemaValue::from_field(id);
                }
                let source = state.passkeys.push_ref(passkey.clone());
                Ok((passkey, source))
            })
            .await?;
        Ok(self.project_passkey_refs(vec![selected]).await?.remove(0))
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let id = self.memory_primary_id_query(&crate::FieldValue::from(id))?;
        self.find_passkey(|row| row.id.field_value().strict_equals(&id))
            .await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        self.find_passkey(|row| row.credential_id == credential_id)
            .await
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let user_id = self.memory_primary_id_query(&crate::FieldValue::from(user_id))?;
        let selected = self
            .raw("passkey", "findMany", |state| {
                crate::query::paginate_memory(
                    state
                        .passkeys
                        .select_refs(|row| row.user_id.field_value().strict_equals(&user_id))?,
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
            .passkey_fields_for_storage(
                Default::default(),
                Default::default(),
                Default::default(),
                false,
                |field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let id = self.memory_primary_id_query(&id.field_value())?;
        let selected = self
            .raw("passkey", "update", |state| {
                let Some(source) = state
                    .passkeys
                    .first_ref(|row| row.id.field_value().strict_equals(&id))?
                else {
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

    async fn update_passkey(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskey,
    ) -> AuthResult<Passkey> {
        let fields = self
            .model_fields
            .passkey_fields_for_storage(
                update.name,
                update.aaguid,
                update.additional_fields,
                false,
                |field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let id = self.memory_primary_id_query(&id.field_value())?;
        let selected = self
            .raw("passkey", "update", |state| {
                let Some(source) = state
                    .passkeys
                    .first_ref(|row| row.id.field_value().strict_equals(&id))?
                else {
                    return Ok(None);
                };
                let snapshot = source.write(|passkey| {
                    fields.apply(passkey);
                    if let Some(counter) = update.counter {
                        passkey.counter = counter;
                    }
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
        let id = self.memory_primary_id_query(&crate::FieldValue::from(id))?;
        self.raw("passkey", "delete", |state| {
            let _ = state
                .passkeys
                .remove_first(|row| row.id.field_value().strict_equals(&id))?;
            Ok(())
        })
        .await
    }
}
