use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::{PasskeyStore, schema::EntityRole};
use crate::{
    AuthError, AuthResult, CreatePasskey, FieldMap, FieldValue, FromFieldMap, Passkey, SchemaValue,
    UpdatePasskey, UpdatePasskeyAuthentication,
};

impl EphemeralStore {
    async fn project_passkey_refs(&self, rows: Vec<RowRef<FieldMap>>) -> AuthResult<Vec<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let internal = rows
            .iter()
            .map(|source| {
                source.read(|row| {
                    let mut fields = FieldMap::new();
                    for definition in crate::store::schema::core_fields(EntityRole::Passkey) {
                        let name = better_auth_schema_registry::canonical_field_name(
                            EntityRole::Passkey,
                            definition.name,
                        );
                        if name != "id"
                            && !schema.fields().contains_key(&name)
                            && let Some(value) = row.get(&name)
                        {
                            let _ = fields.insert(name, value.clone());
                        }
                    }
                    Ok(fields)
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_plugin_refs(EntityRole::Passkey, rows)
            .await?
            .into_iter()
            .zip(internal)
            .map(|(mut fields, internal)| {
                fields.extend(internal);
                Passkey::from_field_values(fields)
            })
            .collect()
    }

    async fn find_passkey(
        &self,
        predicate: impl Fn(&FieldMap) -> bool + Send,
    ) -> AuthResult<Option<Passkey>> {
        let selected = self
            .raw("passkey", "findOne", |state| {
                state.passkeys.first_ref(predicate)
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
    async fn create_passkey_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record(EntityRole::Passkey, input, Default::default())
            .await
    }

    async fn get_passkey_record(&self, id: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::Passkey, id).await
    }

    async fn update_passkey_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::Passkey, id, input, Default::default())
            .await
    }

    async fn create_passkey(&self, mut input: CreatePasskey) -> AuthResult<Passkey> {
        let extras = std::mem::take(&mut input.additional_fields);
        let mut native = input.into_adapter_fields()?;
        let now: crate::FieldDate = Utc::now().into();
        let _ = native.insert("createdAt".into(), now.clone().into());
        let _ = native.insert("updatedAt".into(), now.into());
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let internal: FieldMap = native
            .iter()
            .filter(|(name, _)| !schema.fields().contains_key(*name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let mut fields = extras;
        fields.extend(native);
        let mut projected = self
            .create_plugin_record(EntityRole::Passkey, fields, internal.clone())
            .await?;
        projected.extend(internal);
        Passkey::from_field_values(projected)
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let id = self.plugin_query_value(EntityRole::Passkey, "id", id.into())?;
        self.find_passkey(|row| row.get("id").is_some_and(|value| value.strict_equals(&id)))
            .await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let column = schema.record_storage_key("credentialID");
        let value =
            self.plugin_query_value(EntityRole::Passkey, "credentialID", credential_id.into())?;
        self.find_passkey(|row| {
            row.get(column)
                .is_some_and(|actual| actual.strict_equals(&value))
        })
        .await
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let column = schema.record_storage_key("userId");
        let value = self.plugin_query_value(EntityRole::Passkey, "userId", user_id.into())?;
        let selected = self
            .raw("passkey", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state.passkeys.select_refs(|row| {
                        row.get(column)
                            .is_some_and(|actual| actual.strict_equals(&value))
                    })?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.project_passkey_refs(selected).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let mut fields = FieldMap::new();
        let mut internal = FieldMap::new();
        match update {
            UpdatePasskeyAuthentication::Native { counter } => {
                let _ = fields.insert("counter".into(), FieldValue::from(counter));
            }
            UpdatePasskeyAuthentication::Legacy {
                credential,
                counter,
                backed_up,
                device_type,
            } => {
                fields.extend([
                    ("counter".into(), FieldValue::from(counter)),
                    ("backedUp".into(), backed_up.into()),
                    ("deviceType".into(), device_type.into()),
                ]);
                internal.extend([
                    ("credential".into(), credential.into()),
                    ("updatedAt".into(), Utc::now().into()),
                ]);
            }
        }
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let declared: FieldMap = internal
            .iter()
            .filter(|(name, _)| schema.fields().contains_key(*name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        for name in declared.keys() {
            let _ = internal.shift_remove(name);
        }
        fields.extend(declared);
        let selected = self
            .update_plugin_ref(EntityRole::Passkey, id, fields, internal)
            .await?;
        self.project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop()
            .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn update_passkey(
        &self,
        id: &SchemaValue<String>,
        update: UpdatePasskey,
    ) -> AuthResult<Passkey> {
        let mut fields = update.into_adapter_fields()?;
        let updated_at: FieldValue = Utc::now().into();
        let internal = if self
            .model_fields
            .plugin_fields(EntityRole::Passkey)
            .fields()
            .contains_key("updatedAt")
        {
            let _ = fields.insert("updatedAt".into(), updated_at);
            FieldMap::new()
        } else {
            FieldMap::from([("updatedAt".into(), updated_at)])
        };
        let selected = self
            .update_plugin_ref(EntityRole::Passkey, id, fields, internal)
            .await?;
        self.project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop()
            .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.delete_plugin_records(EntityRole::Passkey, &id.into())
            .await
    }
}
