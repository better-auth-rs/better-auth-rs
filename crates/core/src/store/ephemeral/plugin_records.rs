use super::{
    EphemeralStore, State,
    rows::{RecordSource, RowRef, Rows},
};
use crate::store::schema::EntityRole;
use crate::{AuthError, AuthRecordFields, AuthResult, FieldMap, FieldValue, SchemaValue};

impl State {
    fn plugin_rows(&self, role: EntityRole) -> AuthResult<&Rows<FieldMap>> {
        match role {
            EntityRole::ApiKey => Ok(&self.api_keys),
            EntityRole::Passkey => Ok(&self.passkeys),
            EntityRole::DeviceCode => Ok(&self.device_codes),
            EntityRole::TwoFactor => Ok(&self.two_factors),
            EntityRole::Jwk => Ok(&self.jwks),
            EntityRole::WalletAddress => Ok(&self.wallets),
            _ => Err(AuthError::config(format!(
                "Plugin record storage is not implemented for {role:?}"
            ))),
        }
    }

    fn plugin_rows_mut(&mut self, role: EntityRole) -> AuthResult<&mut Rows<FieldMap>> {
        match role {
            EntityRole::ApiKey => Ok(&mut self.api_keys),
            EntityRole::Passkey => Ok(&mut self.passkeys),
            EntityRole::DeviceCode => Ok(&mut self.device_codes),
            EntityRole::TwoFactor => Ok(&mut self.two_factors),
            EntityRole::Jwk => Ok(&mut self.jwks),
            EntityRole::WalletAddress => Ok(&mut self.wallets),
            _ => Err(AuthError::config(format!(
                "Plugin record storage is not implemented for {role:?}"
            ))),
        }
    }
}

fn model(role: EntityRole) -> AuthResult<&'static str> {
    match role {
        EntityRole::ApiKey => Ok("apikey"),
        EntityRole::Passkey => Ok("passkey"),
        EntityRole::DeviceCode => Ok("deviceCode"),
        EntityRole::TwoFactor => Ok("twoFactor"),
        EntityRole::Jwk => Ok("jwks"),
        EntityRole::WalletAddress => Ok("walletAddress"),
        _ => Err(AuthError::config(format!(
            "Plugin record storage is not implemented for {role:?}"
        ))),
    }
}

impl EphemeralStore {
    pub(super) fn plugin_query_value(
        &self,
        role: EntityRole,
        name: &str,
        value: FieldValue,
    ) -> AuthResult<FieldValue> {
        self.model_fields.begin_id_query(role)?;
        if name == "id" {
            self.memory_primary_id_query(&value)
        } else {
            let fields = self.model_fields.plugin_fields(role);
            if !fields.fields().contains_key(name) {
                return Err(AuthError::config(format!(
                    "Unknown plugin field {role:?}.{name}"
                )));
            }
            self.memory_field_query(&fields, name, value)
        }
    }

    pub(super) async fn project_plugin_refs(
        &self,
        role: EntityRole,
        sources: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_record_sources(
            role,
            &self.model_fields.plugin_fields(role),
            sources.into_iter().map(RecordSource::Live).collect(),
        )
        .await
    }

    pub(super) async fn prepare_plugin_fields(
        &self,
        role: EntityRole,
        mut input: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        let mut supplied = input.shift_remove("id");
        self.model_fields.begin_id_input(
            role,
            crate::id::AdapterIdInput {
                force_allow_id: create && supplied.is_some(),
                supports_native_uuid: false,
            },
        )?;
        let schema = self.model_fields.plugin_fields(role);
        schema
            .storage_fields_with_bound_id(
                input,
                create,
                || {
                    let Some(policy) = self.model_fields.id_input_policy(role)? else {
                        return Ok(supplied.take());
                    };
                    let generation = self.config.advanced.database.generate_id();
                    if create {
                        let count = self.lock()?.plugin_rows(role)?.len();
                        let id = generation.adapter_create_id_input(
                            model(role)?,
                            supplied.take(),
                            policy,
                        )?;
                        Ok(self.next_serial_id(count).or(id))
                    } else {
                        supplied
                            .take()
                            .map(|value| generation.adapter_id_input(value, policy))
                            .transpose()
                            .map(Option::flatten)
                    }
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await
    }

    pub(super) async fn create_plugin_record(
        &self,
        role: EntityRole,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<FieldMap> {
        let source = self.create_plugin_ref(role, input, internal).await?;
        self.project_plugin_refs(role, vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Created plugin record was not projected"))
    }

    pub(super) async fn create_plugin_ref(
        &self,
        role: EntityRole,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<RowRef<FieldMap>> {
        let mut storage = self.prepare_plugin_fields(role, input, true).await?;
        storage.extend(internal);
        self.raw(model(role)?, "create", |state| {
            if let Some(id) = self.next_serial_id(state.plugin_rows(role)?.len()) {
                let _ = storage.insert("id".into(), id);
            }
            Ok(state.plugin_rows_mut(role)?.push_ref(storage))
        })
        .await
    }

    pub(super) async fn get_plugin_record(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        let id = self.plugin_query_value(role, "id", id.field_value())?;
        let selected = self
            .raw(model(role)?, "findOne", |state| {
                state.plugin_rows(role)?.first_ref(|row| {
                    crate::query::field_matches_equality(
                        row.get("id").unwrap_or(&FieldValue::Undefined),
                        &id,
                    )
                })
            })
            .await?;
        Ok(self
            .project_plugin_refs(role, selected.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn update_plugin_record(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let selected = self.update_plugin_ref(role, id, input, internal).await?;
        Ok(self
            .project_plugin_refs(role, selected.into_iter().collect())
            .await?
            .pop())
    }

    pub(super) async fn update_plugin_ref(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let id = self.plugin_query_value(role, "id", id.field_value())?;
        let mut patch = self.prepare_plugin_fields(role, input, false).await?;
        patch.extend(internal);
        self.raw(model(role)?, "update", |state| {
            let matches = state.plugin_rows(role)?.select_refs(|row| {
                crate::query::field_matches_equality(
                    row.get("id").unwrap_or(&FieldValue::Undefined),
                    &id,
                )
            })?;
            for source in &matches {
                source.write(|row| {
                    row.extend(patch.clone());
                    Ok(())
                })?;
            }
            Ok(matches.into_iter().next())
        })
        .await
    }

    pub(super) async fn delete_plugin_records(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        let id = self.plugin_query_value(role, "id", id.field_value())?;
        self.raw(model(role)?, "delete", |state| {
            state.plugin_rows_mut(role)?.retain(|row| {
                !crate::query::field_matches_equality(
                    row.get("id").unwrap_or(&FieldValue::Undefined),
                    &id,
                )
            })?;
            Ok(())
        })
        .await
    }

    /// Observe complete physical records without invoking output callbacks.
    #[doc(hidden)]
    pub fn plugin_storage_rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        self.storage_rows(role)
    }

    /// Observe complete physical records without applying query limits or output callbacks.
    #[doc(hidden)]
    pub fn storage_rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        let state = self.lock()?;
        match role {
            EntityRole::User => state
                .users
                .snapshot()?
                .iter()
                .map(AuthRecordFields::field_values)
                .collect(),
            EntityRole::Session => state.sessions.snapshot(),
            EntityRole::Account => state.accounts.snapshot(),
            EntityRole::Verification => state.verifications.snapshot(),
            EntityRole::Organization => state.organizations.snapshot(),
            EntityRole::Member => state.members.snapshot(),
            EntityRole::Invitation => state.invitations.snapshot(),
            EntityRole::Team => state.teams.snapshot(),
            EntityRole::OrganizationRole => state.organization_roles.snapshot(),
            _ => state.plugin_rows(role)?.snapshot(),
        }
    }
}
