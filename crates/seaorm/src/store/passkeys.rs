use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::{FieldMap, FromFieldMap, SchemaField};
use chrono::Utc;
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait};

use better_auth_core::store::{PasskeyStore, schema::EntityRole};
use better_auth_core::{PasskeyCredentialState, PasskeyStorage, UpdatePasskey};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};

use super::{SeaOrmStore, map_db_err};

#[cfg(test)]
#[path = "passkey_record_tests.rs"]
mod record_tests;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> PasskeyStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    fn passkey_storage(&self) -> PasskeyStorage {
        P::Passkey::passkey_storage()
    }

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_optional(input)
            .await?
            .ok_or_else(|| AuthError::internal("Passkey creation returned no record"))
    }

    async fn create_passkey_optional(&self, input: CreatePasskey) -> AuthResult<Option<Passkey>> {
        self.create_passkey_with_connection(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            input,
        )
        .await
    }

    async fn create_passkey_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.create_plugin_record::<P::Passkey>(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            EntityRole::Passkey,
            "passkey",
            input,
        )
        .await
    }

    async fn update_passkey_record(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let selector = self.bind_plugin_query_field(EntityRole::Passkey, "id", id.field_value())?;
        let patch = self
            .prepare_plugin_fields::<P::Passkey>(EntityRole::Passkey, "passkey", input, false)
            .await?;
        let filter = self.resolve_plugin_equals::<P::Passkey>(EntityRole::Passkey, selector)?;
        let row = self.update_passkey_patch(filter, patch).await?;
        Ok(self
            .project_plugin_rows::<P::Passkey, FieldMap>(
                EntityRole::Passkey,
                row.into_iter().collect(),
            )
            .await?
            .pop())
    }

    async fn get_passkey_record(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record::<P::Passkey>(self.connection(), EntityRole::Passkey, id)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let row = self.get_passkey_row(&id.to_owned().into()).await?;
        Ok(self
            .project_passkey_models(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            self.connection()
                .query_one_raw(
                    Entity::<P::Passkey>::find()
                        .filter(self.plugin_equals::<P::Passkey>(
                            EntityRole::Passkey,
                            "credentialID",
                            credential_id.into(),
                        )?)
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_passkey_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_passkeys_by_user_value(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Passkey>> {
        let models =
            database_operation::<Entity<P::Passkey>, _>(self.config(), "findMany", async {
                self.connection()
                    .query_all_raw(
                        Entity::<P::Passkey>::find()
                            .filter(self.plugin_equals::<P::Passkey>(
                                EntityRole::Passkey,
                                "userId",
                                user_id.clone(),
                            )?)
                            .limit(super::pagination::default_limit(
                                self.config(),
                                self.connection().get_database_backend(),
                            )?)
                            .build(self.connection().get_database_backend()),
                    )
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        self.project_passkey_models(models).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let (counter, mut fields) = match (P::Passkey::passkey_storage(), update) {
            (PasskeyStorage::Native, UpdatePasskeyAuthentication::Native { counter }) => {
                (counter, FieldMap::new())
            }
            (
                PasskeyStorage::Legacy,
                UpdatePasskeyAuthentication::Legacy {
                    credential,
                    counter,
                    backed_up,
                    device_type,
                },
            ) => (
                counter,
                FieldMap::from_iter([
                    ("backedUp".into(), (backed_up).into_field()),
                    ("deviceType".into(), (device_type).into_field()),
                    ("credential".into(), credential.to_owned().into_field()),
                    (
                        "updatedAt".into(),
                        better_auth_core::FieldValue::Date((Utc::now()).into()),
                    ),
                ]),
            ),
            _ => {
                return Err(AuthError::config(
                    "Passkey authentication update does not match the model storage mode",
                ));
            }
        };
        let _ = fields.insert("counter".into(), counter.into_field());
        let selector = self.bind_plugin_query_field(EntityRole::Passkey, "id", id.field_value())?;
        let patch = self
            .prepare_passkey_fields(fields, FieldMap::new(), false)
            .await?;
        let filter = self.resolve_plugin_equals::<P::Passkey>(EntityRole::Passkey, selector)?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(_model) = self
                .connection()
                .query_one_raw(
                    Entity::<P::Passkey>::find()
                        .filter(filter.clone())
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            super::updates::execute_update_returning_raw(
                self.connection(),
                patch
                    .update_returning(self.connection().get_database_backend())?
                    .filter(filter.clone()),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
    async fn update_passkey(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        mut update: UpdatePasskey,
    ) -> AuthResult<Passkey> {
        let selector = self.bind_plugin_query_field(EntityRole::Passkey, "id", id.field_value())?;
        let extras = std::mem::take(&mut update.additional_fields);
        let mut fields = update.into_adapter_fields()?;
        if P::Passkey::passkey_storage() == PasskeyStorage::Legacy {
            let _ = fields.insert(
                "updatedAt".into(),
                better_auth_core::FieldValue::Date((Utc::now()).into()),
            );
        }
        let patch = self.prepare_passkey_fields(fields, extras, false).await?;
        let filter = self.resolve_plugin_equals::<P::Passkey>(EntityRole::Passkey, selector)?;
        let row = self
            .update_passkey_patch(filter, patch)
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        self.project_passkey_models(vec![row])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Passkey creation returned no record"))
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.delete_plugin_record::<P::Passkey>(
            self.connection(),
            EntityRole::Passkey,
            &id.to_owned().into(),
        )
        .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    async fn get_passkey_row(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<Option<sea_orm::QueryResult>> {
        let filter = self.plugin_id_filter::<P::Passkey>(EntityRole::Passkey, id)?;
        database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            self.connection()
                .query_one_raw(
                    Entity::<P::Passkey>::find()
                        .filter(filter)
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)
        })
        .await
    }

    async fn update_passkey_patch(
        &self,
        filter: sea_orm::sea_query::SimpleExpr,
        patch: super::plugin_models::Write<P::Passkey>,
    ) -> AuthResult<Option<sea_orm::QueryResult>> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(_model) = self
                .connection()
                .query_one_raw(
                    Entity::<P::Passkey>::find()
                        .filter(filter.clone())
                        .build(self.connection().get_database_backend()),
                )
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            super::updates::execute_update_returning_raw(
                self.connection(),
                patch
                    .update_returning(self.connection().get_database_backend())?
                    .filter(filter.clone()),
                filter,
            )
            .await
        })
        .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_passkey_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::Passkey>(EntityRole::Passkey)
    }

    async fn project_passkey_models(
        &self,
        rows: Vec<sea_orm::QueryResult>,
    ) -> AuthResult<Vec<Passkey>> {
        let fields = self
            .model_fields
            .plugin_fields(EntityRole::Passkey)
            .adapter_fields(&[]);
        let internal = rows
            .iter()
            .map(|row| super::plugin_rows::undeclared_fields::<P::Passkey>(row, &fields))
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_plugin_rows::<P::Passkey, FieldMap>(EntityRole::Passkey, rows)
            .await?
            .into_iter()
            .zip(internal)
            .map(|(mut fields, internal)| {
                fields.extend(internal);
                self.typed_passkey(fields)
            })
            .collect()
    }

    fn typed_passkey(&self, mut fields: FieldMap) -> AuthResult<Passkey> {
        if P::Passkey::passkey_storage() == PasskeyStorage::Legacy
            && !self
                .model_fields
                .fields(EntityRole::Passkey)
                .fields()
                .contains_key("updatedAt")
            && let Some(value @ better_auth_core::FieldValue::String(_)) =
                fields.get_mut("updatedAt")
        {
            // Legacy Rust models retain their typed timestamp without adding an upstream field policy.
            *value = better_auth_core::query::field_date(value)?.into();
        }
        Passkey::from_field_values(fields)
    }

    async fn prepare_passkey_fields(
        &self,
        mut native: FieldMap,
        mut extras: FieldMap,
        create: bool,
    ) -> AuthResult<super::plugin_models::Write<P::Passkey>> {
        let fields = self.model_fields.plugin_fields(EntityRole::Passkey);
        extras.extend(native.clone());
        let mut active = self
            .prepare_plugin_fields::<P::Passkey>(EntityRole::Passkey, "passkey", extras, create)
            .await?;
        native.retain(|name, _| !fields.fields().contains_key(name));
        super::plugin_models::apply::<P::Passkey>(
            &mut active,
            native,
            self.config().advanced.database.generate_id(),
        )?;
        Ok(active)
    }

    pub(super) async fn create_passkey_with_connection(
        &self,
        connection: &impl sea_orm::ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        mut input: CreatePasskey,
    ) -> AuthResult<Option<Passkey>> {
        let legacy = match (P::Passkey::passkey_storage(), &input.credential) {
            (PasskeyStorage::Native, PasskeyCredentialState::Native) => false,
            (PasskeyStorage::Legacy, PasskeyCredentialState::Legacy(_)) => true,
            _ => {
                return Err(AuthError::config(
                    "Passkey creation does not match the model storage mode",
                ));
            }
        };

        let extras = std::mem::take(&mut input.additional_fields);
        let mut fields = input.into_adapter_fields()?;
        let _ = fields.insert(
            "createdAt".into(),
            better_auth_core::FieldValue::Date((Utc::now()).into()),
        );
        if legacy {
            let _ = fields.insert(
                "updatedAt".into(),
                better_auth_core::FieldValue::Date((Utc::now()).into()),
            );
        }
        let active = self.prepare_passkey_fields(fields, extras, true).await?;
        let row = self.insert_passkey(connection, scope, active).await?;
        Ok(self
            .project_passkey_models(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn insert_passkey(
        &self,
        connection: &impl sea_orm::ConnectionTrait,
        scope: super::create_readback::ReadbackScope<'_>,
        active: super::plugin_models::Write<P::Passkey>,
    ) -> AuthResult<Option<sea_orm::QueryResult>> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "create", async {
            active
                .insert_raw(
                    connection,
                    super::create_readback::CreateReadback {
                        schema: &self.model_fields.plugin_fields(EntityRole::Passkey),
                        policy: self.config().advanced.database.generate_id(),
                        scope,
                        column: P::Passkey::column,
                    },
                )
                .await
        })
        .await
    }
}
