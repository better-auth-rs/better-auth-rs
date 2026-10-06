use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect,
};
use serde_json::{Map, Value, json};

use better_auth_core::store::{PasskeyStore, schema::EntityRole};
use better_auth_core::{PasskeyCredentialState, PasskeyStorage};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};

use super::{SeaOrmStore, map_db_err};

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
        self.create_passkey_with_connection(self.connection(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_passkey_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("credential_id")?.eq(credential_id))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_passkey_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let models =
            database_operation::<Entity<P::Passkey>, _>(self.config(), "findMany", async {
                Entity::<P::Passkey>::find()
                    .filter(
                        P::Passkey::column("user_id")?
                            .eq_id(user_id, self.config().advanced.database.generate_id())?,
                    )
                    .limit(super::pagination::default_limit(
                        self.config(),
                        self.connection().get_database_backend(),
                    )?)
                    .all(self.connection())
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
        let id = id.typed()?;
        let (counter, fields) = match (P::Passkey::passkey_storage(), update) {
            (PasskeyStorage::Native, UpdatePasskeyAuthentication::Native { counter }) => {
                (counter, Map::new())
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
                Map::from_iter([
                    ("backed_up".into(), json!(backed_up)),
                    ("device_type".into(), json!(device_type)),
                    ("credential".into(), json!(credential)),
                    ("updated_at".into(), json!(Utc::now())),
                ]),
            ),
            _ => {
                return Err(AuthError::config(
                    "Passkey authentication update does not match the model storage mode",
                ));
            }
        };
        let patch = self
            .prepare_passkey_fields(fields, Map::new(), false)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(model) = Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            let counter = i64::try_from(counter)
                .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
            let mut active = model.into_active_model();
            super::plugin_models::apply_active_fields::<P::Passkey>(&mut active, patch);
            super::plugin_models::set::<P::Passkey>(
                &mut active,
                "counter",
                counter,
                self.config().advanced.database.generate_id(),
            )?;
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let mut fields = Map::from_iter([("name".into(), json!(name))]);
        if P::Passkey::passkey_storage() == PasskeyStorage::Legacy {
            let _ = fields.insert("updated_at".into(), json!(Utc::now()));
        }
        let patch = self
            .prepare_passkey_fields(fields, Map::new(), false)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(model) = Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            let mut active = model.into_active_model();
            super::plugin_models::apply_active_fields::<P::Passkey>(&mut active, patch);
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "delete", async {
            Entity::<P::Passkey>::delete_many()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_passkey_fields(&self) -> AuthResult<()> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        super::plugin_models::validate_field_columns(
            "Passkey schema",
            fields,
            P::Passkey::column,
            P::Passkey::core_field_name,
        )?;
        let mut extras = fields.clone();
        extras
            .fields_mut()
            .retain(|name, _| !matches!(name.as_str(), "name" | "aaguid"));
        super::plugin_models::validate_additional_field_columns::<P::Passkey>(
            EntityRole::Passkey,
            &extras,
        )
    }

    async fn project_passkey_models(&self, models: Vec<P::Passkey>) -> AuthResult<Vec<Passkey>> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        let records = models
            .iter()
            .map(|model| model.record_fields(fields))
            .collect::<AuthResult<Vec<_>>>()?;
        let rows = models
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields
            .project_passkey_records(
                rows,
                records,
                self.connection().get_database_backend() == DbBackend::Postgres,
            )
            .await
    }

    async fn prepare_passkey_fields(
        &self,
        mut native: Map<String, Value>,
        mut extras: Map<String, Value>,
        create: bool,
    ) -> AuthResult<<P::Passkey as SeaOrmPluginModel>::ActiveModel> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        let _ = extras.remove("name");
        let _ = extras.remove("aaguid");
        extras.extend(native.clone());
        let mut active = super::plugin_models::additional_fields::<P::Passkey>(
            fields,
            extras,
            self.config().advanced.database.generate_id(),
            self.connection().get_database_backend(),
            create,
        )
        .await?;
        native.retain(|name, _| !fields.fields().contains_key(name));
        if create {
            native = self.create_fields("passkey", None, native)?;
        }
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
        input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
        let credential = match (P::Passkey::passkey_storage(), input.credential) {
            (PasskeyStorage::Native, PasskeyCredentialState::Native) => None,
            (PasskeyStorage::Legacy, PasskeyCredentialState::Legacy(value)) => Some(value),
            _ => {
                return Err(AuthError::config(
                    "Passkey creation does not match the model storage mode",
                ));
            }
        };

        let mut fields = Map::from_iter([
            ("public_key".to_owned(), json!(input.public_key)),
            ("user_id".to_owned(), json!(input.user_id)),
            ("credential_id".to_owned(), json!(input.credential_id)),
            ("counter".to_owned(), json!(counter)),
            ("device_type".to_owned(), json!(input.device_type)),
            ("backed_up".to_owned(), json!(input.backed_up)),
            ("transports".to_owned(), json!(input.transports)),
        ]);
        if let Some(credential) = &credential {
            let _ = fields.insert("credential".into(), json!(credential));
        }
        let _ = fields.insert("created_at".into(), json!(Utc::now()));
        if credential.is_some() {
            let _ = fields.insert("updated_at".into(), json!(Utc::now()));
        }
        for (name, value) in [("name", input.name), ("aaguid", input.aaguid)] {
            if let Some(value) = value.json()? {
                let _ = fields.insert(name.into(), value);
            }
        }
        let active = self
            .prepare_passkey_fields(fields, input.additional_fields, true)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "create", async {
            active.insert(connection).await.map_err(map_db_err)
        })
        .await?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
}
