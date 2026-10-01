use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::{Entity, apply};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect,
};
use serde_json::{Map, json};

use better_auth_core::store::{PasskeyStore, schema::EntityRole};

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
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_with_connection(self.connection(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let row = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
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
        let row = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("credential_id")?.eq(credential_id))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()?;
        Ok(self
            .model_fields
            .project_passkeys(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let rows = database_operation::<Entity<P::Passkey>, _>(self.config(), "findMany", async {
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
        .await?
        .iter()
        .map(SeaOrmPluginModel::record)
        .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields.project_passkeys(rows).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let id = id.typed()?;
        let fields = self
            .model_fields
            .fields(EntityRole::Passkey)
            .organization_storage_fields(
                Map::from_iter([
                    ("counter".into(), json!(update.counter)),
                    ("backed_up".into(), json!(update.backed_up)),
                    ("device_type".into(), json!(update.device_type)),
                    ("credential".into(), json!(update.credential)),
                    ("updated_at".into(), json!(Utc::now())),
                ]),
                Map::new(),
                false,
            )
            .await?;
        let row = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
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

            let _ = i64::try_from(update.counter)
                .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
            let mut active = model.into_active_model();
            apply::<P::Passkey>(
                &mut active,
                fields,
                self.config().advanced.database.generate_id(),
            )?;
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?
        .record()?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let fields = self
            .model_fields
            .fields(EntityRole::Passkey)
            .organization_storage_fields(
                Map::from_iter([
                    ("name".into(), json!(name)),
                    ("updated_at".into(), json!(Utc::now())),
                ]),
                Map::new(),
                false,
            )
            .await?;
        let row = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
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
            apply::<P::Passkey>(
                &mut active,
                fields,
                self.config().advanced.database.generate_id(),
            )?;
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?
        .record()?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
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
    pub(super) async fn create_passkey_with_connection(
        &self,
        connection: &impl sea_orm::ConnectionTrait,
        input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        let mut fields = Map::from_iter([
            ("public_key".to_owned(), json!(input.public_key)),
            ("user_id".to_owned(), json!(input.user_id)),
            ("credential_id".to_owned(), json!(input.credential_id)),
            ("counter".to_owned(), json!(counter)),
            ("device_type".to_owned(), json!(input.device_type)),
            ("backed_up".to_owned(), json!(input.backed_up)),
            ("transports".to_owned(), json!(input.transports)),
            ("credential".to_owned(), json!(input.credential)),
            ("created_at".to_owned(), json!(Utc::now())),
            ("updated_at".to_owned(), json!(Utc::now())),
        ]);
        for (name, value) in [("name", input.name), ("aaguid", input.aaguid)] {
            if let Some(value) = value.json()? {
                let _ = fields.insert(name.into(), value);
            }
        }
        let fields = self
            .model_fields
            .fields(EntityRole::Passkey)
            .organization_storage_fields(fields, Map::new(), true)
            .await?;
        let fields = self.create_fields("passkey", None, fields)?;
        let active = super::plugin_models::active::<P::Passkey>(
            fields,
            self.config().advanced.database.generate_id(),
        )?;
        let row = database_operation::<Entity<P::Passkey>, _>(self.config(), "create", async {
            active.insert(connection).await.map_err(map_db_err)
        })
        .await?
        .record()?;
        Ok(self
            .model_fields
            .project_passkeys(vec![row])
            .await?
            .remove(0))
    }
}
