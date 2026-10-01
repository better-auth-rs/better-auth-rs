use super::instrumentation::database_operation;
use super::plugin_models::{Entity, set};
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
};
use serde_json::{Map, json};

use better_auth_core::store::PasskeyStore;

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
        database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("id")?.eq(id))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("credential_id")?.eq(credential_id))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .map(|model| model.record())
        .transpose()
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "findMany", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("user_id")?.eq(user_id))
                .order_by_desc(P::Passkey::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?
        .iter()
        .map(SeaOrmPluginModel::record)
        .collect()
    }

    async fn update_passkey_authentication(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let id = id.typed()?;
        database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(model) = Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("id")?.eq(id))
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };

            let mut active = model.into_active_model();
            set::<P::Passkey>(
                &mut active,
                "counter",
                i64::try_from(update.counter)
                    .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?,
            )?;
            set::<P::Passkey>(&mut active, "backed_up", update.backed_up)?;
            set::<P::Passkey>(&mut active, "device_type", update.device_type)?;
            set::<P::Passkey>(&mut active, "credential", update.credential)?;
            set::<P::Passkey>(&mut active, "updated_at", Utc::now())?;
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?
        .record()
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(model) = Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("id")?.eq(id))
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };

            let mut active = model.into_active_model();
            set::<P::Passkey>(&mut active, "name", Some(name.to_owned()))?;
            set::<P::Passkey>(&mut active, "updated_at", Utc::now())?;
            let model = active.update(self.connection()).await.map_err(map_db_err)?;
            Ok(Some(model))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?
        .record()
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "delete", async {
            Entity::<P::Passkey>::delete_many()
                .filter(P::Passkey::column("id")?.eq(id))
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

        let active = P::Passkey::active(self.create_fields(
            "passkey",
            None,
            Map::from_iter([
                ("name".to_owned(), json!(input.name)),
                ("public_key".to_owned(), json!(input.public_key)),
                ("user_id".to_owned(), json!(input.user_id)),
                ("credential_id".to_owned(), json!(input.credential_id)),
                ("counter".to_owned(), json!(counter)),
                ("device_type".to_owned(), json!(input.device_type)),
                ("backed_up".to_owned(), json!(input.backed_up)),
                ("transports".to_owned(), json!(input.transports)),
                ("credential".to_owned(), json!(input.credential)),
                ("aaguid".to_owned(), json!(input.aaguid)),
                ("created_at".to_owned(), json!(Utc::now())),
                ("updated_at".to_owned(), json!(Utc::now())),
            ]),
        )?)?;
        database_operation::<Entity<P::Passkey>, _>(self.config(), "create", async {
            active.insert(connection).await.map_err(map_db_err)
        })
        .await?
        .record()
    }
}
