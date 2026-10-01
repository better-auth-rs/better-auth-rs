use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::{AuthResult, CreateJwk, Jwk, store::JwksStore};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use serde_json::{Map, json};

use super::{SeaOrmStore, entities::jwk, map_db_err};

pub(super) struct JwtKeys;

impl sea_orm_migration::MigrationName for JwtKeys {
    fn name(&self) -> &str {
        "m20260930_000001_jwt_keys"
    }
}

#[async_trait]
impl sea_orm_migration::MigrationTrait for JwtKeys {
    async fn up(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .create_table(
                sea_orm::Schema::new(manager.get_database_backend())
                    .create_table_from_entity(jwk::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .drop_table(
                sea_orm::sea_query::Table::drop()
                    .table(jwk::Entity)
                    .to_owned(),
            )
            .await
    }
}

#[async_trait]
impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> JwksStore for SeaOrmStore<S, O, P>
{
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<Jwk>> {
        get::<P>(self.config(), self.connection(), id).await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        list::<P>(self.config(), self.connection()).await
    }
    async fn create_jwk(&self, input: CreateJwk) -> AuthResult<Jwk> {
        self.create_jwk_with_connection(self.connection(), input)
            .await
    }
}

#[async_trait]
impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> JwksStore for super::SeaOrmTransaction<S, O, P>
{
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<Jwk>> {
        get::<P>(self.store.config(), &self.tx, id).await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        list::<P>(self.store.config(), &self.tx).await
    }
    async fn create_jwk(&self, input: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with_connection(&self.tx, input).await
    }
}

async fn get<P: crate::SeaOrmPluginSchema>(
    config: &better_auth_core::AuthConfig,
    connection: &impl ConnectionTrait,
    id: &str,
) -> AuthResult<Option<Jwk>> {
    database_operation::<Entity<P::Jwk>, _>(config, "findOne", async {
        Entity::<P::Jwk>::find()
            .filter(P::Jwk::column("id")?.eq_id(id, config.advanced.database.generate_id())?)
            .one(connection)
            .await
            .map_err(map_db_err)
    })
    .await?
    .as_ref()
    .map(SeaOrmPluginModel::record)
    .transpose()
}

async fn list<P: crate::SeaOrmPluginSchema>(
    config: &better_auth_core::AuthConfig,
    connection: &impl ConnectionTrait,
) -> AuthResult<Vec<Jwk>> {
    database_operation::<Entity<P::Jwk>, _>(config, "findMany", async {
        Entity::<P::Jwk>::find()
            .limit(super::pagination::default_limit(
                config,
                connection.get_database_backend(),
            )?)
            .all(connection)
            .await
            .map_err(map_db_err)
    })
    .await?
    .iter()
    .map(SeaOrmPluginModel::record)
    .collect()
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    async fn create_jwk_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        input: CreateJwk,
    ) -> AuthResult<Jwk> {
        let active = super::plugin_models::active::<P::Jwk>(
            self.create_fields(
                "jwks",
                None,
                Map::from_iter([
                    ("public_key".to_owned(), json!(input.public_key)),
                    ("private_key".to_owned(), json!(input.private_key)),
                    ("created_at".to_owned(), json!(Utc::now())),
                    ("expires_at".to_owned(), json!(input.expires_at)),
                    ("alg".to_owned(), json!(Some(input.alg))),
                    ("crv".to_owned(), json!(input.crv)),
                ]),
            )?,
            self.config().advanced.database.generate_id(),
        )?;
        database_operation::<Entity<P::Jwk>, _>(self.config(), "create", async {
            active.insert(connection).await.map_err(map_db_err)
        })
        .await?
        .record()
    }
}
