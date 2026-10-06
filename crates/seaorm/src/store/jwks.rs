use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::{AuthResult, CreateJwk, Jwk, store::JwksStore};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect,
};
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
        let model = get::<P>(self.config(), self.connection(), id).await?;
        Ok(self
            .project_jwk_models(model.into_iter().collect())
            .await?
            .pop())
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        let models = list::<P>(self.config(), self.connection()).await?;
        self.project_jwk_models(models).await
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
        let model = get::<P>(self.store.config(), &self.tx, id).await?;
        Ok(self
            .store
            .project_jwk_models(model.into_iter().collect())
            .await?
            .pop())
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        let models = list::<P>(self.store.config(), &self.tx).await?;
        self.store.project_jwk_models(models).await
    }
    async fn create_jwk(&self, input: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with_connection(&self.tx, input).await
    }
}

async fn get<P: crate::SeaOrmPluginSchema>(
    config: &better_auth_core::AuthConfig,
    connection: &impl ConnectionTrait,
    id: &str,
) -> AuthResult<Option<P::Jwk>> {
    database_operation::<Entity<P::Jwk>, _>(config, "findOne", async {
        Entity::<P::Jwk>::find()
            .filter(P::Jwk::column("id")?.eq_id(id, config.advanced.database.generate_id())?)
            .one(connection)
            .await
            .map_err(map_db_err)
    })
    .await
}

async fn list<P: crate::SeaOrmPluginSchema>(
    config: &better_auth_core::AuthConfig,
    connection: &impl ConnectionTrait,
) -> AuthResult<Vec<P::Jwk>> {
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
    .await
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) fn validate_jwk_fields(&self) -> AuthResult<()> {
        super::plugin_models::validate_additional_field_columns::<P::Jwk>(
            EntityRole::Jwk,
            self.model_fields.fields(EntityRole::Jwk),
        )
    }

    async fn project_jwk_models(&self, models: Vec<P::Jwk>) -> AuthResult<Vec<Jwk>> {
        let fields = self.model_fields.fields(EntityRole::Jwk);
        let records = models
            .iter()
            .map(|model| model.record_fields(fields))
            .collect::<AuthResult<Vec<_>>>()?;
        let mut rows = models
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect::<AuthResult<Vec<_>>>()?;
        let output = fields
            .project_adapter_records(
                records,
                self.connection().get_database_backend() == DbBackend::Postgres,
                true,
            )
            .await?;
        for (row, output) in rows.iter_mut().zip(output) {
            row.additional_fields = output
                .into_iter()
                .map(|(name, value)| Ok(value.json()?.map(|value| (name, value))))
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect();
        }
        Ok(rows)
    }

    async fn create_jwk_with_connection(
        &self,
        connection: &impl ConnectionTrait,
        input: CreateJwk,
    ) -> AuthResult<Jwk> {
        let native = Map::from_iter([
            ("public_key".to_owned(), json!(input.public_key)),
            ("private_key".to_owned(), json!(input.private_key)),
            ("created_at".to_owned(), json!(Utc::now())),
            ("expires_at".to_owned(), json!(input.expires_at)),
            ("alg".to_owned(), json!(Some(input.alg))),
            ("crv".to_owned(), json!(input.crv)),
        ]);
        let config = self.model_fields.fields(EntityRole::Jwk);
        let backend = connection.get_database_backend();
        let mut active = super::plugin_models::additional_fields::<P::Jwk>(
            config,
            input.additional_fields,
            self.config().advanced.database.generate_id(),
            backend,
            true,
        )
        .await?;
        super::plugin_models::apply::<P::Jwk>(
            &mut active,
            self.create_fields("jwks", None, native)?,
            self.config().advanced.database.generate_id(),
        )?;
        let model = database_operation::<Entity<P::Jwk>, _>(self.config(), "create", async {
            active.insert(connection).await.map_err(map_db_err)
        })
        .await?;
        Ok(self.project_jwk_models(vec![model]).await?.remove(0))
    }
}
