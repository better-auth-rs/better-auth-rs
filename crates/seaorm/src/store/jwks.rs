use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::{AuthResult, CreateJwk, Jwk, store::JwksStore};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait};
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
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Entity::<P::Jwk>::find()
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect()
    }

    async fn create_jwk(&self, input: CreateJwk) -> AuthResult<Jwk> {
        P::Jwk::active(Map::from_iter([
            ("id".to_owned(), json!(uuid::Uuid::new_v4().to_string())),
            ("public_key".to_owned(), json!(input.public_key)),
            ("private_key".to_owned(), json!(input.private_key)),
            ("created_at".to_owned(), json!(Utc::now())),
            ("expires_at".to_owned(), json!(input.expires_at)),
            ("alg".to_owned(), json!(Some(input.alg))),
            ("crv".to_owned(), json!(input.crv)),
        ]))?
        .insert(self.connection())
        .await
        .map_err(map_db_err)?
        .record()
    }
}
