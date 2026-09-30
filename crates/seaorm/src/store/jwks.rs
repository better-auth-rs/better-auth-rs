use async_trait::async_trait;
use better_auth_core::{AuthResult, CreateJwk, Jwk, store::JwksStore};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

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
impl<S: better_auth_core::AuthSchema, O: crate::SeaOrmOrganizationSchema> JwksStore
    for SeaOrmStore<S, O>
{
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        jwk::Entity::find()
            .all(self.connection())
            .await
            .map(|keys| keys.into_iter().map(Jwk::from).collect())
            .map_err(map_db_err)
    }

    async fn create_jwk(&self, input: CreateJwk) -> AuthResult<Jwk> {
        jwk::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            public_key: Set(input.public_key),
            private_key: Set(input.private_key),
            created_at: Set(Utc::now()),
            expires_at: Set(input.expires_at),
            alg: Set(Some(input.alg)),
            crv: Set(input.crv),
        }
        .insert(self.connection())
        .await
        .map(Jwk::from)
        .map_err(map_db_err)
    }
}
