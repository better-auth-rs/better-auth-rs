use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, CreateOrganizationRole, OrganizationRole, UpdateOrganizationRole,
    store::OrganizationRoleStore,
};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::json;

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema> OrganizationRoleStore for SeaOrmStore<S, O> {
    async fn create_organization_role(
        &self,
        input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        models::insert::<O::OrganizationRole, _>(
            self.connection(),
            values([
                ("id", json!(uuid::Uuid::new_v4().to_string())),
                ("organization_id", json!(input.organization_id)),
                ("role", json!(input.role)),
                ("permission", input.permission),
                ("created_at", json!(Utc::now())),
                ("updated_at", json!(null)),
            ]),
            input.additional_fields,
            &self.organization_fields()?.organization_role,
        )
        .await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        let config = self.organization_fields()?.organization_role;
        models::find::<O::OrganizationRole, _>(self.connection(), id)
            .await?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        models::project::<O::OrganizationRole>(
            Entity::<O::OrganizationRole>::find()
                .filter(O::OrganizationRole::column("organization_id")?.eq(organization_id))
                .order_by_asc(O::OrganizationRole::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &self.organization_fields()?.organization_role,
        )
    }
    async fn update_organization_role(
        &self,
        id: &str,
        input: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut core = values([("updated_at", json!(Utc::now()))]);
        if let Some(role) = input.role {
            let _ = core.insert("role".into(), json!(role));
        }
        if let Some(permission) = input.permission {
            let _ = core.insert("permission".into(), permission);
        }
        models::update::<O::OrganizationRole, _>(
            self.connection(),
            id,
            core,
            input.additional_fields,
            &self.organization_fields()?.organization_role,
        )
        .await
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::OrganizationRole>::delete_many()
            .filter(O::OrganizationRole::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}
