use super::{
    SeaOrmStore,
    entities::organization_role::{ActiveModel, Column, Entity},
    map_db_err,
};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, CreateOrganizationRole, OrganizationRole, UpdateOrganizationRole,
    store::OrganizationRoleStore,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

#[async_trait]
impl<S: better_auth_core::AuthSchema> OrganizationRoleStore for SeaOrmStore<S> {
    async fn create_organization_role(
        &self,
        input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            organization_id: Set(input.organization_id),
            role: Set(input.role),
            permission: Set(input.permission),
            created_at: Set(Utc::now()),
            updated_at: Set(None),
        }
        .insert(self.connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        Entity::find_by_id(id)
            .one(self.connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut active = ActiveModel {
            id: Set(id.to_owned()),
            updated_at: Set(Some(Utc::now())),
            ..Default::default()
        };
        if let Some(role) = update.role {
            active.role = Set(role);
        }
        if let Some(permission) = update.permission {
            active.permission = Set(permission);
        }
        active
            .update(self.connection())
            .await
            .map(Into::into)
            .map_err(map_db_err)
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id)
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
