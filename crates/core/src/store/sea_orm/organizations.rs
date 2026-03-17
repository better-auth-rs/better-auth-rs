use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::types_org::{CreateOrganization, Organization, UpdateOrganization};

use super::entities;
use super::entities::organization::{ActiveModel, Column, Entity};
use super::{AuthStore, map_db_err};

impl AuthStore {
    pub async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        ActiveModel {
            id: Set(org.id.unwrap_or_else(|| Uuid::new_v4().to_string())),
            name: Set(org.name),
            slug: Set(org.slug),
            logo: Set(org.logo),
            metadata: Set(org.metadata.unwrap_or(serde_json::json!({}))),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(Organization::from)
        .map_err(map_db_err)
    }

    pub async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(Organization::from))
            .map_err(map_db_err)
    }

    pub async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        Entity::find()
            .filter(Column::Slug.eq(slug))
            .one(self.connection())
            .await
            .map(|model| model.map(Organization::from))
            .map_err(map_db_err)
    }

    pub async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Organization not found"));
        };

        let mut active = model.into_active_model();
        if let Some(name) = update.name {
            active.name = Set(name);
        }
        if let Some(slug) = update.slug {
            active.slug = Set(slug);
        }
        if let Some(logo) = update.logo {
            active.logo = Set(Some(logo));
        }
        if let Some(metadata) = update.metadata {
            active.metadata = Set(metadata);
        }
        active.updated_at = Set(Utc::now());

        active
            .update(self.connection())
            .await
            .map(Organization::from)
            .map_err(map_db_err)
    }

    pub async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    pub async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let member_models = entities::member::Entity::find()
            .filter(entities::member::Column::UserId.eq(user_id))
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        if member_models.is_empty() {
            return Ok(Vec::new());
        }

        let organization_ids: Vec<String> = member_models
            .into_iter()
            .map(|member| member.organization_id)
            .collect();

        Entity::find()
            .filter(Column::Id.is_in(organization_ids))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Organization::from).collect())
            .map_err(map_db_err)
    }
}
