use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::types_org::{CreateMember, Member};

use super::entities::member::{ActiveModel, Column, Entity};
use super::{AuthStore, map_db_err};

impl AuthStore {
    pub async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(member.organization_id),
            user_id: Set(member.user_id),
            role: Set(member.role),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(Member::from)
        .map_err(map_db_err)
    }

    pub async fn get_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|model| model.map(Member::from))
            .map_err(map_db_err)
    }

    pub async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(Member::from))
            .map_err(map_db_err)
    }

    pub async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        let Some(model) = Entity::find_by_id(member_id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Member not found"));
        };

        let mut active = model.into_active_model();
        active.role = Set(role.to_owned());
        active
            .update(self.connection())
            .await
            .map(Member::from)
            .map_err(map_db_err)
    }

    pub async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        Entity::delete_by_id(member_id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    pub async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Member::from).collect())
            .map_err(map_db_err)
    }

    pub async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .count(self.connection())
            .await
            .map(|count| count as usize)
            .map_err(map_db_err)
    }

    pub async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Role.eq("owner"))
            .count(self.connection())
            .await
            .map(|count| count as usize)
            .map_err(map_db_err)
    }
}
