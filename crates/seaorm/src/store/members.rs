use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use better_auth_core::store::MemberStore;

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::entities::member::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S> MemberStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(member.organization_id),
            user_id: Set(member.user_id),
            role: Set(member.role),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(|model| Member::from(&model))
        .map_err(map_db_err)
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Member::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Member::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
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
            .map(|model| Member::from(&model))
            .map_err(map_db_err)
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        Entity::delete_by_id(member_id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Member::from).collect())
            .map_err(map_db_err)
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Role.eq("owner"))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }
}
