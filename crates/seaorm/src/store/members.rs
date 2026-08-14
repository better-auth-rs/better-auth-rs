use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Select, Set,
};
use uuid::Uuid;

use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::entities::member::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

fn member_column(field: &str) -> Option<Column> {
    match field {
        "id" => Some(Column::Id),
        "organizationId" => Some(Column::OrganizationId),
        "userId" => Some(Column::UserId),
        "role" => Some(Column::Role),
        "createdAt" => Some(Column::CreatedAt),
        _ => None,
    }
}

fn apply_member_filter(
    mut query: Select<Entity>,
    params: &ListOrganizationMembersParams,
) -> AuthResult<Select<Entity>> {
    let Some(field) = params.filter_field.as_deref() else {
        return Ok(query);
    };
    let Some(value) = params.filter_value.as_deref() else {
        return Ok(query);
    };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");

    match member_column(field) {
        Some(Column::CreatedAt) => {
            let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) else {
                return Ok(query.filter(Column::Id.eq("__better_auth_never_matches__")));
            };
            let parsed = parsed.with_timezone(&Utc);
            query = match operator {
                "eq" => query.filter(Column::CreatedAt.eq(parsed)),
                "ne" => query.filter(Column::CreatedAt.ne(parsed)),
                "gt" => query.filter(Column::CreatedAt.gt(parsed)),
                "gte" => query.filter(Column::CreatedAt.gte(parsed)),
                "lt" => query.filter(Column::CreatedAt.lt(parsed)),
                "lte" => query.filter(Column::CreatedAt.lte(parsed)),
                _ => query,
            };
        }
        Some(column) => {
            query = match operator {
                "eq" => query.filter(column.eq(value)),
                "ne" => query.filter(column.ne(value)),
                "contains" => query.filter(column.contains(value)),
                "gt" => query.filter(column.gt(value)),
                "gte" => query.filter(column.gte(value)),
                "lt" => query.filter(column.lt(value)),
                "lte" => query.filter(column.lte(value)),
                _ => query,
            };
        }
        None => {}
    }

    Ok(query)
}

fn apply_member_sort(
    query: Select<Entity>,
    params: &ListOrganizationMembersParams,
) -> Select<Entity> {
    let Some(sort_by) = params.sort_by.as_deref() else {
        return query.order_by_asc(Column::CreatedAt);
    };
    let descending = matches!(params.sort_direction.as_deref(), Some("desc"));

    match member_column(sort_by) {
        Some(column) if descending => query.order_by_desc(column),
        Some(column) => query.order_by_asc(column),
        None => query.order_by_asc(Column::CreatedAt),
    }
}

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

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let base_query = Entity::find().filter(Column::OrganizationId.eq(&params.organization_id));
        let filtered_query = apply_member_filter(base_query, params)?;
        let total = filtered_query
            .clone()
            .count(self.connection())
            .await
            .map_err(map_db_err)? as usize;

        let mut query = apply_member_sort(filtered_query, params);
        if let Some(offset) = params.offset {
            query = query.offset(offset as u64);
        }
        if let Some(limit) = params.limit {
            query = query.limit(limit as u64);
        }

        query
            .all(self.connection())
            .await
            .map(|models| (models.iter().map(Member::from).collect(), total))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::store::{
        ListOrganizationMembersParams, MemberStore, OrganizationStore, UserStore,
    };
    use better_auth_core::types::{CreateMember, CreateOrganization, CreateUser};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;

    use super::SeaOrmStore;

    async fn test_store() -> SeaOrmStore<BundledSchema> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        SeaOrmStore::new(
            Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
            database,
        )
    }

    #[tokio::test]
    async fn query_organization_members_applies_filter_sort_and_pagination() {
        let store = test_store().await;
        let org_id = "org-1".to_string();
        let _organization = store
            .create_organization(CreateOrganization {
                id: Some(org_id.clone()),
                name: "Org".to_string(),
                slug: "org".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        let _owner = store
            .create_user(CreateUser {
                id: Some("user-owner".to_string()),
                email: Some("owner@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("owner should be created");
        let _member = store
            .create_user(CreateUser {
                id: Some("user-member".to_string()),
                email: Some("member@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("member should be created");
        let _admin = store
            .create_user(CreateUser {
                id: Some("user-admin".to_string()),
                email: Some("admin@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("admin should be created");

        let _ = store
            .create_member(CreateMember::new(&org_id, "user-owner", "owner"))
            .await
            .expect("owner should be created");
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-member", "member"))
            .await
            .expect("member should be created");
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-admin", "admin"))
            .await
            .expect("admin should be created");

        let params = ListOrganizationMembersParams {
            organization_id: org_id,
            limit: Some(1),
            offset: Some(1),
            sort_by: Some("role".to_string()),
            sort_direction: Some("asc".to_string()),
            filter_field: Some("role".to_string()),
            filter_value: Some("owner".to_string()),
            filter_operator: Some("ne".to_string()),
        };

        let (members, total) = store
            .query_organization_members(&params)
            .await
            .expect("member query should succeed");

        assert_eq!(total, 2);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, "member");
    }
}
