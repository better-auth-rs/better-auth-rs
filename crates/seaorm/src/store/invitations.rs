use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use better_auth_core::store::InvitationStore;

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};

use super::entities::invitation::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S> InvitationStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(invitation.organization_id),
            email: Set(invitation.email),
            role: Set(invitation.role),
            status: Set(InvitationStatus::Pending.to_string()),
            inviter_id: Set(invitation.inviter_id),
            expires_at: Set(invitation.expires_at),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(|model| Invitation::from(&model))
        .map_err(map_db_err)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Invitation::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Invitation::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Invitation not found"));
        };

        let mut active = model.into_active_model();
        active.status = Set(status.to_string());
        active
            .update(self.connection())
            .await
            .map(|model| Invitation::from(&model))
            .map_err(map_db_err)
    }

    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }

    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::store::{InvitationStore, OrganizationStore, UserStore};
    use chrono::{Duration, Utc};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;
    use crate::types::CreateUser;
    use crate::types_org::{CreateInvitation, CreateOrganization, InvitationStatus};

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
    async fn pending_invitation_count_excludes_expired_and_non_pending_rows() {
        let store = test_store().await;
        let org_id = "org-1";
        let _organization = store
            .create_organization(CreateOrganization {
                id: Some(org_id.to_string()),
                name: "Org".to_string(),
                slug: "org".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                id: Some("inviter-1".to_string()),
                email: Some("inviter@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("inviter should be created");

        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "first@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await
            .expect("pending invitation should be created");
        let canceled = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "second@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await
            .expect("cancelable invitation should be created");
        let _ = store
            .update_invitation_status(&canceled.id, InvitationStatus::Canceled)
            .await
            .expect("invitation should be canceled");
        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await
            .expect("expired invitation should be created");

        let count = store
            .count_pending_organization_invitations(org_id)
            .await
            .expect("pending invitation count should succeed");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn get_pending_invitation_ignores_expired_rows() {
        let store = test_store().await;
        let org_id = "org-1";
        let _organization = store
            .create_organization(CreateOrganization {
                id: Some(org_id.to_string()),
                name: "Org".to_string(),
                slug: "org-second".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                id: Some("inviter-1".to_string()),
                email: Some("inviter@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("inviter should be created");

        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await
            .expect("expired invitation should be created");

        let invitation = store
            .get_pending_invitation(org_id, "expired@example.com")
            .await
            .expect("lookup should succeed");

        assert!(invitation.is_none());
    }
}
