use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{AuthResult, store::InvitationStore};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder};
use serde_json::json;

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema> InvitationStore for SeaOrmStore<S, O> {
    async fn create_invitation(&self, input: CreateInvitation) -> AuthResult<Invitation> {
        let config = self.organization_fields()?.invitation;
        models::insert::<O::Invitation, _>(
            self.connection(),
            values([
                (
                    "id",
                    json!(input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                ),
                ("organization_id", json!(input.organization_id)),
                ("email", json!(input.email)),
                ("role", json!(input.role)),
                (
                    "status",
                    json!(
                        input
                            .status
                            .unwrap_or(InvitationStatus::Pending)
                            .to_string()
                    ),
                ),
                ("inviter_id", json!(input.inviter_id)),
                ("team_id", json!(input.team_id)),
                ("expires_at", json!(input.expires_at)),
                (
                    "created_at",
                    json!(input.created_at.unwrap_or_else(Utc::now)),
                ),
            ]),
            input.additional_fields,
            &config,
        )
        .await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        models::find::<O::Invitation, _>(self.connection(), id)
            .await?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq(organization_id))
            .filter(O::Invitation::column("email")?.eq(email.to_lowercase()))
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(O::Invitation::column("expires_at")?.gt(Utc::now()))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        models::update::<O::Invitation, _>(
            self.connection(),
            id,
            values([("status", json!(status.to_string()))]),
            Default::default(),
            &self.organization_fields()?.invitation,
        )
        .await
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        models::update::<O::Invitation, _>(
            self.connection(),
            id,
            values([("expires_at", json!(expires_at))]),
            Default::default(),
            &self.organization_fields()?.invitation,
        )
        .await
    }
    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        models::project::<O::Invitation>(
            Entity::<O::Invitation>::find()
                .filter(O::Invitation::column("organization_id")?.eq(organization_id))
                .order_by_asc(O::Invitation::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &self.organization_fields()?.invitation,
        )
    }
    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq(organization_id))
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(O::Invitation::column("expires_at")?.gt(Utc::now()))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        models::project::<O::Invitation>(
            Entity::<O::Invitation>::find()
                .filter(O::Invitation::column("email")?.eq(email.to_lowercase()))
                .filter(O::Invitation::column("status")?.eq("pending"))
                .filter(O::Invitation::column("expires_at")?.gt(Utc::now()))
                .order_by_desc(O::Invitation::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &self.organization_fields()?.invitation,
        )
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
                additional_fields: Default::default(),
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
                additional_fields: Default::default(),
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
