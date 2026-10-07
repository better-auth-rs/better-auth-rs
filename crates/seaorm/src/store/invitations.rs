use super::id_filter::IdColumn;
use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{AuthResult, store::InvitationStore};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect};

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> InvitationStore
    for SeaOrmStore<S, O, P>
{
    async fn create_invitation(&self, mut input: CreateInvitation) -> AuthResult<Invitation> {
        let config = self.organization_fields()?.invitation;
        let mut core = self.create_fields(
            "invitation",
            input.id,
            values([
                ("organization_id", (input.organization_id).into_field()),
                ("email", (input.email).into_field()),
                ("role", (input.role).into_field()),
                (
                    "status",
                    (input
                        .status
                        .unwrap_or(InvitationStatus::Pending)
                        .to_string())
                    .into_field(),
                ),
                ("inviter_id", (input.inviter_id).into_field()),
                ("team_id", (input.team_id).into_field()),
                ("expires_at", (input.expires_at).into_field()),
                (
                    "created_at",
                    input
                        .created_at
                        .unwrap_or_else(|| Utc::now().into())
                        .into_field(),
                ),
            ]),
        )?;
        for (public, stored) in [
            ("status", "status"),
            ("createdAt", "created_at"),
            ("expiresAt", "expires_at"),
            ("inviterId", "inviter_id"),
        ] {
            if let Some(value) = input.additional_fields.remove(public) {
                let _ = core.insert(stored.into(), value);
            }
        }
        models::insert::<O::Invitation, _>(
            self.connection(),
            core,
            input.additional_fields,
            &config,
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let row = models::find::<O::Invitation, _>(
            self.connection(),
            id,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        match row {
            Some(row) => row
                .record(
                    &config,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let row = Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(O::Invitation::column("email")?.eq(email.to_lowercase()))
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(O::Invitation::column("expires_at")?.gt(Utc::now()))
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &config,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        models::update::<O::Invitation, _>(
            self.connection(),
            id,
            values([("status", (status.to_string()).into_field())]),
            Default::default(),
            &self.organization_fields()?.invitation,
            self.config().advanced.database.generate_id(),
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
            values([("expires_at", FieldValue::Date((expires_at).into()))]),
            Default::default(),
            &self.organization_fields()?.invitation,
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        let rows = Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::Invitation>(
            rows,
            &self.organization_fields()?.invitation,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(O::Invitation::column("expires_at")?.gt(Utc::now()))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }
    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<better_auth_core::store::InvitationOrganization>> {
        if self.config().advanced.database.joins == Some(true) {
            return self.joined_user_invitations(email).await;
        }
        let fields = self.organization_fields()?;
        let rows = Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("email")?.eq(email.to_lowercase()))
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project_then::<O::Invitation, _, _>(
            &rows,
            &fields.invitation,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            |index, invitation| {
                let rows = &rows;
                let fields = &fields;
                async move {
                    let row = rows.get(index).ok_or_else(|| {
                        better_auth_core::AuthError::internal(
                            "Invitation projection lost its stored join index",
                        )
                    })?;
                    let organization = Entity::<O::Organization>::find()
                        .filter(
                            O::Organization::column("id")?
                                .eq(models::join_value(row, "organization_id")?),
                        )
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)?;
                    let organization = match organization {
                        Some(row) => Some(
                            row.record(
                                &fields.organization,
                                self.connection().get_database_backend()
                                    == sea_orm::DbBackend::Postgres,
                            )
                            .await?,
                        ),
                        None => None,
                    };
                    Ok(better_auth_core::store::InvitationOrganization {
                        invitation,
                        organization,
                    })
                }
            },
        )
        .await
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
                name: "Org".to_string().into(),
                slug: "org".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
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
                (Utc::now() + Duration::hours(1)).into(),
            ))
            .await
            .expect("pending invitation should be created");
        let canceled = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "second@example.com",
                "member",
                "inviter-1",
                (Utc::now() + Duration::hours(1)).into(),
            ))
            .await
            .expect("cancelable invitation should be created");
        let _ = store
            .update_invitation_status(canceled.id.typed().unwrap(), InvitationStatus::Canceled)
            .await
            .expect("invitation should be canceled");
        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                (Utc::now() - Duration::hours(1)).into(),
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
                name: "Org".to_string().into(),
                slug: "org-second".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
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
                (Utc::now() - Duration::hours(1)).into(),
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
