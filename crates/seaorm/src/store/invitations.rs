use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult,
    store::{InvitationStore, schema::EntityRole},
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, sea_query::ExprTrait,
};

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
            super::create_readback::ReadbackScope::Direct(self.connection()),
            core,
            input.additional_fields,
            &config,
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.get_invitation_by_id_value(&id.into()).await
    }

    async fn get_invitation_by_id_value(&self, id: &FieldValue) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let row = models::find_value::<O::Invitation, _>(
            self.connection(),
            id,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
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
        self.get_pending_invitation_value(&organization_id.into(), email)
            .await
    }

    async fn get_pending_invitation_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let now = super::record_bindings::Binding::Date(Utc::now().into())
            .bind(self.connection().get_database_backend())?;
        let expires_at = O::Invitation::column("expires_at")?;
        let row = Entity::<O::Invitation>::find()
            .filter(self.organization_field_equals::<O::Invitation>(
                EntityRole::Invitation,
                "organizationId",
                organization_id,
            )?)
            .filter(super::value_filter::equals(
                O::Invitation::column("email")?,
                &email.to_lowercase().into(),
                self.connection().get_database_backend(),
            )?)
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(expires_at.into_expr().gt(expires_at.save_as(now)))
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
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
        self.update_invitation_status_value(&id.into(), status)
            .await
    }

    async fn update_invitation_status_value(
        &self,
        id: &FieldValue,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        models::update_value::<O::Invitation, _>(
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
        self.update_invitation_expiry_value(&id.into(), expires_at)
            .await
    }

    async fn update_invitation_expiry_value(
        &self,
        id: &FieldValue,
        expires_at: chrono::DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        models::update_value::<O::Invitation, _>(
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
        self.list_organization_invitations_value(&organization_id.into())
            .await
    }

    async fn list_organization_invitations_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Invitation>> {
        let rows = Entity::<O::Invitation>::find()
            .filter(self.organization_field_equals::<O::Invitation>(
                EntityRole::Invitation,
                "organizationId",
                organization_id,
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
            self.connection().get_database_backend(),
        )
        .await
    }
    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        self.count_pending_organization_invitations_value(&organization_id.into())
            .await
    }

    async fn count_pending_organization_invitations_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<i64> {
        let now = super::record_bindings::Binding::Date(Utc::now().into())
            .bind(self.connection().get_database_backend())?;
        let expires_at = O::Invitation::column("expires_at")?;
        Entity::<O::Invitation>::find()
            .filter(self.organization_field_equals::<O::Invitation>(
                EntityRole::Invitation,
                "organizationId",
                organization_id,
            )?)
            .filter(O::Invitation::column("status")?.eq("pending"))
            .filter(expires_at.into_expr().gt(expires_at.save_as(now)))
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
            .filter(super::value_filter::equals(
                O::Invitation::column("email")?,
                &email.to_lowercase().into(),
                self.connection().get_database_backend(),
            )?)
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
            self.connection().get_database_backend(),
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
                        .filter(super::value_filter::equals_native(
                            O::Organization::column("id")?,
                            models::join_value(row, "organization_id")?,
                            self.connection().get_database_backend(),
                        )?)
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)?;
                    let organization = match organization {
                        Some(row) => Some(
                            row.record(
                                &fields.organization,
                                self.connection().get_database_backend(),
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
    use better_auth_core::store::{
        InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore,
    };
    use better_auth_core::{CreateMember, CreateTeam, FieldValue, SchemaValue, UpdateTeam};
    use chrono::{Duration, Utc};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;
    use crate::types::CreateUser;
    use crate::types_org::{CreateInvitation, CreateOrganization, InvitationStatus};

    use super::SeaOrmStore;

    async fn test_store() -> SeaOrmStore<BundledSchema> {
        test_store_with_joins(false).await
    }

    async fn test_store_with_joins(joins: bool) -> SeaOrmStore<BundledSchema> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        config.advanced.database.joins = Some(joins);
        SeaOrmStore::new(Arc::new(config), database)
    }

    async fn native_fixture(joins: bool) -> SeaOrmStore<BundledSchema> {
        let store = test_store_with_joins(joins).await;
        for id in ["1", "2"] {
            let _ = store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    name: Some(format!("User {id}")).into(),
                    email: Some(format!("{id}@native-team.test")),
                    ..Default::default()
                })
                .await
                .expect("fixture user should be created");
        }
        let mut organization = CreateOrganization::new("Native", "native");
        organization.id = Some("1".into());
        let _ = store
            .create_organization(organization)
            .await
            .expect("fixture organization should be created");
        for id in ["10", "11"] {
            let _ = store
                .create_team(CreateTeam {
                    id: Some(id.into()),
                    organization_id: "1".into(),
                    name: format!("Team {id}").into(),
                    ..Default::default()
                })
                .await
                .expect("fixture team should be created");
        }
        store
    }

    #[tokio::test]
    async fn native_team_mutations_preserve_capacity_idempotence_and_joined_lists() {
        for joins in [false, true] {
            let store = native_fixture(joins).await;
            let team_id = FieldValue::Number(10.0);
            let first_user = FieldValue::Number(1.0);
            let second_user = FieldValue::Number(2.0);
            let member = store
                .add_team_member_value(&team_id, &first_user, Some(1))
                .await
                .expect("native membership should be created")
                .expect("capacity should be available");
            let repeated = store
                .add_team_member(&SchemaValue::from_field(team_id.clone()), "1", Some(0))
                .await
                .expect("existing membership should bypass the capacity limit")
                .expect("existing membership should be returned");
            assert_eq!(member.id, repeated.id);
            assert_eq!(
                store
                    .count_team_members_value(&team_id)
                    .await
                    .expect("native count should succeed"),
                1
            );
            assert!(
                store
                    .add_team_member_value(&team_id, &second_user, Some(1))
                    .await
                    .expect("full team should reject membership without an error")
                    .is_none()
            );
            store
                .remove_team_member_value(&team_id, &first_user)
                .await
                .expect("native removal should release capacity");
            assert_eq!(
                store
                    .count_team_members_value(&team_id)
                    .await
                    .expect("native count should succeed"),
                0
            );
            let _ = store
                .add_team_member_value(&team_id, &second_user, Some(1))
                .await
                .expect("released capacity should be reusable")
                .expect("replacement membership should exist");
            let listed = store
                .list_user_teams_value(&second_user)
                .await
                .expect("native owner list should succeed");
            assert_eq!(listed.len(), 1);
            assert_eq!(
                listed
                    .first()
                    .expect("listed team should exist")
                    .id
                    .field_value(),
                FieldValue::from("10")
            );
            let updated = store
                .update_team_value(
                    &team_id,
                    UpdateTeam {
                        name: Some("Renamed".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("native primary selector should update the team");
            assert_eq!(
                updated
                    .name
                    .typed()
                    .expect("ordinary name should remain a string"),
                "Renamed"
            );
            let organization_member = store
                .create_member(CreateMember::new("1", "2", "member"))
                .await
                .expect("organization membership should be created");
            store
                .delete_member_value(&organization_member.id.field_value())
                .await
                .expect("default primary fields should support membership cleanup");
            assert!(
                store
                    .get_member("1", "2")
                    .await
                    .expect("deleted organization member lookup should succeed")
                    .is_none()
            );
            assert_eq!(
                store
                    .count_team_members_value(&team_id)
                    .await
                    .expect("organization member cleanup should remove team membership"),
                0
            );
            let _ = store
                .add_team_member_value(&team_id, &first_user, Some(1))
                .await
                .expect("organization member cleanup should release team capacity")
                .expect("released capacity should be reusable");
            store
                .delete_team_value(&team_id)
                .await
                .expect("native primary selector should delete the team");
            assert!(
                store
                    .get_team_value(&team_id)
                    .await
                    .expect("deleted team lookup should succeed")
                    .is_none()
            );
            assert_eq!(
                store
                    .count_team_members_value(&team_id)
                    .await
                    .expect("deleted team memberships should be countable"),
                0
            );
            assert!(
                store
                    .list_user_teams_value(&first_user)
                    .await
                    .expect("deleted memberships should not join")
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn native_invitation_acceptance_rolls_back_partial_team_capacity_and_can_retry() {
        let store = native_fixture(false).await;
        let invitation_id = FieldValue::Number(20.0);
        let user_id = FieldValue::Number(2.0);
        let mut invitation = CreateInvitation::new(
            "1",
            "2@native-team.test",
            "member",
            "1",
            (Utc::now() + Duration::hours(1)).into(),
        );
        invitation.id = Some("20".into());
        invitation.team_id = Some("10,11".into());
        let _ = store
            .create_invitation(invitation)
            .await
            .expect("fixture invitation should be created");
        let expires_at = Utc::now() + Duration::hours(2);
        let renewed = store
            .update_invitation_expiry_value(&invitation_id, expires_at)
            .await
            .expect("native invitation selector should renew expiry");
        assert_eq!(
            renewed
                .expires_at
                .typed()
                .expect("expiry should remain a date")
                .milliseconds(),
            expires_at.timestamp_millis() as f64
        );
        let canceled = store
            .update_invitation_status_value(&invitation_id, InvitationStatus::Canceled)
            .await
            .expect("native invitation selector should cancel");
        assert_eq!(
            canceled
                .status
                .typed()
                .expect("status should retain its ordinary type"),
            &InvitationStatus::Canceled
        );
        let _ = store
            .update_invitation_status_value(&invitation_id, InvitationStatus::Pending)
            .await
            .expect("fixture invitation should return to pending");
        let _ = store
            .add_team_member_value(&FieldValue::Number(11.0), &FieldValue::Number(1.0), Some(1))
            .await
            .expect("second team should be filled")
            .expect("initial team capacity should be available");
        assert!(
            store
                .accept_invitation_with_teams_values(
                    &invitation_id,
                    &user_id,
                    None,
                    true,
                    Some(1).into()
                )
                .await
                .is_err()
        );
        assert_eq!(
            store
                .count_team_members("10")
                .await
                .expect("first team count should succeed"),
            0
        );
        assert_eq!(
            store
                .count_team_members("11")
                .await
                .expect("second team count should succeed"),
            1
        );
        assert!(
            store
                .get_member("1", "2")
                .await
                .expect("organization membership lookup should succeed")
                .is_none()
        );
        let pending = store
            .get_invitation_by_id_value(&invitation_id)
            .await
            .expect("claimed invitation should remain readable")
            .expect("claimed invitation should remain stored");
        assert_eq!(
            pending
                .status
                .typed()
                .expect("status should retain its ordinary type"),
            &InvitationStatus::Pending
        );
        store
            .remove_team_member_value(&FieldValue::Number(11.0), &FieldValue::Number(1.0))
            .await
            .expect("second team capacity should be released");
        let (member, invitation, cookie_session) = store
            .accept_invitation_with_teams_values(
                &invitation_id,
                &user_id,
                None,
                true,
                Some(1).into(),
            )
            .await
            .expect("same native invitation should succeed on retry");
        assert_eq!(member.user_id.field_value(), FieldValue::from("2"));
        assert_eq!(
            invitation
                .status
                .typed()
                .expect("status should retain its ordinary type"),
            &InvitationStatus::Accepted
        );
        assert!(cookie_session.is_none());
        for team_id in ["10", "11"] {
            assert_eq!(
                store
                    .count_team_members(team_id)
                    .await
                    .expect("accepted team count should succeed"),
                1
            );
            assert!(
                store
                    .get_team_member(team_id, "2")
                    .await
                    .expect("accepted team member lookup should succeed")
                    .is_some()
            );
        }
        assert!(
            store
                .accept_invitation_with_teams_values(
                    &invitation_id,
                    &user_id,
                    None,
                    true,
                    Some(1).into()
                )
                .await
                .is_err()
        );
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
