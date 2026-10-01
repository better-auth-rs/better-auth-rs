#![allow(
    unused_results,
    reason = "test setup intentionally discards created records"
)]
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::{
    AuthConfig, CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole,
    CreateTeam, CreateUser, UpdateOrganizationRole,
    store::{
        InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, TeamStore,
        UserStore,
    },
};
use std::sync::Arc;

async fn store() -> SeaOrmStore<BundledSchema> {
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    let store = SeaOrmStore::new(
        Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
        db,
    );
    for id in ["org-a", "org-b"] {
        store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(id.into()),
                name: id.into(),
                slug: id.into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .unwrap();
    }
    for id in ["user-a", "user-b"] {
        store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some(id.into()),
                email: Some(format!("{id}@example.com")),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
}

#[tokio::test]
async fn json_policies_keep_native_model_values_and_transform_each_read_once() {
    use better_auth_core::{
        organization_fields::OrganizationFields,
        user_fields::{UserFieldConfig, UserFieldType},
    };
    use sea_orm::EntityTrait;
    use serde_json::{Value, json};
    let store = store().await;
    let mut fields = OrganizationFields::default();
    fields.organization_role.additional_fields.insert(
        "permission".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            input_transform: Some(Arc::new(|value| {
                value
                    .map(|value| {
                        let value: Value = match value {
                            Value::String(value) => serde_json::from_str(&value)?,
                            value => value,
                        };
                        serde_json::from_str(&value.to_string().replace("source", "stored"))
                            .map_err(Into::into)
                    })
                    .transpose()
            })),
            output_transform: Some(Arc::new(|value| {
                Ok(value.map(|value| {
                    json!(
                        value
                            .as_str()
                            .expect("SQLite JSON callbacks receive text")
                            .replace("stored", "visible")
                    )
                }))
            })),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields).unwrap();
    let created = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: "org-a".into(),
            role: "json-role".into(),
            permission: json!({"source":["read"]}),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(
        created.permission.json().unwrap(),
        Some(json!({"visible":["read"]}))
    );
    let row = super::entities::organization_role::Entity::find_by_id(created.id.typed().unwrap())
        .one(store.connection())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.permission, json!({"stored":["read"]}));
    assert_eq!(
        store
            .get_organization_role(created.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .permission,
        created.permission
    );
    let updated = store
        .update_organization_role(
            created.id.typed().unwrap(),
            UpdateOrganizationRole {
                permission: Some(json!({"source":["write"]})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        updated.permission.json().unwrap(),
        Some(json!({"visible":["write"]}))
    );
    let row = super::entities::organization_role::Entity::find_by_id(created.id.typed().unwrap())
        .one(store.connection())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.permission, json!({"stored":["write"]}));
    assert_eq!(
        store
            .get_organization_role(created.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .permission,
        updated.permission
    );
}

#[tokio::test]
async fn team_capacity_deduplication_and_scoped_cleanup() {
    let store = store().await;
    let a = store
        .create_team(CreateTeam {
            name: "a".into(),
            organization_id: "org-a".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let b = store
        .create_team(CreateTeam {
            name: "b".into(),
            organization_id: "org-b".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.add_team_member(&a.id, "user-a", Some(1)),
        store.add_team_member(&a.id, "user-b", Some(1))
    );
    assert_eq!(
        usize::from(first.as_ref().unwrap().is_some())
            + usize::from(second.as_ref().unwrap().is_some()),
        1
    );
    let winner = first.unwrap().or(second.unwrap()).unwrap();
    let (duplicate_a, duplicate_b) = tokio::join!(
        store.add_team_member(&a.id, &winner.user_id, Some(1)),
        store.add_team_member(&a.id, &winner.user_id, Some(1))
    );
    assert_eq!(duplicate_a.unwrap().unwrap().id, winner.id);
    assert_eq!(duplicate_b.unwrap().unwrap().id, winner.id);
    store
        .add_team_member(&b.id, &winner.user_id, None)
        .await
        .unwrap();
    let member = store
        .create_member(CreateMember::new("org-a", &winner.user_id, "member"))
        .await
        .unwrap();
    store
        .delete_member(member.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        store
            .list_team_members(a.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .list_team_members(b.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
    let mut input = CreateInvitation::new(
        "org-a",
        "invite@example.com",
        "member",
        "user-a",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    input.team_id = Some(a.id.typed().unwrap().clone());
    let invitation = store.create_invitation(input).await.unwrap();
    store.delete_team(a.id.typed().unwrap()).await.unwrap();
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .team_id,
        None
    );
    assert!(
        store
            .get_team(b.id.typed().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn dynamic_roles_persist_json_and_organization_deletion_cascades() {
    let store = store().await;
    let role = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: Default::default(),
            organization_id: "org-a".into(),
            role: "editor".into(),
            permission: serde_json::json!({"team": ["create"]}),
        })
        .await
        .unwrap();
    store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: Default::default(),
            organization_id: "org-b".into(),
            role: "editor".into(),
            permission: serde_json::json!({}),
        })
        .await
        .unwrap();
    let updated = store
        .update_organization_role(
            role.id.typed().unwrap(),
            UpdateOrganizationRole {
                additional_fields: Default::default(),
                role: Some("writer".into()),
                permission: Some(serde_json::json!({"team": ["update"]})),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.permission, serde_json::json!({"team": ["update"]}));
    assert!(updated.updated_at.typed().unwrap().is_some());
    let team = store
        .create_team(CreateTeam {
            name: "a".into(),
            organization_id: "org-a".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .add_team_member(&team.id, "user-a", None)
        .await
        .unwrap();
    store.delete_organization("org-a").await.unwrap();
    assert!(
        store
            .get_organization_role(role.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_team(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.list_organization_roles("org-b").await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn accepting_multiple_teams_rolls_back_every_write_when_one_team_is_full() {
    use better_auth_core::{AuthSession, CreateSession, InvitationStatus, store::SessionStore};
    let store = store().await;
    let first = store
        .create_team(CreateTeam {
            name: "first".into(),
            organization_id: "org-a".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let full = store
        .create_team(CreateTeam {
            name: "full".into(),
            organization_id: "org-a".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .add_team_member(&full.id, "user-a", Some(1))
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: "user-b".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        "org-a",
        "user-b@example.com",
        "member",
        "user-a",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    input.team_id = Some(format!(
        "{},{}",
        first.id.typed().unwrap(),
        full.id.typed().unwrap()
    ));
    let invitation = store.create_invitation(input).await.unwrap();
    assert!(
        store
            .accept_invitation_with_teams(
                invitation.id.typed().unwrap(),
                "user-b",
                Some(session.token()),
                true,
                Some(1).into()
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .status,
        InvitationStatus::Pending
    );
    assert!(
        store
            .list_team_members(first.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(store.get_member("org-a", "user-b").await.unwrap().is_none());
    assert_eq!(
        store
            .get_session(session.token())
            .await
            .unwrap()
            .unwrap()
            .active_organization_id(),
        None
    );
    store
        .remove_team_member(full.id.typed().unwrap(), "user-a")
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        store.accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "user-b",
            Some(session.token()),
            true,
            Some(1).into()
        ),
        store.accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "user-b",
            Some(session.token()),
            true,
            Some(1).into()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        store
            .list_team_members(first.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .list_team_members(full.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .get_session(session.token())
            .await
            .unwrap()
            .unwrap()
            .active_organization_id(),
        Some("org-a")
    );
}

#[tokio::test]
async fn single_team_invitation_captures_cookie_before_switching_organization() {
    use better_auth_core::{AuthSession, CreateSession, store::SessionStore};
    let store = store().await;
    let team = store
        .create_team(CreateTeam {
            name: "invited".into(),
            organization_id: "org-a".into(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: "user-b".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: Some("org-b".into()),
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        "org-a",
        "user-b@example.com",
        "member",
        "user-a",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    input.team_id = Some(team.id.typed().unwrap().clone());
    let invitation = store.create_invitation(input).await.unwrap();
    let (member, accepted, snapshot) = store
        .accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "user-b",
            Some(session.token()),
            true,
            None.into(),
        )
        .await
        .unwrap();
    assert_eq!(member.organization_id, "org-a");
    assert_eq!(
        accepted.status,
        better_auth_core::InvitationStatus::Accepted
    );
    let snapshot = snapshot.unwrap();
    assert_eq!(snapshot.active_organization_id(), Some("org-b"));
    assert_eq!(snapshot.active_team_id(), team.id.as_str());
    let persisted = store.get_session(session.token()).await.unwrap().unwrap();
    assert_eq!(persisted.active_organization_id(), Some("org-a"));
    assert_eq!(persisted.active_team_id(), team.id.as_str());
}

#[tokio::test]
async fn dynamic_team_limits_run_in_order_and_rollback_callback_failures() {
    use better_auth_core::store::{SessionStore, TeamMemberLimitResolver, TeamMemberLimits};
    use better_auth_core::{AuthError, AuthResult, AuthSession, CreateSession, InvitationStatus};
    struct Limits {
        calls: std::sync::Mutex<Vec<String>>,
        fail: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl TeamMemberLimitResolver for Limits {
        async fn maximum(&self, team_id: &str) -> AuthResult<Option<usize>> {
            self.calls.lock().unwrap().push(team_id.to_owned());
            if team_id == "second" && self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AuthError::forbidden("Application rejected team capacity"));
            }
            Ok(Some(if team_id == "first" { 1 } else { 2 }))
        }
    }
    let store = store().await;
    for id in ["first", "second"] {
        store
            .create_team(CreateTeam {
                id: Some(id.into()),
                name: id.into(),
                organization_id: "org-a".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
        .add_team_member(&"second".into(), "user-a", None)
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: "user-b".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        "org-a",
        "user-b@example.com",
        "member",
        "user-a",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    input.team_id = Some("first,second".into());
    let invitation = store.create_invitation(input).await.unwrap();
    let limits = Limits {
        calls: Default::default(),
        fail: true.into(),
    };
    let error = store
        .accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "user-b",
            Some(session.token()),
            true,
            TeamMemberLimits::Resolver(&limits),
        )
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), 403);
    assert_eq!(*limits.calls.lock().unwrap(), ["first", "second"]);
    assert!(store.list_team_members("first").await.unwrap().is_empty());
    assert_eq!(store.list_team_members("second").await.unwrap().len(), 1);
    assert!(store.get_member("org-a", "user-b").await.unwrap().is_none());
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .status,
        InvitationStatus::Pending
    );
    assert_eq!(
        store
            .get_session(session.token())
            .await
            .unwrap()
            .unwrap()
            .active_organization_id(),
        None
    );
    limits
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    store
        .accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "user-b",
            Some(session.token()),
            true,
            TeamMemberLimits::Resolver(&limits),
        )
        .await
        .unwrap();
    assert_eq!(store.list_team_members("first").await.unwrap().len(), 1);
    assert_eq!(store.list_team_members("second").await.unwrap().len(), 2);
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .status,
        InvitationStatus::Accepted
    );
}

#[tokio::test]
async fn application_team_and_invitation_fields_survive_persistence() {
    use better_auth_core::{InvitationStatus, UpdateTeam};
    let store = store().await;
    let timestamp = chrono::DateTime::parse_from_rfc3339("2025-01-02T03:04:05Z")
        .unwrap()
        .to_utc();
    let team = store
        .create_team(CreateTeam {
            id: Some("application-team".into()),
            created_at: Some(timestamp),
            name: "Application".into(),
            organization_id: "org-a".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(team.id, "application-team");
    assert_eq!(team.created_at, timestamp);
    let team = store
        .update_team(
            team.id.typed().unwrap(),
            UpdateTeam {
                organization_id: Some("org-b".into()),
                updated_at: Some(Some(timestamp)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(team.organization_id, "org-b");
    assert_eq!(team.updated_at, Some(timestamp));
    let mut input =
        CreateInvitation::new("org-a", "user-b@example.com", "admin", "user-a", timestamp);
    input.id = Some("application-invitation".into());
    input.created_at = Some(timestamp);
    input.status = Some(InvitationStatus::Rejected);
    let invitation = store.create_invitation(input).await.unwrap();
    assert_eq!(invitation.id, "application-invitation");
    assert_eq!(invitation.created_at, timestamp);
    assert_eq!(invitation.status, InvitationStatus::Rejected);
}

#[tokio::test]
async fn organization_id_overrides_obey_database_foreign_keys() {
    use better_auth_core::UpdateOrganization;
    let store = store().await;
    let renamed = store
        .update_organization(
            "org-a",
            UpdateOrganization {
                id: Some("replacement".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(renamed.id, "replacement");
    assert!(
        store
            .get_organization_by_id("org-a")
            .await
            .unwrap()
            .is_none()
    );
    store
        .create_member(CreateMember::new("org-b", "user-a", "owner"))
        .await
        .unwrap();
    assert!(
        store
            .update_organization(
                "org-b",
                UpdateOrganization {
                    id: Some("invalid-replacement".into()),
                    name: Some("Must roll back".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_organization_by_id("org-b")
            .await
            .unwrap()
            .unwrap()
            .name,
        "org-b"
    );
    assert!(
        store
            .get_organization_by_id("invalid-replacement")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_member("org-b", "user-a").await.unwrap().is_some());
}
