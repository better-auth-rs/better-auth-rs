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
                id: Some(id.into()),
                name: id.into(),
                slug: id.into(),
                logo: None,
                metadata: None,
            })
            .await
            .unwrap();
    }
    for id in ["user-a", "user-b"] {
        store
            .create_user(CreateUser {
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
async fn team_capacity_deduplication_and_scoped_cleanup() {
    let store = store().await;
    let a = store
        .create_team(CreateTeam {
            name: "a".into(),
            organization_id: "org-a".into(),
            updated_at: None,
        })
        .await
        .unwrap();
    let b = store
        .create_team(CreateTeam {
            name: "b".into(),
            organization_id: "org-b".into(),
            updated_at: None,
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
    store.delete_member(&member.id).await.unwrap();
    assert!(store.list_team_members(&a.id).await.unwrap().is_empty());
    assert_eq!(store.list_team_members(&b.id).await.unwrap().len(), 1);
    let mut input = CreateInvitation::new(
        "org-a",
        "invite@example.com",
        "member",
        "user-a",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    input.team_id = Some(a.id.clone());
    let invitation = store.create_invitation(input).await.unwrap();
    store.delete_team(&a.id).await.unwrap();
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .team_id,
        None
    );
    assert!(store.get_team(&b.id).await.unwrap().is_some());
}

#[tokio::test]
async fn dynamic_roles_persist_json_and_organization_deletion_cascades() {
    let store = store().await;
    let role = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: "org-a".into(),
            role: "editor".into(),
            permission: serde_json::json!({"team": ["create"]}),
        })
        .await
        .unwrap();
    store
        .create_organization_role(CreateOrganizationRole {
            organization_id: "org-b".into(),
            role: "editor".into(),
            permission: serde_json::json!({}),
        })
        .await
        .unwrap();
    let updated = store
        .update_organization_role(
            &role.id,
            UpdateOrganizationRole {
                role: Some("writer".into()),
                permission: Some(serde_json::json!({"team": ["update"]})),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.permission, serde_json::json!({"team": ["update"]}));
    assert!(updated.updated_at.is_some());
    let team = store
        .create_team(CreateTeam {
            name: "a".into(),
            organization_id: "org-a".into(),
            updated_at: None,
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
            .get_organization_role(&role.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_team(&team.id).await.unwrap().is_none());
    assert!(store.list_team_members(&team.id).await.unwrap().is_empty());
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
        })
        .await
        .unwrap();
    let full = store
        .create_team(CreateTeam {
            name: "full".into(),
            organization_id: "org-a".into(),
            updated_at: None,
        })
        .await
        .unwrap();
    store
        .add_team_member(&full.id, "user-a", Some(1))
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
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
    input.team_id = Some(format!("{},{}", first.id, full.id));
    let invitation = store.create_invitation(input).await.unwrap();
    assert!(
        store
            .accept_invitation_with_teams(&invitation.id, "user-b", session.token(), Some(1))
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvitationStatus::Pending
    );
    assert!(store.list_team_members(&first.id).await.unwrap().is_empty());
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
    store.remove_team_member(&full.id, "user-a").await.unwrap();
    let (a, b) = tokio::join!(
        store.accept_invitation_with_teams(&invitation.id, "user-b", session.token(), Some(1)),
        store.accept_invitation_with_teams(&invitation.id, "user-b", session.token(), Some(1))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(store.list_team_members(&first.id).await.unwrap().len(), 1);
    assert_eq!(store.list_team_members(&full.id).await.unwrap().len(), 1);
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
        })
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
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
    input.team_id = Some(team.id.clone());
    let invitation = store.create_invitation(input).await.unwrap();
    let (member, snapshot) = store
        .accept_invitation_with_teams(&invitation.id, "user-b", session.token(), None)
        .await
        .unwrap();
    assert_eq!(member.organization_id, "org-a");
    let snapshot = snapshot.unwrap();
    assert_eq!(snapshot.active_organization_id(), Some("org-b"));
    assert_eq!(snapshot.active_team_id(), Some(team.id.as_str()));
    let persisted = store.get_session(session.token()).await.unwrap().unwrap();
    assert_eq!(persisted.active_organization_id(), Some("org-a"));
    assert_eq!(persisted.active_team_id(), Some(team.id.as_str()));
}
