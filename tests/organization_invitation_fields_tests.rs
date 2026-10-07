#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields.rs"]
mod fixture;

use better_auth::__private_core::FieldValue;
use better_auth::__private_core::{
    AuthSession, InvitationStatus,
    store::{InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore},
    types::{CreateInvitation, CreateOrganization, CreateSession, CreateTeam, CreateUser},
};
use better_auth::config::UserFieldTransform;
use better_auth::seaorm::{Database, SeaOrmStore};
use better_auth::{AuthConfig, AuthError, plugins::organization::OrganizationConfig};
use better_auth_seaorm::store::__private_test_support::{
    bundled_schema::BundledSchema, migrator::run_migrations,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type Store = SeaOrmStore<BundledSchema, fixture::models::Models>;

async fn store(config: OrganizationConfig) -> Store {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    fixture::create_tables(&db).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("organization-invitation-secret-at-least-32-chars"),
        db,
    )
    .with_organization_schema::<fixture::models::Models>();
    store.configure_organization_fields(config.schema).unwrap();
    for id in ["org-a", "org-b"] {
        let mut input = CreateOrganization::new(id, id);
        input.id = Some(id.into());
        let _ = store.create_organization(input).await.unwrap();
    }
    for id in ["owner", "recipient"] {
        let _ = store
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

fn options() -> OrganizationConfig {
    let mut options = OrganizationConfig::default();
    fixture::configure(&mut options);
    options
}

async fn team(store: &Store) -> String {
    store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "org-a".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .id
        .typed()
        .unwrap()
        .clone()
}

async fn invitation(
    store: &Store,
    team_id: &str,
    organization: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let mut input = CreateInvitation::new(
        organization,
        "recipient@example.com",
        "member",
        "owner",
        expires_at.into(),
    );
    input.team_id = Some(team_id.into());
    store
        .create_invitation(input)
        .await
        .unwrap()
        .id
        .typed()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn team_deletion_updates_only_live_invitations_in_its_organization() {
    let store = store(options()).await;
    let team = team(&store).await;
    let now = chrono::Utc::now();
    let live = invitation(&store, &team, "org-a", now + chrono::Duration::days(1)).await;
    let expired = invitation(&store, &team, "org-a", now - chrono::Duration::days(1)).await;
    let other_org = invitation(&store, &team, "org-b", now + chrono::Duration::days(1)).await;
    store.delete_team(&team).await.unwrap();
    let live = store.get_invitation_by_id(&live).await.unwrap().unwrap();
    assert_eq!(live.team_id, None);
    assert_eq!(
        live.additional_fields.get("marker"),
        Some(&FieldValue::from("updated"))
    );
    for id in [expired, other_org] {
        let invitation = store.get_invitation_by_id(&id).await.unwrap().unwrap();
        assert_eq!(
            invitation.team_id.typed().unwrap().as_deref(),
            Some(team.as_str())
        );
        assert_eq!(
            invitation.additional_fields.get("marker"),
            Some(&FieldValue::from("created"))
        );
    }
    fixture::reset(store.connection()).await.unwrap();
}

#[tokio::test]
async fn failed_acceptance_compensates_invitation_updates_without_committing_members() {
    for teams_enabled in [false, true] {
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut options = options();
        options
            .schema
            .invitation
            .fields_mut()
            .get_mut("marker")
            .unwrap()
            .on_update = Some(Arc::new(move || {
            FieldValue::from(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            ))
        }));
        if !teams_enabled {
            options
                .schema
                .member
                .fields_mut()
                .get_mut("label")
                .unwrap()
                .transform
                .get_or_insert_default()
                .output = Some(UserFieldTransform::new(|_| {
                Err(AuthError::bad_request("member output failed"))
            }));
        }
        let store = store(options).await;
        let team = team(&store).await;
        let id = invitation(
            &store,
            &team,
            "org-a",
            chrono::Utc::now() + chrono::Duration::days(1),
        )
        .await;
        let session = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                user_id: "recipient".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::days(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let error = store
            .accept_invitation_with_teams(
                &id,
                "recipient",
                Some(session.token()),
                teams_enabled,
                Some(0).into(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains(if teams_enabled {
            "Team member limit reached"
        } else {
            "member output failed"
        }));
        let invitation = store.get_invitation_by_id(&id).await.unwrap().unwrap();
        assert_eq!(invitation.status, InvitationStatus::Pending);
        assert_eq!(
            invitation.additional_fields.get("marker"),
            Some(&FieldValue::from("updated-2"))
        );
        assert_eq!(updates.load(Ordering::SeqCst), 2);
        assert!(
            store
                .get_member("org-a", "recipient")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.list_team_members(&team).await.unwrap().is_empty());
        assert!(
            store
                .get_session(session.token())
                .await
                .unwrap()
                .unwrap()
                .active_organization_id()
                .is_none()
        );
    }
}

#[tokio::test]
async fn claim_output_and_compensation_errors_preserve_the_upstream_failure_stage() {
    for claim_output_failure in [false, true] {
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut options = options();
        let marker = options
            .schema
            .invitation
            .fields_mut()
            .get_mut("marker")
            .unwrap();
        marker.on_update = Some(Arc::new(move || {
            FieldValue::from(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            ))
        }));
        if claim_output_failure {
            marker.transform.get_or_insert_default().output =
                Some(UserFieldTransform::new(|value| {
                    if value == FieldValue::from("updated-1") {
                        Err(AuthError::bad_request("claim output failed"))
                    } else {
                        Ok(value)
                    }
                }));
        } else {
            marker.transform.get_or_insert_default().input =
                Some(UserFieldTransform::new(|value| {
                    if value == FieldValue::from("updated-2") {
                        Err(AuthError::bad_request("compensation failed"))
                    } else {
                        Ok(value)
                    }
                }));
        }
        let store = store(options.clone()).await;
        let team = team(&store).await;
        let id = invitation(
            &store,
            &team,
            "org-a",
            chrono::Utc::now() + chrono::Duration::days(1),
        )
        .await;
        let session = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                user_id: "recipient".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::days(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let error = store
            .accept_invitation_with_teams(
                &id,
                "recipient",
                Some(session.token()),
                true,
                Some(0).into(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains(if claim_output_failure {
            "claim output failed"
        } else {
            "compensation failed"
        }));
        options
            .schema
            .invitation
            .fields_mut()
            .get_mut("marker")
            .unwrap()
            .transform
            .get_or_insert_default()
            .output = None;
        store.configure_organization_fields(options.schema).unwrap();
        let invitation = store.get_invitation_by_id(&id).await.unwrap().unwrap();
        assert_eq!(invitation.status, InvitationStatus::Accepted);
        assert_eq!(
            invitation.additional_fields.get("marker"),
            Some(&FieldValue::from("updated-1"))
        );
        assert_eq!(
            updates.load(Ordering::SeqCst),
            if claim_output_failure { 1 } else { 2 }
        );
        assert!(
            store
                .get_member("org-a", "recipient")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.list_team_members(&team).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn team_deletion_rolls_back_read_and_update_output_errors() {
    for failure_stage in ["expired", "unassigned", "updated"] {
        let store = store(options()).await;
        let team_id = team(&store).await;
        let _ = store
            .add_team_member(&team_id.clone().into(), "owner", None)
            .await
            .unwrap();
        let expires = chrono::Utc::now() + chrono::Duration::days(1);
        let mut live = Vec::new();
        for _ in 0..2 {
            live.push(invitation(&store, &team_id, "org-a", expires).await);
        }
        if failure_stage != "updated" {
            let mut input = CreateInvitation::new(
                "org-a",
                "other@example.com",
                "member",
                "owner",
                expires.into(),
            );
            if failure_stage == "expired" {
                input.team_id = Some(team_id.clone());
                input.expires_at = (chrono::Utc::now() - chrono::Duration::days(1)).into();
            }
            let _ = input
                .additional_fields
                .insert("marker".into(), FieldValue::from("read-fail"));
            let _ = store.create_invitation(input).await.unwrap();
        }
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut config = options();
        let marker = config
            .schema
            .invitation
            .fields_mut()
            .get_mut("marker")
            .unwrap();
        marker.on_update = Some(Arc::new(move || {
            FieldValue::from(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            ))
        }));
        marker.transform.get_or_insert_default().output = Some(UserFieldTransform::new(|value| {
            if value == FieldValue::from("read-fail") || value == FieldValue::from("updated-2") {
                Err(AuthError::bad_request("invitation output failed"))
            } else {
                Ok(value)
            }
        }));
        store.configure_organization_fields(config.schema).unwrap();
        let error = store.delete_team(&team_id).await.unwrap_err();
        assert!(error.to_string().contains("invitation output failed"));
        assert_eq!(
            updates.load(Ordering::SeqCst),
            if failure_stage == "updated" { 2 } else { 0 }
        );
        store
            .configure_organization_fields(options().schema)
            .unwrap();
        assert!(store.get_team(&team_id).await.unwrap().is_some());
        assert_eq!(store.list_team_members(&team_id).await.unwrap().len(), 1);
        for id in live {
            let row = store.get_invitation_by_id(&id).await.unwrap().unwrap();
            assert_eq!(
                row.team_id.typed().unwrap().as_deref(),
                Some(team_id.as_str())
            );
            assert_eq!(
                row.additional_fields.get("marker"),
                Some(&FieldValue::from("created"))
            );
        }
    }
}
