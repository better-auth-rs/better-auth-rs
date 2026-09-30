#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields.rs"]
mod fixture;

use better_auth::__private_core::{
    AuthSession,
    store::{InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore},
    types::{
        CreateInvitation, CreateMember, CreateOrganization, CreateSession, CreateTeam, CreateUser,
        UpdateOrganization,
    },
};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth::seaorm::{
    Database, SeaOrmStore,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
};
use better_auth_seaorm::store::__private_test_support::{
    bundled_schema::BundledSchema, migrator::run_migrations,
};
use serde_json::json;

#[tokio::test]
async fn custom_organization_tables_preserve_fields_and_atomic_invitation_defaults_after_reopen() {
    let path = std::env::temp_dir().join(format!(
        "better-auth-organization-fields-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let db = Database::connect(&url).await.unwrap();
    run_migrations(&db).await.unwrap();
    fixture::create_tables(&db).await.unwrap();
    let config = better_auth::AuthConfig::new("organization-persistence-secret-at-least-32-chars");
    let mut options = OrganizationConfig::default();
    fixture::configure(&mut options);
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone())
        .with_organization_schema::<fixture::models::Models>();
    store
        .configure_organization_fields(options.schema.clone())
        .unwrap();
    for id in ["owner", "recipient"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                email: Some(format!("{id}@example.com")),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let mut create = CreateOrganization::new("Mapped organization", "mapped");
    let _ = create
        .additional_fields
        .insert("label".into(), json!("original"));
    let organization = store.create_organization(create).await.unwrap();
    assert_eq!(organization.metadata, None);
    assert_eq!(organization.additional_fields["label"], "original:in:out");
    assert_eq!(organization.additional_fields["secret"], "hidden");
    let _ = store
        .create_member(CreateMember::new(&organization.id, "owner", "owner"))
        .await
        .unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "Mapped team".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            user_id: "recipient".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let mut invitation = CreateInvitation::new(
        &organization.id,
        "recipient@example.com",
        "member",
        "owner",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    invitation.team_id = Some(team.id.clone());
    let _ = invitation
        .additional_fields
        .insert("label".into(), json!("invite"));
    let invitation = store.create_invitation(invitation).await.unwrap();
    let (member, accepted, snapshot) = store
        .accept_invitation_with_teams(
            &invitation.id,
            "recipient",
            session.token(),
            true,
            Some(1).into(),
        )
        .await
        .unwrap();
    assert_eq!(member.additional_fields["label"], "guest:in:out");
    assert_eq!(accepted.additional_fields["label"], "invite:in:out");
    assert_eq!(accepted.additional_fields["marker"], "updated");
    assert_eq!(
        snapshot.unwrap().active_team_id.as_deref(),
        Some(team.id.as_str())
    );
    let raw = fixture::models::organization::Entity::find_by_id(&organization.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.stored_label.as_deref(), Some("original:in"));
    let membership = fixture::models::team_member::Entity::find()
        .filter(fixture::models::team_member::Column::TeamId.eq(&team.id))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        membership.membership_key,
        Some(
            better_auth::__private_core::organization_fields::team_membership_key(
                &team.id,
                "recipient"
            )
            .unwrap()
        )
    );
    drop(store);
    db.close().await.unwrap();

    let db = Database::connect(&url).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(config, db.clone())
        .with_organization_schema::<fixture::models::Models>();
    store.configure_organization_fields(options.schema).unwrap();
    let restored = store
        .get_organization_by_id(&organization.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.additional_fields["label"], "original:in:out");
    let updated = store
        .update_organization(
            &organization.id,
            UpdateOrganization {
                metadata: Some(json!(null)),
                additional_fields: [("label".into(), json!("changed"))].into_iter().collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.name, "Mapped organization");
    assert_eq!(updated.metadata, Some(json!(null)));
    assert_eq!(updated.additional_fields["label"], "changed:in:out");
    assert_eq!(updated.additional_fields["marker"], "updated");
    let updated = store
        .update_organization(
            &organization.id,
            UpdateOrganization {
                metadata: Some(json!({})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.metadata, Some(json!({})));
    let pending = store
        .get_invitation_by_id(&invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.additional_fields["marker"], "updated");
    let users = store.list_team_members(&team.id).await.unwrap();
    assert_eq!(users.len(), 1);
    fixture::reset(&db).await.unwrap();
    drop(store);
    db.close().await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn organization_field_configuration_rejects_incompatible_policies_and_missing_columns_at_startup()
 {
    use better_auth::{
        BetterAuth, config::UserFieldConfig, plugins::organization::OrganizationPlugin,
    };

    for (entity, name, storage, expected) in [
        (
            "organization",
            "metadata",
            None,
            "organization.metadata does not support",
        ),
        (
            "member",
            "user_id",
            None,
            "must use the public field name userId",
        ),
        (
            "invitation",
            "expiresAt",
            None,
            "must preserve the built-in DateTimeUtc field type",
        ),
        (
            "team",
            "organizationId",
            Some("name"),
            "maps to a different typed field name",
        ),
        (
            "organizationRole",
            "permission",
            None,
            "organizationRole.permission does not support",
        ),
        (
            "organization",
            "label",
            Some("name"),
            "maps to a different typed field name",
        ),
        (
            "organization",
            "label",
            Some("unmappedLabel"),
            "Unknown organization model column: unmappedLabel",
        ),
    ] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let config =
            better_auth::AuthConfig::new("organization-configuration-secret-at-least-32-chars");
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db)
            .with_organization_schema::<fixture::models::Models>();
        let mut options = OrganizationConfig::default();
        let fields = match entity {
            "organization" => &mut options.schema.organization,
            "member" => &mut options.schema.member,
            "invitation" => &mut options.schema.invitation,
            "team" => &mut options.schema.team,
            "organizationRole" => &mut options.schema.organization_role,
            _ => unreachable!(),
        };
        let _ = fields.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                field_name: storage.map(str::to_owned),
                ..Default::default()
            },
        );
        let error = BetterAuth::<BundledSchema>::new(config)
            .store(store)
            .plugin(OrganizationPlugin::with_config(options))
            .build()
            .await
            .err()
            .expect("invalid field configuration must fail before handling requests");
        assert!(
            error.to_string().contains(expected),
            "{entity}.{name}: {error}"
        );
    }
}
