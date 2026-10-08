#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields.rs"]
mod fixture;

use better_auth::__private_core::{
    AuthSession, FieldMap, FieldValue,
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

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify persistence and invitation atomicity; setup errors propagate separately."
)]
async fn custom_organization_tables_preserve_fields_and_atomic_invitation_defaults_after_reopen()
-> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-organization-fields-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let db = Database::connect(&url).await?;
    run_migrations(&db).await?;
    fixture::create_tables(&db).await?;
    let config = better_auth::AuthConfig::new("organization-persistence-secret-at-least-32-chars")
        .base_url("http://localhost:3000");
    let mut options = OrganizationConfig::default();
    fixture::configure(&mut options);
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone())
        .with_organization_schema::<fixture::models::Models>();
    store.configure_organization_fields(options.schema.clone())?;
    for id in ["owner", "recipient"] {
        let _ = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some(id.into()),
                email: Some(format!("{id}@example.com")),
                ..Default::default()
            })
            .await?;
    }
    let mut create = CreateOrganization::new("Mapped organization", "mapped");
    let _ = create
        .additional_fields
        .insert("label".into(), FieldValue::from("original"));
    let organization = store.create_organization(create).await?;
    assert_eq!(organization.metadata.field_value(), FieldValue::Null);
    assert_eq!(
        organization.additional_fields.get("label"),
        Some(&FieldValue::from("original:in:out"))
    );
    assert_eq!(
        organization.additional_fields.get("secret"),
        Some(&FieldValue::from("hidden"))
    );
    let _ = store
        .create_member(CreateMember::new(
            organization.id.typed()?,
            "owner",
            "owner",
        ))
        .await?;
    let team = store
        .create_team(CreateTeam {
            name: "Mapped team".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: "recipient".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let mut invitation = CreateInvitation::new(
        organization.id.typed()?,
        "recipient@example.com",
        "member",
        "owner",
        (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
    );
    invitation.team_id = Some(team.id.typed()?.clone());
    let _ = invitation
        .additional_fields
        .insert("label".into(), FieldValue::from("invite"));
    let invitation = store.create_invitation(invitation).await?;
    let (member, accepted, snapshot) = store
        .accept_invitation_with_teams(
            invitation.id.typed()?,
            "recipient",
            Some(session.token()),
            true,
            Some(1).into(),
        )
        .await?;
    assert_eq!(
        member.additional_fields.get("label"),
        Some(&FieldValue::from("guest:in:out"))
    );
    assert_eq!(
        accepted.additional_fields.get("label"),
        Some(&FieldValue::from("invite:in:out"))
    );
    assert_eq!(
        accepted.additional_fields.get("marker"),
        Some(&FieldValue::from("updated"))
    );
    assert_eq!(
        snapshot
            .ok_or("Accepted invitation must return a session snapshot")?
            .active_team_id
            .as_deref(),
        team.id.as_str()
    );
    let raw = fixture::models::organization::Entity::find_by_id(organization.id.typed()?)
        .one(&db)
        .await?
        .ok_or("Created organization must remain stored")?;
    assert_eq!(raw.stored_label.as_deref(), Some("original:in"));
    let membership = fixture::models::team_member::Entity::find()
        .filter(fixture::models::team_member::Column::TeamId.eq(team.id.typed()?))
        .one(&db)
        .await?
        .ok_or("Accepted invitation must create a team membership")?;
    assert_eq!(
        membership.membership_key,
        Some(
            better_auth::__private_core::organization_fields::team_membership_key(
                team.id.typed()?,
                "recipient"
            )?
        )
    );
    drop(store);
    db.close().await?;

    let db = Database::connect(&url).await?;
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone())
        .with_organization_schema::<fixture::models::Models>();
    store.configure_organization_fields(options.schema.clone())?;
    let restored = store
        .get_organization_by_id(organization.id.typed()?)
        .await?
        .ok_or("Organization must remain stored after reopening the database")?;
    assert_eq!(
        restored.additional_fields.get("label"),
        Some(&FieldValue::from("original:in:out"))
    );
    let owner_session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: "owner".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await?;
    let auth = better_auth::BetterAuth::<BundledSchema>::new(config)
        .store(store.clone())
        .plugin(better_auth::plugins::organization::OrganizationPlugin::with_config(options))
        .build()
        .await?;
    let updated = store
        .update_organization(
            organization.id.typed()?,
            UpdateOrganization {
                metadata: Some(FieldValue::Null),
                additional_fields: [("label".into(), FieldValue::from("changed"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.name, "Mapped organization");
    assert_eq!(updated.metadata.field_value(), FieldValue::from("null"));
    assert_http_metadata(
        &auth,
        owner_session.token(),
        organization.id.typed()?,
        json!(null),
    )
    .await?;
    assert_eq!(
        updated.additional_fields.get("label"),
        Some(&FieldValue::from("changed:in:out"))
    );
    assert_eq!(
        updated.additional_fields.get("marker"),
        Some(&FieldValue::from("updated"))
    );
    let updated = store
        .update_organization(
            organization.id.typed()?,
            UpdateOrganization {
                metadata: Some(FieldValue::from(FieldMap::new())),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.metadata.field_value(), FieldValue::from("{}"));
    assert_http_metadata(
        &auth,
        owner_session.token(),
        organization.id.typed()?,
        json!({}),
    )
    .await?;
    let pending = store
        .get_invitation_by_id(invitation.id.typed()?)
        .await?
        .ok_or("Accepted invitation must remain stored after reopening the database")?;
    assert_eq!(
        pending.additional_fields.get("marker"),
        Some(&FieldValue::from("updated"))
    );
    let users = store.list_team_members(team.id.typed()?).await?;
    assert_eq!(users.len(), 1);
    fixture::reset(&db).await?;
    drop(auth);
    drop(store);
    db.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}

async fn assert_http_metadata(
    auth: &better_auth::BetterAuth<BundledSchema>,
    token: &str,
    organization_id: &str,
    expected: serde_json::Value,
) -> TestResult {
    let cookie = better_auth::__private_core::utils::cookie_utils::sign_cookie_value(
        token,
        auth.config().signing_secret(),
    );
    let response = auth
        .call_endpoint(
            better_auth::__private_core::HttpMethod::Post,
            "/organization/update",
            better_auth::server_api::EndpointInput {
                headers: Some(std::collections::HashMap::from([
                    (
                        "cookie".into(),
                        format!("better-auth.session_token={cookie}"),
                    ),
                    ("origin".into(), "http://localhost:3000".into()),
                ])),
                body: Some(json!({"organizationId":organization_id,"data":{"metadata":expected}})),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| error.to_auth_response());
    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes()?)?;
    if expected.is_null() {
        assert_eq!(response.status, 400);
        assert_eq!(
            body,
            json!({
                "code": "VALIDATION_ERROR",
                "message": "[body.data.metadata] Invalid input: expected record, received null"
            })
        );
    } else {
        assert_eq!(response.status, 200);
        assert_eq!(body.get("metadata"), Some(&expected));
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify accepted policies and exact configuration failures; setup errors propagate separately."
)]
async fn organization_field_configuration_accepts_replacement_policies_and_rejects_invalid_mappings()
-> TestResult {
    use better_auth::{
        BetterAuth, config::UserFieldConfig, plugins::organization::OrganizationPlugin,
    };

    for (entity, name, storage, expected) in [
        ("organization", "metadata", None, None),
        (
            "member",
            "user_id",
            None,
            Some("maps to a different typed field user_id"),
        ),
        ("invitation", "expiresAt", None, None),
        (
            "team",
            "organizationId",
            Some("name"),
            Some("maps to a different typed field name"),
        ),
        ("organizationRole", "permission", None, None),
        (
            "organization",
            "label",
            Some("name"),
            Some("maps to a different typed field name"),
        ),
        (
            "organization",
            "label",
            Some("unmappedLabel"),
            Some("Unknown organization model column: unmappedLabel"),
        ),
    ] {
        let db = Database::connect("sqlite::memory:").await?;
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
            _ => return Err(format!("Unknown fixture entity: {entity}").into()),
        };
        let _ = fields.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_name: storage.map(str::to_owned),
                ..Default::default()
            },
        );
        let result = BetterAuth::<BundledSchema>::new(config)
            .store(store)
            .plugin(OrganizationPlugin::with_config(options))
            .build()
            .await;
        if let Some(expected) = expected {
            let error = result
                .err()
                .ok_or("invalid field configuration must fail before handling requests")?;
            assert!(
                error.to_string().contains(expected),
                "{entity}.{name}: {error}"
            );
        } else {
            assert!(
                result.is_ok(),
                "replacement policy must initialize: {entity}.{name}"
            );
        }
    }
    Ok(())
}
