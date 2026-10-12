#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]

use better_auth_core::types::{CreateOrganization, CreateUser, HttpMethod};
use chrono::Duration;

use crate::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use crate::plugins::test_helpers::{
    create_auth_json_request_no_query, create_test_config, create_test_context_with_plugins,
    create_user, create_user_and_session,
};

use super::{get_full_organization_core, handle_create_organization};
use crate::plugins::organization::types::GetFullOrganizationQuery;

fn test_config() -> OrganizationConfig {
    OrganizationConfig {
        allow_user_to_create_organization: true,
        organization_limit: None,
        membership_limit: Some(100),
        creator_role: "owner".to_string(),
        invitation_expires_in: 172800.0,
        invitation_limit: Some(100),
        disable_organization_deletion: false,
        roles: None,
        send_invitation_email: None,
        ..Default::default()
    }
}

fn test_user(email: &str, name: &str) -> CreateUser {
    CreateUser {
        email: Some(email.to_string()),
        name: Some(name.to_string()).into(),
        ..CreateUser::default()
    }
}

#[tokio::test]
async fn create_organization_keeps_current_active_organization_when_requested() {
    let config = test_config();
    let ctx = create_test_context_with_plugins(
        create_test_config(),
        &[&OrganizationPlugin::with_config(config.clone())],
    )
    .await;
    let (user, session) = create_user_and_session(
        &ctx,
        test_user("owner@example.com", "Owner"),
        Duration::hours(1),
    )
    .await;
    let existing = ctx
        .database
        .create_organization(CreateOrganization {
            additional_fields: Default::default(),
            id: None,
            name: "Existing".to_string().into(),
            slug: "existing".to_string().into(),
            logo: None.into(),
            metadata: None.into(),
        })
        .await
        .expect("organization should be created");
    ctx.database
        .update_session_active_organization(
            session.token.typed().unwrap(),
            Some(existing.id.typed().unwrap()),
        )
        .await
        .expect("active organization should update");

    let request = create_auth_json_request_no_query(
        HttpMethod::Post,
        "/organization/create",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({
            "name": "Next",
            "slug": "next",
            "keepCurrentActiveOrganization": true
        })),
    );

    handle_create_organization(&request, &ctx, &config)
        .await
        .expect("request should succeed");

    let updated_session = ctx
        .database
        .get_session(session.token.typed().unwrap())
        .await
        .expect("session lookup should succeed")
        .expect("session should exist");
    assert_eq!(
        updated_session
            .active_organization_id
            .typed()
            .unwrap()
            .as_ref(),
        Some(existing.id.typed().unwrap())
    );
    assert_eq!(user.id, session.user_id);
}

#[tokio::test]
async fn create_organization_updates_active_organization_by_default() {
    let config = test_config();
    let ctx = create_test_context_with_plugins(
        create_test_config(),
        &[&OrganizationPlugin::with_config(config.clone())],
    )
    .await;
    let (_, session) = create_user_and_session(
        &ctx,
        test_user("owner2@example.com", "Owner"),
        Duration::hours(1),
    )
    .await;

    let request = create_auth_json_request_no_query(
        HttpMethod::Post,
        "/organization/create",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({
            "name": "Created",
            "slug": "created"
        })),
    );

    let response = handle_create_organization(&request, &ctx, &config)
        .await
        .expect("request should succeed");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body.bytes().unwrap()).expect("response should be JSON");
    let created_id = body["id"]
        .as_str()
        .expect("response should contain organization id");

    let updated_session = ctx
        .database
        .get_session(session.token.typed().unwrap())
        .await
        .expect("session lookup should succeed")
        .expect("session should exist");
    assert_eq!(
        updated_session
            .active_organization_id
            .typed()
            .unwrap()
            .as_deref(),
        Some(created_id)
    );
}

#[tokio::test]
async fn get_full_organization_respects_members_limit() {
    let config = test_config();
    let ctx = create_test_context_with_plugins(
        create_test_config(),
        &[&OrganizationPlugin::with_config(config.clone())],
    )
    .await;
    let (user, session) = create_user_and_session(
        &ctx,
        test_user("owner3@example.com", "Owner"),
        Duration::hours(1),
    )
    .await;
    let organization = ctx
        .database
        .create_organization(CreateOrganization {
            additional_fields: Default::default(),
            id: None,
            name: "Team".to_string().into(),
            slug: "team".to_string().into(),
            logo: None.into(),
            metadata: None.into(),
        })
        .await
        .expect("organization should be created");
    ctx.database
        .create_member(better_auth_core::types::CreateMember {
            additional_fields: Default::default(),
            organization_id: organization.id.clone(),
            user_id: user.id.clone(),
            role: config.creator_role.clone().into(),
        })
        .await
        .expect("owner member should be created");

    let extra_user = create_user(&ctx, test_user("member@example.com", "Member")).await;
    ctx.database
        .create_member(better_auth_core::types::CreateMember {
            additional_fields: Default::default(),
            organization_id: organization.id.clone(),
            user_id: extra_user.id.clone(),
            role: "member".into(),
        })
        .await
        .expect("extra member should be created");

    let response = get_full_organization_core(
        &GetFullOrganizationQuery {
            organization_id: Some(organization.id.typed().unwrap().clone()),
            organization_slug: None,
            members_limit: Some(1.0),
        },
        &(user, session).into(),
        &config,
        &ctx,
    )
    .await
    .expect("request should succeed")
    .expect("organization should exist");

    assert_eq!(
        response
            .model_property("members")
            .unwrap()
            .as_array()
            .unwrap()
            .len()
            .expect("member array must be readable"),
        1
    );
}
