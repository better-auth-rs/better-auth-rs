#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;
use crate::plugins::organization::OrganizationPlugin;
use crate::plugins::test_helpers::{
    assert_coded_api_error, create_test_config, create_test_context_with_plugins,
    create_user_and_session,
};
use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
use chrono::Duration;

#[tokio::test]
async fn resend_renews_existing_invitation_when_pending_limit_is_reached() {
    let config = OrganizationConfig {
        invitation_limit: Some(1),
        ..Default::default()
    };
    let ctx = create_test_context_with_plugins(
        create_test_config(),
        &[&OrganizationPlugin::with_config(config.clone())],
    )
    .await;
    let (user, session) = create_user_and_session(
        &ctx,
        CreateUser {
            name: Some("Fixture".into()).into(),
            email: Some("owner@example.com".into()),
            ..Default::default()
        },
        Duration::hours(1),
    )
    .await;
    let organization = ctx
        .database
        .create_organization(CreateOrganization {
            additional_fields: Default::default(),
            id: None,
            name: "Organization".into(),
            slug: "resend-limit".into(),
            logo: None.into(),
            metadata: None.into(),
        })
        .await
        .unwrap();
    ctx.database
        .create_member(CreateMember {
            additional_fields: Default::default(),
            organization_id: organization.id.typed().unwrap().clone().into(),
            user_id: user.id.clone(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let mut body: InviteMemberRequest = serde_json::from_value(serde_json::json!({
        "organizationId": organization.id, "email": "invitee@example.com", "role": "member",
    }))
    .unwrap();
    let first = invite_member_core(
        &body,
        &(user.clone(), session.clone()).into(),
        &config,
        &ctx,
        None,
    )
    .await
    .unwrap();
    let shortened = first
        .expires_at
        .typed()
        .unwrap()
        .to_datetime()
        .unwrap()
        .unwrap()
        - Duration::hours(1);
    ctx.database
        .update_invitation_expiry(first.id.typed().unwrap(), shortened)
        .await
        .unwrap();
    body.resend = true.into();
    let resent = invite_member_core(
        &body,
        &(user.clone(), session.clone()).into(),
        &config,
        &ctx,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resent.id, first.id);
    assert!(
        resent
            .expires_at
            .typed()
            .unwrap()
            .to_datetime()
            .unwrap()
            .unwrap()
            > shortened
    );
    assert_eq!(
        ctx.database
            .get_invitation_by_id(first.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        resent.expires_at
    );
    body.email = "another@example.com".into();
    let error = invite_member_core(
        &body,
        &(user.clone(), session.clone()).into(),
        &config,
        &ctx,
        None,
    )
    .await
    .unwrap_err();
    assert_coded_api_error(
        &error,
        "FORBIDDEN",
        403,
        "INVITATION_LIMIT_REACHED",
        "Invitation limit reached",
    );
}
