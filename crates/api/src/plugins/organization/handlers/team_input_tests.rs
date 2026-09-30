use super::*;
use crate::plugins::organization::OrganizationTeamsConfig;
use crate::plugins::test_helpers::{
    create_auth_json_request_no_query, create_test_context, create_user_and_session,
};
use better_auth_core::{
    CreateMember, CreateOrganization, CreateUser, user_fields::UserFieldConfig,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Callbacks {
    limits: AtomicUsize,
    updates: AtomicUsize,
}

#[async_trait::async_trait]
impl OrganizationPolicy for Callbacks {
    async fn maximum_teams(
        &self,
        _: OrganizationTeamLimit<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        self.limits.fetch_add(1, Ordering::SeqCst);
        Ok(Some(100))
    }
}

#[async_trait::async_trait]
impl OrganizationHooks for Callbacks {
    async fn before_update_team(
        &self,
        _: &mut better_auth_core::UpdateTeam,
        _: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        self.updates.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn invalid_team_input_precedes_policies_and_preserves_null_errors() {
    let ctx = create_test_context().await;
    let (user, session) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("team-input@example.com"),
        chrono::Duration::hours(1),
    )
    .await;
    let org = ctx
        .database
        .create_organization(CreateOrganization::new("Input", "team-input"))
        .await
        .unwrap();
    ctx.database
        .create_member(CreateMember {
            organization_id: org.id.clone(),
            user_id: user.id,
            role: "owner".into(),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    ctx.database
        .update_session_active_organization(&session.token, Some(&org.id))
        .await
        .unwrap();
    let callbacks = Arc::new(Callbacks::default());
    let mut config = OrganizationConfig {
        teams: OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        },
        policy: Some(callbacks.clone()),
        hooks: Some(callbacks.clone()),
        ..Default::default()
    };
    config.schema.team.additional_fields.insert(
        "label".into(),
        UserFieldConfig {
            required: Some(true),
            ..Default::default()
        },
    );
    let create = |body| {
        create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create-team",
            Some(&session.token),
            Some(body),
        )
    };
    for (body, field, received) in [
        (json!({"name":"Team"}), "label", "undefined"),
        (
            json!({"name":"Team", "label":"valid", "organizationId":null}),
            "organizationId",
            "null",
        ),
    ] {
        let response = handle_team_request(&create(body), &ctx, &config)
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(response.status, 400);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!({
                "code":"VALIDATION_ERROR",
                "message":format!("[body.{field}] Invalid input: expected string, received {received}")
            })
        );
    }
    assert_eq!(callbacks.limits.load(Ordering::SeqCst), 0);
    let response = handle_team_request(
        &create(json!({"name":"Team", "label":"valid"})),
        &ctx,
        &config,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(callbacks.limits.load(Ordering::SeqCst), 1);
    let team = serde_json::from_slice::<Value>(&response.body).unwrap();
    let update = |data| {
        create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/update-team",
            Some(&session.token),
            Some(json!({"teamId":team["id"], "data":data})),
        )
    };
    for name_policy in [None, Some(true), Some(false)] {
        if let Some(input) = name_policy {
            config.schema.team.additional_fields.insert(
                "name".into(),
                UserFieldConfig {
                    required: Some(true),
                    input,
                    ..Default::default()
                },
            );
        }
        for field in ["name", "organizationId"] {
            let response = handle_team_request(&update(json!({field:null})), &ctx, &config)
                .await
                .unwrap_err()
                .to_auth_response();
            assert_eq!(response.status, 400);
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap(),
                json!({
                    "code":"VALIDATION_ERROR",
                    "message":format!("[body.data.{field}] Invalid input: expected string, received null")
                })
            );
        }
    }
    assert_eq!(callbacks.updates.load(Ordering::SeqCst), 0);
    let response = handle_team_request(&update(json!({})), &ctx, &config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(callbacks.updates.load(Ordering::SeqCst), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap()["name"],
        "Team"
    );
}
