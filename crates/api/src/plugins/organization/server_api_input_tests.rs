use super::*;
use crate::plugins::organization::OrganizationConfig;
use crate::plugins::test_helpers::create_test_context;
use better_auth_core::{CreateOrganization, CreateUser, user_fields::UserFieldConfig};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct CountLimits(AtomicUsize);

#[async_trait::async_trait]
impl MembershipLimitPolicy for CountLimits {
    async fn membership_limit(&self, _: OrganizationUser<'_>) -> AuthResult<usize> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(100)
    }
}

#[tokio::test]
async fn add_member_validates_fields_before_queries_and_limit_callbacks() {
    let mut ctx = create_test_context().await;
    ctx.extensions.insert(Arc::new(
        better_auth_core::endpoint_dispatch::EndpointDispatcher::<
            better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::new(Arc::new(Vec::new()), Default::default(), []),
    ));
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("member-input@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Input", "member-input"))
        .await
        .unwrap();
    let calls = Arc::new(CountLimits::default());
    let mut config = OrganizationConfig {
        membership_limit_callback: Some(calls.clone()),
        ..Default::default()
    };
    config.schema.member.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            required: Some(true),
            ..Default::default()
        },
    );
    config.schema.member.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            required: Some(true),
            ..Default::default()
        },
    );
    let plugin = OrganizationPlugin::with_config(config);
    let valid = AddMemberInput {
        user_id: user.id.into(),
        organization_id: organization.id.into(),
        role: RoleInput::One("member".into()).into(),
        team_id: Default::default(),
        additional_fields: json!({"label":"valid"}).as_object().unwrap().clone(),
    };
    for (input, message) in [
        (
            AddMemberInput {
                additional_fields: Default::default(),
                ..valid.clone()
            },
            "[body.label] Invalid input: expected string, received undefined",
        ),
        (
            AddMemberInput {
                role: RoleInput::Many(vec!["member".into()]).into(),
                ..valid.clone()
            },
            "[body.role] Invalid input: expected string, received array",
        ),
        (
            AddMemberInput {
                user_id: "missing-user".into(),
                additional_fields: Default::default(),
                ..valid.clone()
            },
            "[body.label] Invalid input: expected string, received undefined",
        ),
    ] {
        let response = plugin
            .add_member(input, None, &ctx)
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(response.status, 400);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!({
                "code":"VALIDATION_ERROR", "message":message
            })
        );
    }
    assert_eq!(calls.0.load(Ordering::SeqCst), 0);
    let member = plugin.add_member(valid, None, &ctx).await.unwrap();
    assert_eq!(member.role, "member");
    assert_eq!(calls.0.load(Ordering::SeqCst), 1);
}
