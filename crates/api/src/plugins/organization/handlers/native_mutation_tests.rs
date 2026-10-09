use super::native_tests::{context, numeric_output, session};
use super::*;
use crate::plugins::organization::{
    AddMemberInput, OrganizationPlugin, OrganizationTeamsConfig, hooks::*, types::*,
};
use crate::plugins::test_helpers;
use better_auth_core::{
    CreateMember, CreateOrganization, CreateTeam, CreateUser, FieldMap, FieldValue, HttpMethod,
    config::{CookieCacheConfig, CookieCacheVersion, UserFieldConfig, UserFieldReference},
    id::IdGeneration,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct DenyCreation(Mutex<Vec<FieldValue>>);

#[async_trait::async_trait]
impl OrganizationPolicy for DenyCreation {
    async fn allow_user_to_create_organization(
        &self,
        user: &FieldValue,
    ) -> AuthResult<Option<bool>> {
        self.0.lock().unwrap().push(user.clone());
        Ok(Some(false))
    }
}

#[tokio::test]
async fn creation_policy_observes_native_user_and_falsy_session_user_uses_body_subject() {
    let policy = Arc::new(DenyCreation::default());
    let config = OrganizationConfig {
        policy: Some(policy.clone()),
        ..Default::default()
    };
    let ctx = context(test_helpers::create_test_config(), &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("org-policy@example.test"))
        .await
        .unwrap();
    let mut data = session(&ctx, &user).await;
    for raw in [
        FieldValue::Bool(true),
        vec![FieldValue::from("relationship")].into(),
        FieldValue::Null,
        false.into(),
    ] {
        data.user = raw.clone();
        let body = serde_json::from_value(
            serde_json::json!({"name":"Policy", "slug":"policy", "userId":user.id}),
        )
        .unwrap();
        assert!(matches!(
            create_organization_core(&body, Some(&data), &config, &ctx, None).await,
            Err(AuthError::Upstream {
                code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
                ..
            })
        ));
        let observed = policy.0.lock().unwrap().pop().unwrap();
        if raw.is_truthy() {
            assert!(observed.strict_equals(&raw));
        } else {
            assert_eq!(
                observed.json().unwrap(),
                FieldValue::from(FieldMap::from(user.clone()))
                    .json()
                    .unwrap()
            );
        }
        assert!(
            ctx.database
                .get_organization_by_slug("policy")
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[derive(Default)]
struct MutationHooks {
    expected: Mutex<Option<FieldValue>>,
    events: Mutex<Vec<&'static str>>,
    fail_update: AtomicBool,
    fail_delete: AtomicBool,
}
impl MutationHooks {
    fn record(&self, phase: &'static str, user: &FieldValue) {
        assert!(user.strict_equals(self.expected.lock().unwrap().as_ref().unwrap()));
        self.events.lock().unwrap().push(phase);
    }
}
#[async_trait::async_trait]
impl OrganizationHooks for MutationHooks {
    async fn before_update_organization(
        &self,
        _: &mut better_auth_core::UpdateOrganization,
        actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.record("before-update", actor.user);
        Ok(())
    }
    async fn after_update_organization(
        &self,
        _: &OrganizationResponse,
        actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.record("after-update", actor.user);
        if self.fail_update.load(Ordering::SeqCst) {
            return Err(AuthError::internal("after-update failure"));
        }
        Ok(())
    }
    async fn before_delete_organization(
        &self,
        event: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record("before-delete", event.user);
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(AuthError::internal("before-delete failure"));
        }
        Ok(())
    }
    async fn after_delete_organization(
        &self,
        event: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record("after-delete", event.user);
        Ok(())
    }
}

#[tokio::test]
async fn mutation_hooks_keep_session_user_identity_and_committed_failure_effects() {
    let hooks = Arc::new(MutationHooks::default());
    let config = OrganizationConfig {
        hooks: Some(hooks.clone()),
        ..Default::default()
    };
    let ctx = context(test_helpers::create_test_config(), &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("org-mutation@example.test"))
        .await
        .unwrap();
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Before", "mutation"))
        .await
        .unwrap();
    let _ = ctx
        .database
        .create_member(CreateMember {
            organization_id: organization.id.clone(),
            user_id: user.id.clone(),
            role: "owner".into(),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    let mut data = session(&ctx, &user).await;
    let marker: FieldValue = vec![FieldValue::from("same-object")].into();
    let mut fields = FieldMap::from(user.clone());
    let _ = fields.insert("marker".into(), marker);
    data.user = fields.into();
    *hooks.expected.lock().unwrap() = Some(data.user.clone());
    data.session = ctx
        .database
        .update_session_active_organization_by_token_value(
            &data.session.token.field_value(),
            Some(&organization.id.field_value()),
        )
        .await
        .unwrap();
    hooks.fail_update.store(true, Ordering::SeqCst);
    let update: UpdateOrganizationRequest =
        serde_json::from_value(serde_json::json!({"data":{"name":"After"}})).unwrap();
    assert!(
        update_organization_core(&update, &data, &config, &ctx)
            .await
            .is_err()
    );
    let stored = ctx
        .database
        .get_organization_by_id_value(&organization.id.field_value())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.name.field_value(), FieldValue::from("After"));
    hooks.fail_delete.store(true, Ordering::SeqCst);
    let delete = DeleteOrganizationRequest {
        organization_id: organization.id.typed().unwrap().clone(),
    };
    assert!(
        delete_organization_core(&delete, &data, None, &config, &ctx)
            .await
            .is_err()
    );
    assert!(
        ctx.database
            .get_organization_by_id_value(&organization.id.field_value())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        ctx.database
            .get_session_by_token_value(&data.session.token.field_value())
            .await
            .unwrap()
            .unwrap()
            .active_organization_id
            .field_value(),
        FieldValue::Null
    );
    hooks.fail_delete.store(false, Ordering::SeqCst);
    let deleted = delete_organization_core(&delete, &data, None, &config, &ctx)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(deleted).unwrap(),
        serde_json::to_value(crate::plugins::organization::fields::organization(
            &stored, &ctx
        ))
        .unwrap()
    );
    assert!(
        ctx.database
            .get_organization_by_id_value(&organization.id.field_value())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        [
            "before-update",
            "after-update",
            "before-delete",
            "before-delete",
            "after-delete"
        ]
    );
}

#[tokio::test]
async fn clearing_active_context_keeps_native_user_in_cookie_callbacks() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let capture = observed.clone();
    let mut auth = test_helpers::create_test_config();
    auth.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        version: CookieCacheVersion::dynamic(move |data| {
            let capture = capture.clone();
            async move {
                capture.lock().unwrap().push(data.user);
                Ok("native-organization".into())
            }
        }),
        ..Default::default()
    });
    let config = OrganizationConfig {
        teams: OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let ctx = context(auth, &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("org-cookie@example.test"))
        .await
        .unwrap();
    let mut data = session(&ctx, &user).await;
    for raw in [
        FieldValue::Null,
        false.into(),
        vec![FieldValue::from("relationship")].into(),
    ] {
        data.user = raw.clone();
        data.session = ctx
            .database
            .update_session_active_organization_by_token_value(
                &data.session.token.field_value(),
                Some(&"active".into()),
            )
            .await
            .unwrap();
        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/set-active",
            None,
            Some(serde_json::json!({"organizationId":null})),
        );
        let response = set_active_organization_core(
            &request,
            &SetActiveOrganizationRequest {
                organization_id: NullableStringField::Null,
                organization_slug: None,
            },
            &data,
            &ctx,
        )
        .await
        .unwrap();
        assert!(response.is_none());
        assert!(observed.lock().unwrap().pop().unwrap().strict_equals(&raw));
        assert!(
            request
                .new_session()
                .unwrap()
                .unwrap()
                .user
                .strict_equals(&raw)
        );
        let stored = ctx
            .database
            .get_session_by_token_value(&data.session.token.field_value())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.active_organization_id.field_value(),
            FieldValue::Null
        );
    }
}

#[tokio::test]
async fn trusted_member_capacity_failure_cleans_up_native_identifiers() {
    let mut auth = test_helpers::create_test_config();
    auth.advanced.database.generate_id = Some(IdGeneration::Serial);
    let _ = auth
        .user
        .fields_mut()
        .insert("id".into(), numeric_output(Arc::new(AtomicBool::new(true))));
    let mut config = OrganizationConfig {
        teams: OrganizationTeamsConfig {
            enabled: true,
            maximum_members_per_team: Some(0),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = config.schema.member.fields_mut().insert(
        "userId".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..numeric_output(Arc::new(AtomicBool::new(true)))
        },
    );
    let ctx = context(auth, &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("org-capacity@example.test"))
        .await
        .unwrap();
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Capacity", "capacity"))
        .await
        .unwrap();
    let team = ctx
        .database
        .create_team(CreateTeam {
            name: "Full".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let result = OrganizationPlugin::with_config(config)
        .add_member(
            AddMemberInput {
                additional_fields: Default::default(),
                user_id: user.id.display_string().unwrap().into(),
                organization_id: organization.id.clone(),
                role: RoleInput::One("member".into()).into(),
                team_id: team.id.display_string().unwrap().into(),
            },
            None,
            &ctx,
        )
        .await;
    assert!(
        matches!(
            &result,
            Err(AuthError::Upstream {
                code: "TEAM_MEMBER_LIMIT_REACHED",
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        ctx.database
            .count_organization_members_value(&organization.id.field_value())
            .await
            .unwrap(),
        0
    );
    assert!(
        ctx.database
            .get_member_value(&organization.id.field_value(), &user.id.field_value())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .list_team_members_value(&team.id.field_value())
            .await
            .unwrap()
            .is_empty()
    );
}
