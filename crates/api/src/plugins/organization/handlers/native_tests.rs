use super::*;
use crate::plugins::organization::{OrganizationPlugin, types::*};
use crate::plugins::test_helpers;
use better_auth_core::{
    CreateMember, CreateOrganization, CreateSession, CreateUser, FieldMap, FieldValue, HttpMethod,
    SchemaValue,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    id::IdGeneration,
    session::NativeSessionData,
    store::{EphemeralStore, StatelessSchema},
};
use chrono::{Duration, Utc};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) async fn context(
    config: better_auth_core::AuthConfig,
    organization: &OrganizationConfig,
) -> AuthContext<StatelessSchema> {
    let config = Arc::new(config);
    test_helpers::initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[&OrganizationPlugin::with_config(organization.clone())],
    )
    .await
    .unwrap()
}

pub(super) async fn session(
    ctx: &AuthContext<StatelessSchema>,
    user: &better_auth_core::wire::UserView,
) -> NativeSessionData {
    let session = ctx
        .database
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    NativeSessionData {
        session,
        user: FieldMap::from(user.clone()).into(),
    }
}

#[tokio::test]
async fn native_read_routes_preserve_property_access_order_and_failed_membership_storage() {
    let config = OrganizationConfig::default();
    let ctx = context(test_helpers::create_test_config(), &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("native-org@example.test"))
        .await
        .unwrap();
    let mut data = session(&ctx, &user).await;
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Native", "native"))
        .await
        .unwrap();
    data.user = FieldValue::Null;
    assert!(matches!(
        get_active_member_core(&data, &ctx).await,
        Err(AuthError::BadRequest(message)) if message == "No active organization"
    ));
    assert!(
        get_full_organization_core(&GetFullOrganizationQuery::default(), &data, &config, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        get_full_organization_core(
            &GetFullOrganizationQuery {
                organization_id: Some("missing".into()),
                ..Default::default()
            },
            &data, &config, &ctx,
        ).await,
        Err(AuthError::BadRequest(message)) if message == "Organization not found"
    ));
    let active = organization.id.typed().unwrap();
    data.session = ctx
        .database
        .update_session_active_organization_by_token_value(
            &data.session.token.field_value(),
            Some(&organization.id.field_value()),
        )
        .await
        .unwrap();
    assert!(matches!(
        get_active_member_core(&data, &ctx).await,
        Err(AuthError::TypeError(message)) if message == "Cannot read properties of null (reading 'id')"
    ));
    assert_eq!(
        ctx.database
            .get_session_by_token_value(&data.session.token.field_value())
            .await
            .unwrap()
            .unwrap()
            .active_organization_id
            .field_value(),
        FieldValue::from(active.clone())
    );
    for primitive in [
        FieldValue::Bool(false),
        3.0.into(),
        Vec::<FieldValue>::new().into(),
    ] {
        data.user = primitive;
        assert!(
            list_organizations_core(&data, &ctx)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            get_active_member_core(&data, &ctx).await,
            Err(AuthError::BadRequest(message)) if message == "Member not found"
        ));
        assert!(matches!(
            get_full_organization_core(
                &GetFullOrganizationQuery::default(), &data, &config, &ctx
            ).await,
            Err(AuthError::Forbidden(message)) if message == "User is not a member of the organization"
        ));
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
    }
}

pub(super) fn numeric_output(enabled: Arc<AtomicBool>) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: None,
            output: Some(UserFieldTransform::new(move |value| {
                if !enabled.load(Ordering::SeqCst) {
                    return Ok(value);
                }
                if value.is_number() {
                    return Ok(value);
                }
                let number = value.as_str().unwrap().parse::<f64>().unwrap();
                Ok(FieldValue::Number(number))
            })),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn native_member_page_preserves_numeric_ids_and_strict_join_identity() {
    let numeric_users = Arc::new(AtomicBool::new(true));
    let mut auth = test_helpers::create_test_config();
    auth.advanced.database.generate_id = Some(IdGeneration::Serial);
    let _ = auth
        .user
        .fields_mut()
        .insert("id".into(), numeric_output(numeric_users.clone()));
    let mut config = OrganizationConfig::default();
    let _ = config.schema.member.fields_mut().insert(
        "userId".into(),
        UserFieldConfig {
            references: Some(better_auth_core::config::UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..numeric_output(Arc::new(AtomicBool::new(true)))
        },
    );
    let ctx = context(auth, &config).await;
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Native", "native"))
        .await
        .unwrap();
    let mut users = Vec::new();
    let mut members = Vec::new();
    for index in 1..=2 {
        let mut input = CreateUser::new()
            .with_email(format!("native-{index}@example.test"))
            .with_name(format!("Native {index}"));
        input.image = Some(format!("https://example.test/{index}.png")).into();
        let user = ctx.database.create_user(input).await.unwrap();
        assert_eq!(user.id.field_value(), FieldValue::Number(f64::from(index)));
        members.push(
            ctx.database
                .create_member(CreateMember {
                    additional_fields: Default::default(),
                    organization_id: organization.id.clone(),
                    user_id: user.id.clone(),
                    role: "owner".into(),
                })
                .await
                .unwrap(),
        );
        users.push(user);
    }
    let mut data = session(&ctx, &users[0]).await;
    data.session = ctx
        .database
        .update_session_active_organization_by_token_value(
            &data.session.token.field_value(),
            Some(&organization.id.field_value()),
        )
        .await
        .unwrap();
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/organization/list-members",
        Some(data.session.token.typed().unwrap()),
        None,
    );
    let response = handle_list_members(&request, &config, &ctx).await.unwrap();
    let expected = serde_json::json!({
        "members": members.iter().zip(&users).map(|(member, user)| {
            serde_json::json!({
                "id": member.id, "organizationId": member.organization_id,
                "userId": member.user_id, "role": member.role, "createdAt": member.created_at,
                "user": {"id": user.id, "name": user.name, "email": user.email, "image": user.image}
            })
        }).collect::<Vec<_>>(),
        "total": 2,
    });
    assert_eq!(response.body.json().unwrap(), Some(expected));
    let organizations = list_organizations_core(&data, &ctx).await.unwrap();
    assert_eq!(organizations.len(), 1);
    assert_eq!(organizations[0].id, organization.id);
    numeric_users.store(false, Ordering::SeqCst);
    assert!(matches!(
        list_members_core(&ListMembersQuery::default(), &config, &data, &ctx).await,
        Err(AuthError::Internal(message)) if message == "Unexpected error: User not found for member"
    ));
    assert_eq!(
        ctx.database
            .count_organization_members_value(&organization.id.field_value())
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn active_member_role_returns_native_values_and_empty_target_uses_requester() {
    for role in [
        FieldValue::Undefined,
        FieldValue::Null,
        7.0.into(),
        vec![FieldValue::from("owner")].into(),
    ] {
        let mut config = OrganizationConfig::default();
        let output = role.clone();
        let _ = config.schema.member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |_| Ok(output.clone()))),
                }),
                ..Default::default()
            },
        );
        let ctx = context(test_helpers::create_test_config(), &config).await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("role@example.test"))
            .await
            .unwrap();
        let organization = ctx
            .database
            .create_organization(CreateOrganization::new("Role", "role"))
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember::new(
                organization.id.typed().unwrap(),
                user.id.typed().unwrap(),
                "owner",
            ))
            .await
            .unwrap();
        let mut data = session(&ctx, &user).await;
        data.session.active_organization_id = Some(organization.id.typed().unwrap().clone()).into();
        let response = get_active_member_role_core(
            &GetActiveMemberRoleQuery {
                user_id: Some(String::new()),
                organization_slug: Some(String::new()),
                ..Default::default()
            },
            &data,
            &ctx,
        )
        .await
        .unwrap();
        assert!(response.role.field_value().strict_equals(&role));
        let expected = if role.is_undefined() {
            serde_json::json!({})
        } else {
            serde_json::json!({"role": SchemaValue::<String>::from_field(role)})
        };
        assert_eq!(serde_json::to_value(response).unwrap(), expected);
    }
}

#[tokio::test]
async fn native_invitation_reads_preserve_email_fallback_and_verification_order() {
    let config = OrganizationConfig::default();
    let ctx = context(test_helpers::create_test_config(), &config).await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("recipient@example.test"))
        .await
        .unwrap();
    let mut data = session(&ctx, &user).await;
    let organization = ctx
        .database
        .create_organization(CreateOrganization::new("Invites", "invites"))
        .await
        .unwrap();
    let invitation = ctx
        .database
        .create_invitation(better_auth_core::CreateInvitation::new(
            organization.id.typed().unwrap(),
            "recipient@example.test",
            "member",
            user.id.typed().unwrap(),
            (Utc::now() + Duration::hours(1)).into(),
        ))
        .await
        .unwrap();
    data.user = FieldValue::Null;
    assert!(
        get_invitation_core(
            &GetInvitationQuery {
                id: "missing".into()
            },
            &data,
            &config,
            &ctx
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        get_invitation_core(&GetInvitationQuery { id: invitation.id.typed().unwrap().clone() }, &data, &config, &ctx).await,
        Err(AuthError::TypeError(message)) if message == "Cannot read properties of null (reading 'email')"
    ));
    assert!(matches!(
        list_user_invitations_core(Some(&data), Some("recipient@example.test"), &ctx).await,
        Err(AuthError::TypeError(message)) if message == "Cannot read properties of null (reading 'emailVerified')"
    ));
    data.user = false.into();
    assert!(matches!(
        list_user_invitations_core(Some(&data), Some("recipient@example.test"), &ctx).await,
        Err(AuthError::Forbidden(message)) if message == "Email verification required to view or list invitations for the session email"
    ));
    assert!(matches!(
        list_user_invitations_core(None, None, &ctx).await,
        Err(AuthError::BadRequest(message)) if message == "Missing session headers, or email query parameter."
    ));
    let expected = serde_json::json!([{
        "id": invitation.id, "organizationId": invitation.organization_id,
        "email": invitation.email, "role": invitation.role, "status": invitation.status,
        "inviterId": invitation.inviter_id, "expiresAt": invitation.expires_at,
        "createdAt": invitation.created_at, "organizationName": organization.name,
    }]);
    for email in [FieldValue::Null, "".into(), false.into()] {
        data.user = FieldMap::from([
            ("email".into(), email),
            ("emailVerified".into(), Vec::<FieldValue>::new().into()),
        ])
        .into();
        let rows = list_user_invitations_core(Some(&data), Some("RECIPIENT@example.test"), &ctx)
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(rows).unwrap(), expected);
    }
    let rows = list_user_invitations_core(None, Some("RECIPIENT@example.test"), &ctx)
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(rows).unwrap(), expected);
    data.user = FieldMap::from([
        ("email".into(), 17.0.into()),
        ("emailVerified".into(), true.into()),
    ])
    .into();
    assert!(matches!(
        list_user_invitations_core(Some(&data), None, &ctx).await,
        Err(AuthError::TypeError(message)) if message == "user.email.toLowerCase is not a function"
    ));
    let mut request = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/organization/list-user-invitations",
        Some(data.session.token.typed().unwrap()),
        None,
    );
    request.query = Some(serde_json::json!({"email": "recipient@example.test"}));
    assert!(matches!(
        handle_list_user_invitations(&request, &ctx).await,
        Err(AuthError::BadRequest(message)) if message == "User email cannot be passed for client side API calls."
    ));
    assert_eq!(
        ctx.database
            .list_organization_invitations_value(&organization.id.field_value())
            .await
            .unwrap()
            .len(),
        1
    );
}
