#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use better_auth_core::{
    AuthInitContext, CreateMember, CreateOrganization, CreateOrganizationRole, FieldMap,
    FieldValue, SchemaValue, UpdateOrganizationRole,
    organization_fields::OrganizationFields,
    store::{EphemeralStore, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};

async fn check_organization_reference<S: better_auth_core::AuthSchema>(ctx: AuthContext<S>) {
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .build();
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone())
        .expect("fixture context initializes");
    better_auth_core::AuthPlugin::<S>::schema(&plugin, &mut model_fields).unwrap();
    plugin.on_init(&mut init).await.unwrap();
    model_fields
        .register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "referenceId".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            transform: Some(FieldTransforms {
                                input: None,
                                output: Some(UserFieldTransform::new(|_| Ok(41.0.into()))),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
        .unwrap();
    let organization_reference = UserConfig {
        additional_fields: Some(
            [(
                "organizationId".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    model_fields.register_organization_schema(
        &OrganizationFields {
            member: organization_reference.clone(),
            organization_role: organization_reference,
            ..Default::default()
        },
        false,
        true,
    );
    let database = ctx
        .database
        .with_runtime(ctx.config.clone(), Vec::new(), model_fields)
        .unwrap();
    use crate::plugins::organization::{
        METADATA_AC, METADATA_DYNAMIC_ACCESS_CONTROL, METADATA_ENABLED,
    };
    let ctx = AuthContext::with_metadata(
        ctx.config.clone(),
        database,
        HashMap::from([
            (METADATA_ENABLED.into(), serde_json::json!(true)),
            (
                METADATA_DYNAMIC_ACCESS_CONTROL.into(),
                serde_json::json!(true),
            ),
            (METADATA_AC.into(), serde_json::json!({"apiKey":["read"]})),
        ]),
    )
    .expect("fixture context initializes");
    let (user, session) = create_user_with_session(&ctx, "dynamic-owner@example.com").await;
    let mut organization = CreateOrganization::new("Machines", "machines");
    organization.id = Some("41".into());
    let _ = ctx
        .database
        .create_organization(organization)
        .await
        .unwrap();
    let member = ctx
        .database
        .create_member(CreateMember {
            additional_fields: Default::default(),
            organization_id: SchemaValue::from_field(41.0.into()),
            user_id: user.id.clone(),
            role: "machine-reader".into(),
        })
        .await
        .unwrap();
    let role = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            additional_fields: [("organizationId".into(), 41.0.into())].into(),
            organization_id: "41".into(),
            role: "machine-reader".into(),
            permission: FieldValue::from_json(serde_json::json!({"apiKey":["read"]})).unwrap(),
        })
        .await
        .unwrap();
    let created = super::super::handlers::create_key_for_user(
        &super::super::request::CapturedInput::new(
            &CreateKeyRequest::default(),
            &FieldValue::Undefined,
        )
        .unwrap(),
        &"41".into(),
        &ApiKeyPlugin::builder().build(),
        &ctx,
        ApiKeyEndpoint::new(&ctx, None, Some("/api-key/create"), &FieldMap::new().into()),
    )
    .await
    .unwrap();
    assert_eq!(created.api_key.reference_id.field_value(), 41.0.into());
    let request = create_auth_request(
        HttpMethod::Get,
        "/api-key/get",
        Some(session.token.typed().unwrap()),
        None,
        Some(HashMap::from([(
            "id".into(),
            created.api_key.id.typed().unwrap().clone(),
        )])),
    );
    let response = plugin.handle_get(&request, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(json_body(&response)["referenceId"], 41);

    for (permission, member_role, allowed) in [
        (serde_json::json!({"apiKey":[]}), "machine-reader", false),
        (serde_json::json!("invalid permissions"), "owner", false),
        (serde_json::json!({"apiKey":[]}), "owner", true),
        (serde_json::json!({"apiKey":[]}), " owner", false),
    ] {
        ctx.database
            .update_member_role(member.id.typed().unwrap(), member_role)
            .await
            .unwrap();
        ctx.database
            .update_organization_role(
                role.id.typed().unwrap(),
                UpdateOrganizationRole {
                    permission: Some(FieldValue::from_json(permission).unwrap()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        match plugin.handle_get(&request, &ctx).await {
            Ok(response) => {
                assert!(allowed, "{member_role}");
                assert_eq!(response.status, 200);
            }
            Err(error) => {
                assert!(!allowed, "{member_role}: {error}");
                crate::plugins::test_helpers::assert_coded_api_error(
                    &error,
                    "FORBIDDEN",
                    403,
                    "INSUFFICIENT_API_KEY_PERMISSIONS",
                    "You do not have permission to perform this action on organization API keys.",
                );
            }
        }
    }
}

#[tokio::test]
async fn memory_organization_key_uses_projected_reference_and_dynamic_roles() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let store = Arc::new(EphemeralStore::new(config.clone()));
    check_organization_reference(
        AuthContext::new(config, store).expect("fixture context initializes"),
    )
    .await;
}

#[tokio::test]
async fn sqlite_organization_key_uses_projected_reference_and_dynamic_roles() {
    check_organization_reference(crate::plugins::test_helpers::create_test_context().await).await;
}
