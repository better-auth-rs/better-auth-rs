use super::*;
use better_auth_core::{CreateMember, CreateOrganization, SchemaValue};

async fn check_organization_actor<S: AuthSchema>(ctx: AuthContext<S>) {
    let (mut ctx, _, sessions, _, callbacks) = harness(ctx, false).await;
    let _ = ctx.metadata.insert(
        crate::plugins::organization::METADATA_ENABLED.into(),
        json!(true),
    );
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .enable_metadata(true)
        .default_permissions_callback(Arc::new(Permissions(callbacks.clone())))
        .build();
    let mut user = CreateUser::new()
        .with_email("member@native-actor.test")
        .with_name("Member");
    user.id = Some("7".into());
    let _ = ctx.database.create_user(user).await.unwrap();
    let mut organization = CreateOrganization::new("Machines", "machines");
    organization.id = Some("machine-org".into());
    let _ = ctx
        .database
        .create_organization(organization)
        .await
        .unwrap();
    let _ = ctx
        .database
        .create_member(CreateMember {
            additional_fields: Default::default(),
            organization_id: "machine-org".into(),
            user_id: SchemaValue::from_field(7.0.into()),
            role: "owner".into(),
        })
        .await
        .unwrap();
    actor(&sessions, Some(&json!(7))).await;
    let metadata = &cases()["metadata"];
    let created = json_body(
        &plugin
            .handle_create(
                &request(
                    HttpMethod::Post,
                    "/api-key/create",
                    Some(json!({"organizationId": "machine-org", "metadata": metadata})),
                    None,
                ),
                &ctx,
            )
            .await
            .unwrap(),
    );
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["referenceId"], "machine-org");
    assert_eq!(
        *callbacks.lock().unwrap(),
        vec![json!(["machine-org", metadata, 0])]
    );
    assert_eq!(
        json_body(
            &plugin
                .handle_get(
                    &request(
                        HttpMethod::Get,
                        "/api-key/get",
                        None,
                        Some(json!({"id": id}))
                    ),
                    &ctx
                )
                .await
                .unwrap()
        )["id"],
        id
    );
    let listed = json_body(
        &plugin
            .handle_list(
                &request(
                    HttpMethod::Get,
                    "/api-key/list",
                    None,
                    Some(json!({"organizationId": "machine-org"})),
                ),
                &ctx,
            )
            .await
            .unwrap(),
    );
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["apiKeys"][0]["id"], id);
    actor(&sessions, Some(&json!(8))).await;
    for result in [
        plugin
            .handle_get(
                &request(
                    HttpMethod::Get,
                    "/api-key/get",
                    None,
                    Some(json!({"id": id})),
                ),
                &ctx,
            )
            .await,
        plugin
            .handle_update(
                &request(
                    HttpMethod::Post,
                    "/api-key/update",
                    Some(json!({"keyId": id, "name": "Unauthorized"})),
                    None,
                ),
                &ctx,
            )
            .await,
        plugin
            .handle_delete(
                &request(
                    HttpMethod::Post,
                    "/api-key/delete",
                    Some(json!({"keyId": id})),
                    None,
                ),
                &ctx,
            )
            .await,
        plugin
            .handle_list(
                &request(
                    HttpMethod::Get,
                    "/api-key/list",
                    None,
                    Some(json!({"organizationId": "machine-org"})),
                ),
                &ctx,
            )
            .await,
    ] {
        let error = result.unwrap_err();
        assert_eq!(error.status_code(), 403);
        assert_eq!(
            json_body(&error.to_auth_response())["code"],
            "USER_NOT_MEMBER_OF_ORGANIZATION"
        );
    }
    actor(&sessions, Some(&json!(7))).await;
    assert_eq!(
        json_body(
            &plugin
                .handle_update(
                    &request(
                        HttpMethod::Post,
                        "/api-key/update",
                        Some(json!({"keyId": id, "name": "Updated"})),
                        None
                    ),
                    &ctx
                )
                .await
                .unwrap()
        )["name"],
        "Updated"
    );
    assert_eq!(
        json_body(
            &plugin
                .handle_delete(
                    &request(
                        HttpMethod::Post,
                        "/api-key/delete",
                        Some(json!({"keyId": id})),
                        None
                    ),
                    &ctx
                )
                .await
                .unwrap()
        ),
        json!({"success": true})
    );
}

#[tokio::test]
async fn memory_organization_api_keys_query_membership_with_native_actor() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    check_organization_actor(AuthContext::new(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
    ))
    .await;
}

#[tokio::test]
async fn sqlite_organization_api_keys_query_membership_with_native_actor() {
    check_organization_actor(crate::plugins::test_helpers::create_test_context().await).await;
}
