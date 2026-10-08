use super::*;
use better_auth_core::{AuthConfig, CreateSession, CreateUser, HttpMethod};
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn context() -> (AuthContext<TestSchema>, String, String) {
    let database = crate::plugins::test_helpers::create_test_database().await;
    let user = database
        .create_user(
            CreateUser::new()
                .with_email("crud@example.com")
                .with_name("CRUD user"),
        )
        .await
        .unwrap();
    let user_id = user.id().into_owned();
    let session = database
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user_id.clone(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let token = better_auth_core::entity::AuthSession::token(&session)
        .typed()
        .unwrap()
        .to_string();
    let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
    config.session.bearer = Some(Default::default());
    (
        AuthContext::new(Arc::new(config), database),
        user_id.typed().unwrap().clone(),
        token,
    )
}

fn request(token: &str, path: &str, body: serde_json::Value) -> AuthRequest {
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        path.to_string(),
        HashMap::from([("authorization".to_string(), format!("Bearer {token}"))]),
        Some(serde_json::to_vec(&body).unwrap()),
        None,
    );
    request.clone().with_original_request(request)
}

async fn server_key(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<TestSchema>,
    user_id: &str,
    config_id: &str,
) -> CreateKeyResponse {
    plugin
        .create_key(
            ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.to_string()),
                config_id: Some(config_id.to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn list_without_configuration_includes_all_user_configurations() {
    let (ctx, user_id, _) = context().await;
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "secondary".to_string(),
        ..Default::default()
    });
    server_key(&plugin, &ctx, &user_id, "default").await;
    server_key(&plugin, &ctx, &user_id, "secondary").await;
    let list = list_keys_core(&user_id, &ListKeysQuery::default(), &plugin, &ctx)
        .await
        .unwrap();
    assert_eq!(list.total, 2);
    let list = list_keys_core(
        &user_id,
        &ListKeysQuery {
            config_id: Some("secondary".to_string()),
            ..Default::default()
        },
        &plugin,
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(list.total, 1);
    assert_eq!(list.api_keys[0].config_id, "secondary");
    let list = list_keys_core(
        &user_id,
        &ListKeysQuery {
            config_id: Some("missing".to_string()),
            ..Default::default()
        },
        &plugin,
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(list.total, 0);

    let no_default = ApiKeyPlugin::builder()
        .config_id("secondary".to_string())
        .build();
    assert_eq!(
        list_keys_core(&user_id, &ListKeysQuery::default(), &no_default, &ctx)
            .await
            .unwrap()
            .total,
        2
    );
}

#[tokio::test]
async fn http_requests_cannot_impersonate_users_or_change_server_permissions() {
    let (ctx, user_id, token) = context().await;
    let plugin = ApiKeyPlugin::builder().build();
    let create = request(&token, "/api-key/create", json!({"userId":user_id}));
    assert_eq!(
        plugin
            .handle_create(&create, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let key = server_key(&plugin, &ctx, &user_id, "default").await;
    let update = request(
        &token,
        "/api-key/update",
        json!({"keyId":key.api_key.id,"userId":"someone-else","enabled":false}),
    );
    assert_eq!(
        plugin
            .handle_update(&update, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let update = request(
        &token,
        "/api-key/update",
        json!({"keyId":key.api_key.id,"permissions":null}),
    );
    assert_eq!(
        plugin
            .handle_update(&update, &ctx)
            .await
            .unwrap_err()
            .to_string(),
        ApiKeyErrorCode::ServerOnlyProperty.message()
    );
    let update = request(&token, "/api-key/update", json!({"keyId":"missing"}));
    assert_eq!(
        plugin
            .handle_update(&update, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        404
    );
}

#[tokio::test]
async fn metadata_can_be_cleared_and_disabled_metadata_is_ignored_on_update() {
    let (ctx, user_id, token) = context().await;
    let enabled = ApiKeyPlugin::builder().enable_metadata(true).build();
    let key = enabled
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.clone()),
                metadata: Some(json!(["initial"])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        key.api_key.metadata.json().unwrap(),
        Some(json!(["initial"]))
    );
    let update = request(
        &token,
        "/api-key/update",
        json!({"keyId":key.api_key.id,"metadata":null}),
    );
    let response = enabled.handle_update(&update, &ctx).await.unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap()["metadata"].is_null()
    );
    let disabled = ApiKeyPlugin::builder().build();
    let update = request(
        &token,
        "/api-key/update",
        json!({"keyId":key.api_key.id,"metadata":{"ignored":true},"enabled":false}),
    );
    let response = disabled.handle_update(&update, &ctx).await.unwrap();
    let result: serde_json::Value =
        serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert!(result["metadata"].is_null());
    assert_eq!(result["enabled"], false);
    let update = request(
        &token,
        "/api-key/update",
        json!({"keyId":key.api_key.id,"metadata":null}),
    );
    assert_eq!(
        disabled
            .handle_update(&update, &ctx)
            .await
            .unwrap_err()
            .to_string(),
        ApiKeyErrorCode::NoValuesToUpdate.message()
    );
}

#[tokio::test]
async fn trusted_creation_and_update_preserve_permissions_and_fractional_expiration() {
    let (ctx, user_id, _) = context().await;
    let plugin = ApiKeyPlugin::builder()
        .key_expiration(KeyExpirationConfig {
            min_expires_in: 0.0,
            ..Default::default()
        })
        .build();
    let before = Utc::now();
    let key = plugin
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.clone()),
                expires_in: Some(86400.25),
                remaining: Some(3.0),
                permissions: Some(HashMap::from([(
                    "device".to_string(),
                    vec!["read".to_string()],
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(key.api_key.remaining, Some(3.0));
    assert_eq!(
        key.api_key.permissions.json().unwrap(),
        Some(json!({"device":["read"]}))
    );
    let expires_at = key
        .api_key
        .expires_at
        .typed()
        .unwrap()
        .as_ref()
        .unwrap()
        .to_datetime()
        .unwrap()
        .unwrap();
    assert!((expires_at - before).num_milliseconds() >= 86_400_249);
    assert!((expires_at - Utc::now()).num_milliseconds() <= 86_400_250);
    let updated = plugin
        .update_key(
            &ctx,
            &UpdateKeyRequest {
                key_id: key.api_key.id.typed().unwrap().clone(),
                user_id: Some(user_id),
                remaining: Some(5.0),
                permissions: Some(None),
                expires_in: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.remaining, Some(5.0));
    assert_eq!(
        updated.permissions.json().unwrap(),
        Some(serde_json::Value::Null)
    );
    assert_eq!(updated.expires_at, None);
    let stored = ctx
        .database
        .get_api_key_by_id(key.api_key.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.key_hash, key.key);
}

#[tokio::test]
async fn list_rejects_invalid_pagination_instead_of_ignoring_it() {
    let (ctx, _, token) = context().await;
    let plugin = ApiKeyPlugin::builder().build();
    let route = <ApiKeyPlugin as better_auth_core::AuthPlugin<TestSchema>>::routes(&plugin)
        .into_iter()
        .find(|route| route.path == "/api-key/list")
        .unwrap();
    let validate = route.query_validator.unwrap();
    for (field, value) in [
        ("limit", "-1"),
        ("offset", "1.5"),
        ("limit", "bad"),
        ("sortDirection", "sideways"),
    ] {
        let mut req = request(&token, "/api-key/list", json!({}));
        req.query
            .get_or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .insert(
                field.to_string(),
                serde_json::Value::from(value.to_string()),
            );
        let response = match validate(req.query.clone()) {
            Ok(query) => {
                req.query = query;
                plugin.handle_list(&req, &ctx).await.unwrap()
            }
            Err(error) => error.to_auth_response(),
        };
        assert_eq!(response.status, 400);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap()["code"],
            "VALIDATION_ERROR"
        );
    }
}
