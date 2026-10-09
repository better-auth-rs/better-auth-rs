use super::*;
use crate::plugins::test_helpers;
use better_auth_core::config::AccountConfig;
use better_auth_core::wire::SessionView;
use better_auth_core::{CreateSession, CreateUser};
use chrono::{Duration, Utc};

#[tokio::test]
async fn invalid_sign_out_body_preserves_session_without_oauth_plugin() {
    let (ctx, _, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("logout-body@example.com")
            .with_name("Fixture"),
        Duration::hours(24),
    )
    .await;
    let plugin = SessionManagementPlugin::new();
    for body in [
        serde_json::json!({"disableRedirect": null}),
        serde_json::json!({"state": 5}),
    ] {
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-out",
            Some(session.token.typed().unwrap()),
            Some(body),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 400);
        let body: serde_json::Value =
            serde_json::from_slice(response.body.bytes().unwrap().as_ref()).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
        assert!(
            ctx.database
                .get_session(session.token.typed().unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn storage_failure_returns_500_and_disables_http_caching() {
    use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    use better_auth_seaorm::{Database, SeaOrmStore};
    use std::sync::Arc;

    let connection = Database::connect("sqlite::memory:").await.unwrap();
    let config = Arc::new(test_helpers::create_test_config());
    let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
        config.clone(),
        connection.clone(),
    ));
    let ctx = AuthContext::new(config, store);
    connection.close().await.unwrap();
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/get-session",
        Some("unavailable-store-token"),
        None,
    );
    let error = SessionManagementPlugin::new()
        .on_request(&req, &ctx)
        .await
        .unwrap_err();
    let mut response = error.to_auth_response();
    ctx.session_manager()
        .finish_response(&req, &mut response)
        .unwrap();
    assert_eq!(response.status, 500);
    assert_eq!(
        response.headers.get("Cache-Control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        response.headers.get("Pragma").map(String::as_str),
        Some("no-cache")
    );
    let body: serde_json::Value =
        serde_json::from_slice(response.body.bytes().unwrap().as_ref()).unwrap();
    assert_eq!(body["code"], "FAILED_TO_GET_SESSION");
    assert_eq!(body["message"], "Failed to get session");
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_get_session_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/get-session",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.handle_get_session(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(
        response_data["session"]["token"].as_str().unwrap(),
        session.token.typed().unwrap()
    );
    assert_eq!(
        response_data["user"]["email"]
            .as_str()
            .map(|s| s.to_string()),
        Some("test@example.com".to_string())
    );
}

#[tokio::test]
async fn get_session_preserves_numeric_key_user_relationships() -> AuthResult<()> {
    use better_auth_core::{
        store::{EphemeralStore, StatelessSchema},
        user_fields::{UserFieldConfig, UserFieldReference},
    };
    use std::sync::Arc;

    for count in [0, 1, 2] {
        let mut config = test_helpers::create_test_config();
        let _ = config.user.fields_mut().insert(
            "image".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "session".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let database = Arc::new(EphemeralStore::new(config.clone()));
        let ctx = AuthContext::<StatelessSchema>::new(config, database);
        let session = ctx
            .database
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                user_id: "canonical-owner".into(),
                expires_at: (Utc::now() + Duration::hours(24)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let mut expected_users = FieldMap::new();
        for index in 0..count {
            let mut input = CreateUser::new()
                .with_email(format!("selected-{index}@session.example.test"))
                .with_name(format!("Selected {index}"));
            input.image = Some(session.id.typed()?.clone()).into();
            let user = ctx.database.create_user(input).await?;
            let _ = expected_users.insert(index.to_string(), FieldMap::from(user).into());
        }
        let mut request = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some(session.token.typed()?),
            None,
        );
        request.query = Some(serde_json::json!({"disableRefresh": true}));
        let response = SessionManagementPlugin::new()
            .handle_get_session(&request, &ctx)
            .await?;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(response.body.bytes()?.as_ref())?;
        let snapshot = request
            .native_session_snapshot()?
            .ok_or_else(|| AuthError::internal("Expected native Session snapshot"))?;
        assert_eq!(snapshot.user, FieldValue::from(expected_users));
        assert_eq!(
            response.body.field_value()?,
            FieldValue::from(FieldMap::from(snapshot.clone()))
        );
        assert_eq!(body, serde_json::to_value(&snapshot)?);
        assert!(snapshot.user_field("id")?.is_undefined());
        assert!(matches!(
            request.session_snapshot(),
            Err(AuthError::Internal(message)) if message == "A User relationship array cannot authenticate a typed User"
        ));
        assert!(request.new_session()?.is_none());
        assert_eq!(
            ctx.database
                .get_session(session.token.typed()?)
                .await?
                .map(|stored| stored.expires_at),
            Some(session.expires_at),
        );
    }
    Ok(())
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_get_session_unauthorized() {
    // /get-session returns 200 with null body when unauthenticated.
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req =
        test_helpers::create_auth_request_no_query(HttpMethod::Get, "/get-session", None, None);
    let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value =
        serde_json::from_slice(response.body.bytes().unwrap().as_ref()).expect("valid JSON");
    assert!(body.is_null());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_sign_out_success() {
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(session.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let response = handle_sign_out(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: SuccessResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.success);

    let session_check = ctx
        .database
        .get_session(session.token.typed().unwrap())
        .await
        .unwrap();
    assert!(session_check.is_none());
}

#[tokio::test]
async fn test_sign_out_clears_account_cookie_when_enabled() {
    let config = test_helpers::create_test_config().account(AccountConfig {
        store_account_cookie: Some(true),
        ..Default::default()
    });
    let ctx = test_helpers::create_test_context_with_config(config).await;
    let (_user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(session.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let response = handle_sign_out(&req, &ctx).await.unwrap();

    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "sign-out should clear the account_data cookie when store_account_cookie is enabled"
    );
}

#[tokio::test]
async fn test_sign_out_does_not_emit_account_cookie_when_disabled() {
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(session.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let response = handle_sign_out(&req, &ctx).await.unwrap();

    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        !response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "sign-out should not emit account_data clearing cookies when store_account_cookie is disabled"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_list_sessions_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("another-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    ctx.database.create_session(create_session2).await.unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn test_list_sessions_filters_impersonated_sessions_when_admin_plugin_is_enabled() {
    let plugin = SessionManagementPlugin::new();
    let ctx = test_helpers::create_test_context_with_plugins(
        test_helpers::create_test_config(),
        &[&crate::plugins::admin::AdminPlugin::new()],
    )
    .await;
    let (user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let direct_session = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("another-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    ctx.database.create_session(direct_session).await.unwrap();

    let impersonated_session = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("10.0.0.5".to_string()),
        user_agent: Some("impersonated-agent".to_string()),
        impersonated_by: Some("admin-user".to_string()),
        active_organization_id: None,
    };
    let impersonated = ctx
        .database
        .create_session(impersonated_session)
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.token != impersonated.token),
        "impersonated sessions should not be returned from /list-sessions"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_session_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("another-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    let session2 = ctx.database.create_session(create_session2).await.unwrap();

    let body = serde_json::json!({ "token": session2.token });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(session.token.typed().unwrap()),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let session2_check = ctx
        .database
        .get_session(session2.token.typed().unwrap())
        .await
        .unwrap();
    assert!(session2_check.is_none());

    let session1_check = ctx
        .database
        .get_session(session.token.typed().unwrap())
        .await
        .unwrap();
    assert!(session1_check.is_some());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_session_forbidden_different_user() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user1, session1) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_user2 = CreateUser::new()
        .with_email("user2@example.com")
        .with_name("User Two");
    let user2 = ctx.database.create_user(create_user2).await.unwrap();

    let create_session2 = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user2.id,
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("another-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    let session2 = ctx.database.create_session(create_session2).await.unwrap();

    let body = serde_json::json!({ "token": session2.token });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(session1.token.typed().unwrap()),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value =
        serde_json::from_slice(response.body.bytes().unwrap().as_ref()).unwrap();
    assert_eq!(body["status"], true);

    let still_exists = ctx
        .database
        .get_session(session2.token.typed().unwrap())
        .await
        .unwrap();
    assert!(
        still_exists.is_some(),
        "other user's session must not be revoked"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_sessions_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session1) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("another-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    ctx.database.create_session(create_session2).await.unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-sessions",
        Some(session1.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let response = plugin.handle_revoke_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let user_sessions = ctx
        .database
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(user_sessions.len(), 0);
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_plugin_routes() {
    let plugin = SessionManagementPlugin::new();
    let routes = AuthPlugin::<
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
    >::routes(&plugin);

    assert_eq!(routes.len(), 8);
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
    );
    // Upstream serves `/get-session` on both methods.
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/get-session" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/sign-out" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/list-sessions" && r.method == HttpMethod::Get)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/revoke-session" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/revoke-sessions" && r.method == HttpMethod::Post)
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_plugin_on_request_routing() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    // Test valid route
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/get-session",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().status, 200);

    // POST /get-session is served, but rejected with 405 until
    // `session.defer_session_refresh` is enabled.
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/get-session",
        Some(session.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let err = plugin.on_request(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 405);

    // Test invalid route
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/invalid-route",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_configuration() {
    let plugin = SessionManagementPlugin::new()
        .enable_session_listing(false)
        .enable_session_revocation(false)
        .require_authentication(false);

    assert!(!plugin.config.enable_session_listing);
    assert!(!plugin.config.enable_session_revocation);
    assert!(!plugin.config.require_authentication);

    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_none());

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(session.token.typed().unwrap()),
        Some(b"{}".to_vec()),
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_none());
}
