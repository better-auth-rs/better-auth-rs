use super::*;

// =======================================================================
// Comprehensive integration tests (9 scenarios from the test plan)
// =======================================================================

#[tokio::test]
async fn test_virtual_session_answers_get_and_post_get_session() {
    use better_auth_core::AuthPlugin;

    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, session) = create_test_context_with_user().await;
    let (id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "get-session" }),
    )
    .await;

    for method in [HttpMethod::Get, HttpMethod::Post] {
        let mut request = create_auth_request(method, "/get-session", None, None, None);
        let _ = request
            .headers
            .insert("x-api-key".to_string(), raw_key.clone());
        let action = AuthPlugin::<TestSchema>::before_request(&plugin, &request, &ctx)
            .await
            .unwrap();
        let Some(BeforeRequestAction::Respond(response)) = action else {
            panic!("API key sessions must answer GET and POST before route dispatch")
        };
        assert_eq!(response.status, 200);
        let body = json_body(&response);
        assert_eq!(body["session"]["id"], id);
        assert_eq!(body["session"]["token"], raw_key);
        assert_eq!(body["session"]["userId"], user.id.typed().unwrap().as_str());
    }
}

// 1. Virtual session: before_request injects session without DB writes
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_virtual_session_creates_no_db_session() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Create an API key
    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "virtual-session-test" }),
    )
    .await;

    // Count sessions before
    let sessions_before = ctx
        .database
        .get_user_sessions(_user.id.typed().unwrap())
        .await
        .unwrap()
        .len();

    // Simulate a request to a protected route with only x-api-key header
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key.clone());
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/update-user".to_string(),
        headers,
        None,
        None,
    );

    // Call before_request -- should return InjectSession
    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(action.is_some(), "before_request should return an action");
    match action.unwrap() {
        BeforeRequestAction::InjectSession { session } => {
            assert_eq!(session.user_id, _user.id);
        }
        BeforeRequestAction::Respond(_) => {
            panic!("Expected InjectSession, got Respond");
        }
        BeforeRequestAction::ReplaceBody(_) | BeforeRequestAction::MergeContext(_) => {
            panic!("Expected InjectSession, got ReplaceBody");
        }
    }

    // Count sessions after -- should be unchanged (no DB writes)
    let sessions_after = ctx
        .database
        .get_user_sessions(_user.id.typed().unwrap())
        .await
        .unwrap()
        .len();
    assert_eq!(
        sessions_before, sessions_after,
        "No new sessions should be created in the database"
    );
}

// 2. Virtual session on /get-session: synthetic response
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_virtual_session_on_get_session() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "get-session-test" }),
    )
    .await;

    // Send request to /get-session with x-api-key header
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key.clone());
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_string(),
        headers,
        None,
        None,
    );

    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(action.is_some());
    match action.unwrap() {
        BeforeRequestAction::Respond(resp) => {
            assert_eq!(resp.status, 200);
            let body: serde_json::Value =
                serde_json::from_slice(&resp.body.bytes().unwrap()).unwrap();
            // Should contain user data
            assert_eq!(body["user"]["id"], user.id.typed().unwrap().as_str());
            assert_eq!(body["user"]["email"], "test@example.com");
            // Should contain session-like data
            assert!(body["session"]["id"].is_string());
            assert_eq!(body["session"]["userId"], user.id.typed().unwrap().as_str());
        }
        BeforeRequestAction::InjectSession { .. } => {
            panic!("Expected Respond for /get-session, got InjectSession");
        }
        BeforeRequestAction::ReplaceBody(_) | BeforeRequestAction::MergeContext(_) => {
            panic!("Expected Respond for /get-session, got ReplaceBody");
        }
    }
}

// 3. Rate limiting: create key with rateLimitMax=2, 3rd call fails
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_rate_limiting_third_call_fails() {
    let plugin = ApiKeyPlugin::builder()
        .rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000.0,
            max_requests: 2.0,
        })
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "rl-integration" }),
        UpdateApiKey {
            rate_limit_enabled: Some(true),
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(2.0),
            ..Default::default()
        },
    )
    .await;

    // First two pass
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true, "1st request should pass");

    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true, "2nd request should pass");

    // Third should fail
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false, "3rd request should be rate-limited");
    assert_eq!(r3["error"]["code"], "RATE_LIMITED");
}

// 4. Remaining consumption: remaining=2, no refill, 3rd fails
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_remaining_consumption_no_refill() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "remaining-test" }),
        UpdateApiKey {
            remaining: Some(2.0),
            ..Default::default()
        },
    )
    .await;

    // 1st: remaining 2->1
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);
    assert_eq!(r1["key"]["remaining"], 1);

    // 2nd: remaining 1->0
    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true);
    assert_eq!(r2["key"]["remaining"], 0);

    // 3rd: usage exceeded
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false);
    assert_eq!(r3["error"]["code"], "USAGE_EXCEEDED");
}

// 5. Refill logic: remaining=1, refillInterval=100ms, refillAmount=10,
//    verify once -> remaining=0, wait 150ms, verify -> refill to 10 then
//    decrement to 9.
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_refill_resets_remaining_after_interval() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Use a very short refill interval for testing (100 ms)
    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "refill-test" }),
        UpdateApiKey {
            remaining: Some(1.0),
            refill_interval: Some(100.0),
            refill_amount: Some(10.0),
            ..Default::default()
        },
    )
    .await;

    // First verify: remaining 1->0
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);
    assert_eq!(r1["key"]["remaining"], 0);

    // Wait for refill interval to elapse
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Second verify: should refill to 10 and then decrement -> 9
    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true, "Should succeed after refill");
    assert_eq!(r2["key"]["remaining"], 9, "Should be refillAmount - 1 = 9");
}

// 6. Permissions: key with {"admin": ["read"]}, verify with
//    {"admin": ["write"]} should fail
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_permissions_mismatch_fails() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "perm-mismatch" }),
        UpdateApiKey {
            permissions: Some(
                serde_json::to_string(&serde_json::json!({ "admin": ["read"] })).unwrap(),
            ),
            ..Default::default()
        },
    )
    .await;

    // Verify with matching permission -> pass
    let perms_ok = serde_json::json!({ "admin": ["read"] });
    let r1 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_ok)).await;
    assert_eq!(r1["valid"], true);

    // Verify with mismatched permission -> fail
    let perms_fail = serde_json::json!({ "admin": ["write"] });
    let r2 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_fail)).await;
    assert_eq!(r2["valid"], false);
}

// 7. Concurrent rate limiting: send 5 sequential verify requests with
//    rateLimitMax=2, only first 2 succeed (sequential proves logic is
//    correct; true concurrency race conditions are documented above).
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_concurrent_rate_limiting() {
    let plugin = ApiKeyPlugin::builder()
        .rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000.0,
            max_requests: 2.0,
        })
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "concurrent-rl" }),
        UpdateApiKey {
            rate_limit_enabled: Some(true),
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(2.0),
            ..Default::default()
        },
    )
    .await;

    let mut success_count = 0;
    let mut fail_count = 0;

    for _ in 0..5 {
        let body = verify_key(&plugin, &ctx, &raw_key, None).await;
        if body["valid"] == true {
            success_count += 1;
        } else {
            fail_count += 1;
            assert_eq!(body["error"]["code"], "RATE_LIMITED");
        }
    }

    assert_eq!(success_count, 2, "Only 2 out of 5 should succeed");
    assert_eq!(fail_count, 3, "3 out of 5 should be rate-limited");
}

// 8. Database compatibility: test delete_expired_api_keys through the
//    in-repo auth store implementation.
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_delete_expired_api_keys_memory_adapter() {
    let (ctx, _user, session) = create_test_context_with_user().await;
    let plugin = ApiKeyPlugin::builder().build();

    // Create two keys
    let (id1, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "will-expire" }),
    )
    .await;
    let (_id2, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "wont-expire" }),
    )
    .await;

    // Expire the first key by setting expires_at to the past
    let past = better_auth_core::FieldDate::from(Utc::now() - Duration::hours(1));
    ctx.database
        .update_api_key(
            &id1.clone().into(),
            UpdateApiKey {
                expires_at: Some(Some(past)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Delete expired keys
    let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
    assert_eq!(deleted, 1, "Should delete exactly 1 expired key");

    // Verify only the non-expired key remains
    let remaining = ctx
        .database
        .list_api_keys_by_reference(_user.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
}

// 9. Delete expired: calling the store function directly removes only expired keys
#[tokio::test]
async fn test_delete_expired_removes_only_expired() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Create two keys, expire one
    let (id1, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "expired" }),
    )
    .await;
    let (_id2, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "active" }),
    )
    .await;

    let past = better_auth_core::FieldDate::from(Utc::now() - Duration::hours(1));
    ctx.database
        .update_api_key(
            &id1.clone().into(),
            UpdateApiKey {
                expires_at: Some(Some(past)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
    assert_eq!(deleted, 1);

    let remaining = ctx
        .database
        .list_api_keys_by_reference(_user.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
}

// 10. before_request returns None when enableSessionForAPIKeys is false
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_before_request_disabled_returns_none() {
    let plugin = ApiKeyPlugin::builder().build(); // enable_session_for_api_keys defaults to false
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        session.token.typed().unwrap(),
        serde_json::json!({ "name": "disabled-session" }),
    )
    .await;

    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key);
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_string(),
        headers,
        None,
        None,
    );

    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(
        action.is_none(),
        "before_request should return None when session emulation is disabled"
    );
}

// Upstream reference: @better-auth/api-key :: resolveConfiguration — an absent
// or unknown configId falls back to the default configuration.
#[tokio::test]
async fn test_resolve_configuration_falls_back_to_default() {
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "billing".to_string(),
        ..ApiKeyConfig::default()
    });

    assert_eq!(
        plugin.resolve_configuration(None).unwrap().config_id,
        "default"
    );
    assert_eq!(
        plugin
            .resolve_configuration(Some("billing"))
            .unwrap()
            .config_id,
        "billing"
    );
    // Unknown ids fall back rather than erroring.
    assert_eq!(
        plugin
            .resolve_configuration(Some("nope"))
            .unwrap()
            .config_id,
        "default"
    );
}

// Upstream reference: @better-auth/api-key :: resolveConfiguration errors when
// no configuration is registered as the default.
#[tokio::test]
async fn test_resolve_configuration_without_default_is_an_error() {
    let plugin = ApiKeyPlugin::builder()
        .config_id("billing".to_string())
        .build();

    let err = plugin.resolve_configuration(None).unwrap_err();
    assert_eq!(err.status_code(), 400);
    assert_eq!(err.to_string(), "No default api-key configuration found.");
}

// Upstream reference: @better-auth/api-key :: configIdMatches treats a missing
// configId as the default, for keys written before the column existed.
#[tokio::test]
async fn test_config_id_matches_treats_missing_as_default() {
    assert!(super::config_id_matches(&"".into(), "default"));
    assert!(super::config_id_matches(&"default".into(), ""));
    assert!(super::config_id_matches(&"billing".into(), "billing"));
    assert!(!super::config_id_matches(&"billing".into(), "default"));
}

// Upstream reference: @better-auth/api-key :: create with `references:
// "organization"` requires organizationId.
#[tokio::test]
async fn test_create_for_organization_requires_organization_id() {
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({ "name": "org-key" })),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

    assert_eq!(err.status_code(), 400);
    assert_eq!(
        err.to_string(),
        "Organization ID is required for organization-owned API keys."
    );
}

// Upstream reference: @better-auth/api-key :: checkOrgApiKeyPermission fails
// when the organization plugin, which supplies the access control, is absent.
#[tokio::test]
async fn test_create_for_organization_requires_the_organization_plugin() {
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({ "name": "org-key", "organizationId": "org-1" })),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

    assert_eq!(
        err.to_string(),
        "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin."
    );
}

// Upstream reference: @better-auth/api-key :: checkOrgApiKeyPermission rejects
// a caller who is not a member of the owning organization.
#[tokio::test]
async fn test_create_for_organization_rejects_non_member() {
    let plugin = ApiKeyPlugin::builder()
        .references(ApiKeyReferences::Organization)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Stand in for a registered organization plugin.
    let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
    let _ = metadata.insert(
        crate::plugins::organization::METADATA_ENABLED.to_string(),
        serde_json::Value::Bool(true),
    );
    let ctx = AuthContext::with_metadata(ctx.config.clone(), ctx.database.clone(), metadata);

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({ "name": "org-key", "organizationId": "org-the-user-is-not-in" })),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

    assert_eq!(
        err.to_string(),
        "You are not a member of the organization that owns this API key."
    );
}
