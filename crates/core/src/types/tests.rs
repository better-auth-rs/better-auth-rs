use super::*;
use chrono::Utc;

// ── AuthRequest ─────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_new_defaults() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    assert_eq!(req.method(), &HttpMethod::Get);
    assert_eq!(req.path(), "/test");
    assert!(req.headers.is_empty());
    assert!(req.body.is_none());
    assert!(req.virtual_user_id().is_none());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_from_parts() {
    let mut headers = HashMap::new();
    let _ = headers.insert("host".to_string(), "localhost".to_string());
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/login".into(),
        headers,
        Some(b"{}".to_vec()),
        None,
    );
    assert_eq!(req.method(), &HttpMethod::Post);
    assert_eq!(req.header("host"), Some(&"localhost".to_string()));
    assert!(req.body.is_some());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_body_as_json_with_body() {
    let req = AuthRequest {
        method: HttpMethod::Post,
        path: "/test".into(),
        headers: HashMap::new(),
        body: Some(br#"{"name":"test"}"#.to_vec()),
        query: None,
        url: None,
        base_relative_path: false,
        original_request: None,
        parsed_http_body: None,
        endpoint_body: None,
        virtual_session: None,
        response_headers: Default::default(),
        response_status: Default::default(),
        server_only: false,
        server_context: Default::default(),
        headers_present: true,
        new_session: Default::default(),
        session_snapshot: Default::default(),
    };
    let val: serde_json::Value = req.body_as_json().expect("parse");
    assert_eq!(val["name"], "test");
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_body_as_json_without_body() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    let val: serde_json::Value = req.body_as_json().expect("parse empty");
    assert!(val.is_object());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_virtual_user_id() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    assert!(req.virtual_user_id().is_none());
    let now = Utc::now();
    req.set_virtual_session(crate::wire::SessionView {
        field_order: Default::default(),
        visible_fields: None,
        id: "key-123".into(),
        token: "key-token".into(),
        user_id: "user-123".into(),
        created_at: now.into(),
        updated_at: now.into(),
        expires_at: now.into(),
        ip_address: None.into(),
        user_agent: None.into(),
        impersonated_by: None.into(),
        active_organization_id: None.into(),
        active_team_id: None.into(),
        active: true,
        additional_fields: Default::default(),
    });
    assert_eq!(req.virtual_user_id(), Some("user-123"));
}

// ── AuthResponse ────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_new() {
    let resp = AuthResponse::new(200);
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_json() {
    let resp = AuthResponse::json(200, &OkResponse { ok: true }).expect("json");
    assert_eq!(resp.status, 200);
    assert!(resp.headers.is_empty());
    let resp = resp.into_http_response().unwrap();
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "application/json"
    );
    let body: serde_json::Value = serde_json::from_slice(&resp.body.bytes().unwrap()).unwrap();
    assert_eq!(body["ok"], true);
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_text() {
    let resp = AuthResponse::text(404, "Not found");
    assert_eq!(resp.status, 404);
    assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
    assert_eq!(
        std::str::from_utf8(&resp.body.bytes().unwrap()).unwrap(),
        "Not found"
    );
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_html() {
    let resp = AuthResponse::html(200, "<h1>Hi</h1>");
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_with_header() {
    let resp = AuthResponse::new(200).with_header("x-custom", "val");
    assert_eq!(resp.headers.get("x-custom").unwrap(), "val");
}

// ── RequestMeta ─────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_extracts_from_headers() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    let _ = req
        .headers
        .insert("x-forwarded-for".into(), "1.2.3.4".into());
    let _ = req.headers.insert("user-agent".into(), "TestAgent".into());
    let meta = RequestMeta::from_request(&req);
    assert_eq!(meta.ip_address.as_deref(), Some("1.2.3.4"));
    assert_eq!(meta.user_agent.as_deref(), Some("TestAgent"));
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_supports_configured_real_ip_header() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    let _ = req.headers.insert("x-real-ip".into(), "5.6.7.8".into());
    let config = crate::config::IpAddressConfig {
        headers: Some(vec!["x-real-ip".into()]),
        ..Default::default()
    };
    let meta = RequestMeta::from_request_with_config(&req, &config);
    assert_eq!(meta.ip_address.as_deref(), Some("5.6.7.8"));
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_none_when_no_headers() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    let meta = RequestMeta::from_request(&req);
    assert!(meta.ip_address.is_none());
    assert!(meta.user_agent.is_none());
}

// ── CreateUser builder ──────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn create_user_builder() {
    let cu = CreateUser::new()
        .with_email("Test@Example.COM")
        .with_name("Test")
        .with_email_verified(true)
        .with_username("testuser")
        .with_role("admin")
        .with_metadata(crate::FieldValue::from_json(serde_json::json!({"key": "val"})).unwrap());

    assert!(cu.id.is_none()); // ID generation is delegated to the model/store path
    assert_eq!(cu.email.as_deref(), Some("test@example.com"));
    assert_eq!(cu.name.typed().unwrap().as_deref(), Some("Test"));
    assert_eq!(cu.email_verified, Some(true));
    assert_eq!(
        cu.username.as_ref().and_then(Option::as_deref),
        Some("testuser")
    );
    assert_eq!(cu.role.as_deref(), Some("admin"));
    assert!(cu.metadata.is_some());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn create_user_default() {
    let cu = CreateUser::default();
    assert!(cu.id.is_none());
    assert!(cu.email.is_none());
}

#[test]
fn nullable_user_updates_preserve_omission_null_and_values() {
    let cases = [
        (serde_json::json!({}), None),
        (
            serde_json::json!({
                "phone_number": null,
                "ban_reason": null,
                "ban_expires": null,
            }),
            Some(serde_json::Value::Null),
        ),
        (
            serde_json::json!({
                "phone_number": "+12025550123",
                "ban_reason": "review",
                "ban_expires": "2030-01-01T00:00:00Z",
            }),
            Some(serde_json::json!("2030-01-01T00:00:00.000Z")),
        ),
    ];
    for (input, expected_date) in cases {
        let patch: UpdateUser = serde_json::from_value(input.clone()).unwrap();
        let output = serde_json::to_value(&patch).unwrap();
        for field in ["phone_number", "ban_reason"] {
            assert_eq!(output.get(field), input.get(field));
        }
        assert_eq!(output.get("ban_expires"), expected_date.as_ref());
        let restored: UpdateUser = serde_json::from_value(output).unwrap();
        assert_eq!(restored.phone_number, patch.phone_number);
        assert_eq!(restored.ban_reason, patch.ban_reason);
        assert_eq!(restored.ban_expires, patch.ban_expires);
    }
}

// ── is_false helper ─────────────────────────────────────────────────
