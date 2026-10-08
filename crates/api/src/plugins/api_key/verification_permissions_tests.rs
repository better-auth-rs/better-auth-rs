use super::*;
use serde_json::json;

// Source-derived from pinned 1.7.6 access/access.mjs and API Key validate/verify catch boundaries.
#[tokio::test]
async fn permission_runtime_properties_control_verification_before_consuming_usage() {
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        defer_updates: false,
        ..Default::default()
    });
    let (ctx, _, session) = create_test_context_with_user().await;
    for (case, permissions, required, error_code) in [
        (
            "object action",
            json!({"nodes":["read"]}),
            json!({"nodes":["read"]}),
            None,
        ),
        (
            "array index",
            json!([["read"]]),
            json!({"0":["read"]}),
            None,
        ),
        ("string index", json!("read"), json!({"0":["r"]}), None),
        (
            "array length",
            json!([["read"]]),
            json!({"length":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "string length",
            json!("read"),
            json!({"length":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "object inherited method",
            json!({}),
            json!({"toString":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "array inherited method",
            json!([]),
            json!({"toString":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "string inherited method",
            json!("read"),
            json!({"toString":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "falsy array length",
            json!([]),
            json!({"length":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "missing array index",
            json!([["read"]]),
            json!({"1":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "object shadows inherited method",
            json!({"toString":["read"]}),
            json!({"toString":["read"]}),
            None,
        ),
        (
            "null shadows inherited method",
            json!({"toString":null}),
            json!({"toString":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "object noncanonical index",
            json!({"01":["read"]}),
            json!({"01":["read"]}),
            None,
        ),
        (
            "array noncanonical index",
            json!([[], ["read"]]),
            json!({"01":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "string index counts surrogate pair",
            json!("💻read"),
            json!({"2":["r"]}),
            None,
        ),
        (
            "string index retains one surrogate",
            json!("💻read"),
            json!({"0":["💻"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "unpaired indexed surrogate includes empty action",
            json!("💻read"),
            json!({"1":[""]}),
            None,
        ),
        (
            "array specific inherited method",
            json!([]),
            json!({"map":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "object does not inherit array methods",
            json!({}),
            json!({"map":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "string specific inherited method",
            json!("read"),
            json!({"charAt":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "boolean inherited method",
            json!(true),
            json!({"valueOf":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "parsed false rejects before property access",
            json!(false),
            json!({"valueOf":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "number inherited method",
            json!(1),
            json!({"toFixed":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "parsed zero rejects before property access",
            json!(0),
            json!({"toFixed":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "revived date inherited method",
            json!("2026-01-01T00:00:00.000Z"),
            json!({"getTime":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "string actions use substring inclusion",
            json!({"nodes":"bread"}),
            json!({"nodes":["read"]}),
            None,
        ),
        (
            "array actions require exact string",
            json!({"nodes":["bread"]}),
            json!({"nodes":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "truthy object has no callable includes",
            json!({"nodes":{"includes":["read"]}}),
            json!({"nodes":["read"]}),
            Some("INVALID_API_KEY"),
        ),
        (
            "empty request avoids inherited includes call",
            json!({}),
            json!({"toString":[]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "numeric request keys use property order",
            json!([null, 1]),
            json!({"1":["read"],"0":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
        (
            "null permissions reject before property access",
            json!(null),
            json!({"toString":["read"]}),
            Some("KEY_NOT_FOUND"),
        ),
    ] {
        let (id, key) = create_key_with_server_fields(
            &plugin,
            &ctx,
            &session.token,
            json!({"name":"Permissions"}),
            UpdateApiKey {
                remaining: Some(3.0),
                permissions: Some(permissions.to_string()),
                rate_limit_enabled: Some(true),
                rate_limit_max: Some(10.0),
                rate_limit_time_window: Some(60_000.0),
                ..Default::default()
            },
        )
        .await;
        let before = ctx.database.get_api_key_by_id(&id).await.unwrap().unwrap();
        assert_eq!(before.request_count, Some(0.0), "{case}");
        assert_eq!(before.remaining, Some(3.0), "{case}");
        let started = Utc::now().timestamp_millis() as f64;
        let result = plugin
            .verify_api_key(
                &VerifyApiKey {
                    key: &key,
                    config_id: None,
                    permissions: Some(&required),
                },
                &ctx,
            )
            .await;
        let ended = Utc::now().timestamp_millis() as f64;
        let actual = match result {
            Ok(view) => json!({"valid":true,"error":null,"key":view}),
            Err(error) => {
                let response = error.into_response().unwrap();
                assert_eq!(response.status, 200, "{case}");
                json_body(&response)
            }
        };
        let after = ctx.database.get_api_key_by_id(&id).await.unwrap().unwrap();
        if let Some(code) = error_code {
            let message = if code == "INVALID_API_KEY" {
                json!({"code":"INVALID_API_KEY","message":"Invalid API key."})
            } else {
                json!("API Key not found")
            };
            assert_eq!(
                actual,
                json!({
                    "valid":false,
                    "error":{"code":code,"message":message},
                    "key":null,
                }),
                "{case}"
            );
            assert_eq!(
                after, before,
                "{case}: rejected permissions must preserve the complete stored record"
            );
            continue;
        }
        let last_request = after.last_request.typed().unwrap().as_ref().unwrap();
        assert!(
            (started..=ended).contains(&last_request.milliseconds()),
            "{case}"
        );
        assert!(
            (started..=ended).contains(&after.updated_at.typed().unwrap().milliseconds()),
            "{case}"
        );
        let mut expected = before;
        expected.remaining = Some(2.0).into();
        expected.request_count = Some(1.0).into();
        expected.last_request = after.last_request.clone();
        expected.updated_at = after.updated_at.clone();
        assert_eq!(
            after, expected,
            "{case}: one successful verification consumes one quota and rate-limit slot"
        );
        let mut public = serde_json::to_value(&expected).unwrap();
        let public_fields = public.as_object_mut().unwrap();
        assert!(public_fields.remove("key").is_some());
        let _ = public_fields.insert("permissions".into(), permissions);
        let _ = public_fields.insert("metadata".into(), serde_json::Value::Null);
        assert_eq!(
            actual,
            json!({"valid":true,"error":null,"key":public}),
            "{case}"
        );
    }
}
