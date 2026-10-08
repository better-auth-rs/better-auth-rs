use super::*;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/api-key-create-gate-cases.json"
    ))
    .unwrap()
}

fn assert_error(error: AuthError, expected: &Value) {
    assert_eq!(
        u64::from(error.status_code()),
        expected["status"].as_u64().unwrap()
    );
    assert_eq!(json_body(&error.to_auth_response()), expected["body"]);
}

#[tokio::test]
async fn typed_and_http_creation_preserve_gate_order_before_side_effects() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let (ctx, _, _, _, callbacks) = harness(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        false,
    )
    .await;
    let contract = contract();
    for case in contract["cases"].as_array().unwrap() {
        let plugin = ApiKeyPlugin::builder()
            .references(if case["organization"] == true {
                ApiKeyReferences::Organization
            } else {
                ApiKeyReferences::User
            })
            .default_permissions_callback(Arc::new(Permissions(callbacks.clone())))
            .build();
        let body: CreateKeyRequest = serde_json::from_value(case["body"].clone()).unwrap();
        assert_error(
            plugin.create_key(&ctx, &body).await.unwrap_err(),
            &contract["errors"][case["typed"].as_str().unwrap()],
        );
        let request = request(
            HttpMethod::Post,
            "/api-key/create",
            Some(case["body"].clone()),
            None,
        );
        let request = request.clone().with_original_request(request);
        assert_error(
            plugin.handle_create(&request, &ctx).await.unwrap_err(),
            &contract["errors"][case["http"].as_str().unwrap()],
        );
    }
    assert!(callbacks.lock().unwrap().is_empty());
    for reference in ["owner", "machines"] {
        assert_eq!(
            ctx.database
                .count_api_keys_by_reference(reference)
                .await
                .unwrap(),
            0
        );
    }
}

struct SelectedKey(Arc<Mutex<Option<String>>>);

impl ApiKeyGetter for SelectedKey {
    fn get(&self, _ctx: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn typed_and_http_creation_cannot_replace_the_authenticated_user() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let (ctx, _, sessions, _, callbacks) = harness(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        false,
    )
    .await;
    let mut owner = CreateUser::new()
        .with_email("owner@create-gate.test")
        .with_name("Owner");
    owner.id = Some("owner".into());
    let _ = ctx.database.create_user(owner).await.unwrap();
    let selected = Arc::new(Mutex::new(None));
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .custom_api_key_getter(Arc::new(SelectedKey(selected.clone())))
        .default_permissions_callback(Arc::new(Permissions(callbacks.clone())))
        .build();
    let source = plugin
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some("owner".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    *selected.lock().unwrap() = Some(source.key);
    callbacks.lock().unwrap().clear();
    let expected = &contract()["errors"]["UNAUTHORIZED_SESSION"];
    assert_error(
        plugin
            .create_key(
                &ctx,
                &CreateKeyRequest {
                    user_id: Some("other-user".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
        expected,
    );
    *selected.lock().unwrap() = None;
    actor(&sessions, Some(&json!("owner"))).await;
    let request = request(
        HttpMethod::Post,
        "/api-key/create",
        Some(json!({"userId": "other-user"})),
        None,
    );
    let request = request.clone().with_original_request(request);
    assert_error(
        plugin.handle_create(&request, &ctx).await.unwrap_err(),
        expected,
    );
    assert!(callbacks.lock().unwrap().is_empty());
    assert_eq!(
        ctx.database
            .count_api_keys_by_reference("owner")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ctx.database
            .count_api_keys_by_reference_value(&"other-user".into())
            .await
            .unwrap(),
        0
    );
}
