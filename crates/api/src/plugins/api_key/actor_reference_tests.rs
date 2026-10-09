use super::*;
use better_auth_core::{
    AuthInitContext, AuthSchema, FieldValue,
    store::{EphemeralStore, MemoryCacheAdapter, SecondaryStorage, secondary::SecondaryStore},
};
use serde_json::{Value, json};
use std::sync::Mutex;

fn cases() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/api-key-actor-reference-cases.json"
    ))
    .unwrap()
}

struct Permissions(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl ApiKeyDefaultPermissions for Permissions {
    async fn permissions(
        &self,
        reference: &FieldValue,
        ctx: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        let count = ctx
            .api_keys
            .count_api_keys_by_reference_value(reference)
            .await?;
        self.0
            .lock()
            .unwrap()
            .push(json!([reference.json()?, ctx.body["metadata"], count]));
        Ok(serde_json::from_value(cases()["permissions"].clone()).unwrap())
    }
}

async fn harness<S: AuthSchema>(
    ctx: AuthContext<S>,
    secondary: bool,
) -> (
    AuthContext<S>,
    ApiKeyPlugin,
    Arc<MemoryCacheAdapter>,
    Arc<MemoryCacheAdapter>,
    Arc<Mutex<Vec<Value>>>,
) {
    let sessions = Arc::new(MemoryCacheAdapter::new());
    let keys = Arc::new(MemoryCacheAdapter::new());
    let callbacks = Arc::new(Mutex::new(Vec::new()));
    let plugin = ApiKeyPlugin::builder()
        .storage(if secondary {
            ApiKeyStorage::SecondaryStorage
        } else {
            ApiKeyStorage::Database
        })
        .custom_storage(keys.clone())
        .enable_metadata(true)
        .default_permissions_callback(Arc::new(Permissions(callbacks.clone())))
        .build();
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await.unwrap();
    let store = ctx
        .database
        .with_runtime(
            ctx.config.clone(),
            Vec::new(),
            init.into_parts().plugin_fields,
        )
        .unwrap();
    let store = SecondaryStore::new(
        store,
        sessions.clone(),
        ctx.config.clone(),
        Default::default(),
    )
    .unwrap();
    let mut ctx = AuthContext::new(ctx.config, Arc::new(store));
    ctx.secondary_storage = Some(sessions.clone());
    (ctx, plugin, sessions, keys, callbacks)
}

async fn actor(cache: &MemoryCacheAdapter, value: Option<&Value>) {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut user = json!({
        "name": "Native actor", "email": "actor@native-actor.test", "emailVerified": true,
        "createdAt": now, "updatedAt": now,
    });
    if let Some(value) = value {
        user["id"] = value.clone();
    }
    let envelope = json!({
        "session": { "id": "actor-session", "userId": "session-owner", "token": "actor-token",
            "createdAt": now, "updatedAt": now, "expiresAt": "2100-01-01T00:00:00.000Z" },
        "user": user,
    });
    cache
        .set("actor-token", &envelope.to_string(), None)
        .await
        .unwrap();
}

fn request(
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    query: Option<Value>,
) -> AuthRequest {
    AuthRequest::from_parts(
        method,
        path.into(),
        HashMap::from([("authorization".into(), "Bearer actor-token".into())]),
        body.map(|value| serde_json::to_vec(&value).unwrap()),
        query,
    )
}

async fn list<S: AuthSchema>(plugin: &ApiKeyPlugin, ctx: &AuthContext<S>) -> Value {
    json_body(
        &plugin
            .handle_list(&request(HttpMethod::Get, "/api-key/list", None, None), ctx)
            .await
            .unwrap(),
    )
}

async fn check_lifecycle<S: AuthSchema>(ctx: AuthContext<S>, secondary: bool, sqlite: bool) {
    let (ctx, plugin, sessions, keys, callbacks) = harness(ctx, secondary).await;
    let cases = cases();
    for sample in cases["owners"].as_array().unwrap() {
        actor(&sessions, Some(&sample["actor"])).await;
        callbacks.lock().unwrap().clear();
        let created = json_body(
            &plugin
                .handle_create(
                    &request(
                        HttpMethod::Post,
                        "/api-key/create",
                        Some(json!({"name": "Machine", "metadata": cases["metadata"]})),
                        None,
                    ),
                    &ctx,
                )
                .await
                .unwrap(),
        );
        let id = created["id"].as_str().unwrap();
        let reference = if sqlite {
            &sample["sqliteReference"]
        } else {
            &sample["actor"]
        };
        assert_eq!(&created["referenceId"], reference);
        assert_eq!(created["metadata"], cases["metadata"]);
        assert_eq!(created["permissions"], cases["permissions"]);
        let expected_callback = vec![json!([sample["actor"], cases["metadata"], 0])];
        assert_eq!(*callbacks.lock().unwrap(), expected_callback);
        let native_actor = FieldValue::from_json(sample["actor"].clone()).unwrap();
        if secondary {
            let stored = keys
                .get(&format!("api-key:by-id:{id}"))
                .await
                .unwrap()
                .unwrap();
            let stored: Value = serde_json::from_str(stored.as_str().unwrap()).unwrap();
            assert_eq!(stored["referenceId"], sample["actor"]);
            assert_eq!(stored["metadata"], cases["metadata"]);
            assert_eq!(
                serde_json::from_str::<Value>(stored["permissions"].as_str().unwrap()).unwrap(),
                cases["permissions"]
            );
            let index = keys
                .get(&format!(
                    "api-key:by-ref:{}",
                    sample["cacheReference"].as_str().unwrap()
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(index.as_str().unwrap()).unwrap(),
                json!([id])
            );
            assert_eq!(
                ctx.database
                    .count_api_keys_by_reference_value(&native_actor)
                    .await
                    .unwrap(),
                0
            );
        } else {
            let rows = ctx
                .database
                .find_api_keys_by_reference_value(&native_actor, None)
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].id, id);
            assert_eq!(
                serde_json::to_value(&rows[0].reference_id).unwrap(),
                *reference
            );
            assert_eq!(
                serde_json::to_value(&rows[0].metadata).unwrap(),
                cases["metadata"]
            );
            assert_eq!(
                ctx.database
                    .count_api_keys_by_reference_value(&native_actor)
                    .await
                    .unwrap(),
                1
            );
            let other = FieldValue::from_json(sample["other"].clone()).unwrap();
            assert_eq!(
                ctx.database
                    .count_api_keys_by_reference_value(&other)
                    .await
                    .unwrap(),
                u64::from(sqlite && sample["name"] != "boolean")
            );
        }
        let unauthorized = if sqlite && &sample["actor"] != reference {
            &sample["actor"]
        } else {
            &sample["other"]
        };
        actor(&sessions, Some(unauthorized)).await;
        let get = request(
            HttpMethod::Get,
            "/api-key/get",
            None,
            Some(json!({"id": id})),
        );
        let update = request(
            HttpMethod::Post,
            "/api-key/update",
            Some(json!({"keyId": id, "name": "Unauthorized"})),
            None,
        );
        let delete = request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(json!({"keyId": id})),
            None,
        );
        assert_eq!(
            plugin
                .handle_get(&get, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(
            plugin
                .handle_update(&update, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(
            plugin
                .handle_delete(&delete, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(list(&plugin, &ctx).await["total"], 0);

        actor(&sessions, Some(reference)).await;
        let found = json_body(
            &plugin
                .handle_get(
                    &request(
                        HttpMethod::Get,
                        "/api-key/get",
                        None,
                        Some(json!({"id": id})),
                    ),
                    &ctx,
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            json!([
                found["referenceId"],
                found["metadata"],
                found["permissions"]
            ]),
            json!([reference, cases["metadata"], cases["permissions"]])
        );
        let listed = list(&plugin, &ctx).await;
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["apiKeys"][0]["id"], id);
        let updated = json_body(
            &plugin
                .handle_update(
                    &request(
                        HttpMethod::Post,
                        "/api-key/update",
                        Some(json!({"keyId": id, "name": "Updated"})),
                        None,
                    ),
                    &ctx,
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            json!([updated["referenceId"], updated["name"], updated["metadata"]]),
            json!([reference, "Updated", cases["metadata"]])
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
        assert_eq!(list(&plugin, &ctx).await["total"], 0);
        assert_eq!(*callbacks.lock().unwrap(), expected_callback);
    }
    callbacks.lock().unwrap().clear();
    for sample in cases["rejected"].as_array().unwrap() {
        actor(&sessions, sample.get("actor")).await;
        for result in [
            plugin
                .handle_create(
                    &request(
                        HttpMethod::Post,
                        "/api-key/create",
                        Some(json!({"name": "Rejected"})),
                        None,
                    ),
                    &ctx,
                )
                .await,
            plugin
                .handle_update(
                    &request(
                        HttpMethod::Post,
                        "/api-key/update",
                        Some(json!({"keyId": "missing", "userId": "fallback", "name": "Rejected"})),
                        None,
                    ),
                    &ctx,
                )
                .await,
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.status_code(), 401, "{}", sample["name"]);
            assert_eq!(
                json_body(&error.to_auth_response())["code"],
                "UNAUTHORIZED_SESSION"
            );
        }
    }
    assert!(callbacks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn memory_api_key_lifecycle_retains_native_actor_reference() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    check_lifecycle(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        false,
        false,
    )
    .await;
}

#[tokio::test]
async fn sqlite_api_key_lifecycle_retains_native_actor_reference() {
    check_lifecycle(
        crate::plugins::test_helpers::create_test_context().await,
        false,
        true,
    )
    .await;
}

#[tokio::test]
async fn secondary_api_key_lifecycle_retains_native_actor_reference() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    check_lifecycle(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        true,
        false,
    )
    .await;
}

#[tokio::test]
async fn secondary_null_and_missing_references_retain_distinct_strict_owners() {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let (ctx, plugin, sessions, keys, callbacks) = harness(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        true,
    )
    .await;
    let null = Value::Null;
    for (value, suffix, expected, other) in [
        (Some(&null), "null", "null-owner", "missing-owner"),
        (None, "undefined", "missing-owner", "null-owner"),
    ] {
        actor(&sessions, value).await;
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        for (id, reference) in [("null-owner", Some(&null)), ("missing-owner", None)] {
            let mut row = json!({"id": id, "configId": "default", "key": format!("hash:{id}"), "createdAt": now, "updatedAt": now});
            if let Some(reference) = reference {
                row["referenceId"] = reference.clone();
            }
            keys.set(&format!("api-key:by-id:{id}"), &row.to_string(), None)
                .await
                .unwrap();
        }
        keys.set(
            &format!("api-key:by-ref:{suffix}"),
            "[\"null-owner\",\"missing-owner\"]",
            None,
        )
        .await
        .unwrap();
        let listed = list(&plugin, &ctx).await;
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["apiKeys"][0]["id"], expected);
        assert_eq!(
            json_body(
                &plugin
                    .handle_get(
                        &request(
                            HttpMethod::Get,
                            "/api-key/get",
                            None,
                            Some(json!({"id": expected}))
                        ),
                        &ctx
                    )
                    .await
                    .unwrap()
            )["id"],
            expected
        );
        assert_eq!(
            plugin
                .handle_get(
                    &request(
                        HttpMethod::Get,
                        "/api-key/get",
                        None,
                        Some(json!({"id": other}))
                    ),
                    &ctx
                )
                .await
                .unwrap_err()
                .status_code(),
            404
        );
    }
    assert!(callbacks.lock().unwrap().is_empty());
}

#[path = "actor_reference_tests/create_gate.rs"]
mod create_gate;
#[path = "actor_reference_tests/organization.rs"]
mod organization;

#[tokio::test]
async fn deleting_api_keys_only_rejects_a_strict_boolean_ban() {
    let mut config = crate::plugins::test_helpers::create_test_config();
    let _ = config.user.fields_mut().insert(
        "banned".into(),
        better_auth_core::user_fields::UserFieldConfig {
            field_type: better_auth_core::user_fields::UserFieldType::Boolean,
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let (ctx, plugin, sessions, keys, _) = harness(
        AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config))),
        true,
    )
    .await;
    for banned in [
        json!(true),
        json!(false),
        json!("true"),
        json!(1),
        json!([]),
        Value::Null,
    ] {
        actor(&sessions, Some(&json!("owner"))).await;
        let cached = sessions.get("actor-token").await.unwrap().unwrap();
        let mut cached: Value = serde_json::from_str(cached.as_str().unwrap()).unwrap();
        cached["user"]["banned"] = banned.clone();
        sessions
            .set("actor-token", &cached.to_string(), None)
            .await
            .unwrap();
        let key = json!({
            "id":"strict-ban-key", "configId":"default", "referenceId":"owner",
            "key":"strict-ban-hash", "createdAt":"2026-01-01T00:00:00.000Z",
            "updatedAt":"2026-01-01T00:00:00.000Z"
        });
        keys.set("api-key:by-id:strict-ban-key", &key.to_string(), None)
            .await
            .unwrap();
        keys.set("api-key:by-ref:owner", "[\"strict-ban-key\"]", None)
            .await
            .unwrap();
        let response = plugin
            .handle_delete(
                &request(
                    HttpMethod::Post,
                    "/api-key/delete",
                    Some(json!({"keyId":"strict-ban-key"})),
                    None,
                ),
                &ctx,
            )
            .await;
        if banned == json!(true) {
            let error = response.unwrap_err();
            assert_eq!(error.status_code(), 401);
            assert_eq!(
                json_body(&error.to_auth_response()),
                json!({"code":"USER_BANNED", "message":"User is banned"})
            );
            assert!(
                keys.get("api-key:by-id:strict-ban-key")
                    .await
                    .unwrap()
                    .is_some()
            );
        } else {
            assert_eq!(
                json_body(&response.unwrap()),
                json!({"success":true}),
                "{banned}"
            );
            assert!(
                keys.get("api-key:by-id:strict-ban-key")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
