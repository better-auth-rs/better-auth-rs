#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Account-info preserves native token inputs and spreads the complete provider response.

use super::*;
use better_auth_api::plugins::oauth::{
    OAuthAccountSubject, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue,
    endpoint_dispatch::EndpointDispatcher,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};

struct NativeProfile {
    access_token: FieldValue,
    id_token: FieldValue,
    calls: Arc<std::sync::Mutex<Vec<FieldMap>>>,
}

#[async_trait]
impl OAuthUserInfoHandler for NativeProfile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        let fields = request.fields();
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["accessToken", "accessTokenExpiresAt", "scopes", "idToken"]
        );
        assert!(fields["accessToken"].strict_equals(&self.access_token));
        assert!(fields["idToken"].strict_equals(&self.id_token));
        assert_eq!(
            fields["accessTokenExpiresAt"],
            FieldValue::Number(4_102_444_800_000.0)
        );
        assert_eq!(fields["scopes"].json()?, Some(json!(["email profile"])));
        let _ = fields["idToken"]
            .as_object()
            .unwrap()
            .set("observed", true.into())?;
        self.calls.lock().unwrap().push(fields);
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "provider-owner".into(),
                name: Some("Provider Owner".into()).into(),
                email: Some("native-tokens@example.com".into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
            data: json!({"sub": "provider-owner"}),
        }))
    }
}

#[tokio::test]
async fn test_account_info_preserves_number_expiry_and_native_token_identity() {
    for access_token in [
        FieldValue::Number(7.0),
        FieldMap::from([("credential".into(), "native-access".into())]).into(),
    ] {
        let mut config = test_config();
        let db = create_test_database().await;
        let (user_id, session_token, account_id) = setup_user_with_account(
            &db,
            &Arc::new(config.clone()),
            "native-tokens@example.com",
            "google",
            Some("stored-access".into()),
            Some("stored-refresh".into()),
        )
        .await;
        let before = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        let before = before.internal_fields().unwrap().json().unwrap();
        let id_token: FieldValue = FieldMap::from([
            (
                "claims".into(),
                FieldMap::from([("sub".into(), "native-id".into())]).into(),
            ),
            ("absent".into(), FieldValue::Undefined),
        ])
        .into();
        for (name, value) in [
            ("accessToken", access_token.clone()),
            ("idToken", id_token.clone()),
            (
                "accessTokenExpiresAt",
                FieldValue::Number(4_102_444_800_000.0),
            ),
        ] {
            let _ = config.account.additional_fields.insert(
                name.into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |_| Ok(value.clone()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut provider = make_test_provider("http://localhost:65535");
        provider.get_user_info = Some(Arc::new(NativeProfile {
            access_token: access_token.clone(),
            id_token: id_token.clone(),
            calls: calls.clone(),
        }));
        let mut oauth_config = OAuthConfig::default();
        let _ = oauth_config.providers.insert("google".into(), provider);
        let plugin = OAuthPlugin::with_config(oauth_config);
        let config = Arc::new(config);
        let runtime = db
            .with_runtime(config.clone(), Vec::new(), Default::default())
            .unwrap();
        let context = AuthContext::new(config, runtime)
            .expect("fixture context initializes")
            .initialize_request_context()
            .await
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Get, "/account-info");
        request.query = Some(json!({"accountId": account_id}));
        let _ = request
            .headers
            .insert("cookie".into(), session_cookie(&session_token));
        let response = refresh_cookie::dispatch(&plugin, &request, &context)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
            json!({
                "user": {
                    "id": "provider-owner", "name": "Provider Owner",
                    "email": "native-tokens@example.com", "emailVerified": true
                },
                "data": {"sub": "provider-owner"},
                "account": {"id": account_id, "providerId": "google", "accountId": "google-account-id"}
            })
        );
        assert_eq!(response.headers.get_all("Set-Cookie").count(), 0);
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].json().unwrap(),
                json!({
                    "accessToken": access_token.json().unwrap(),
                    "accessTokenExpiresAt": 4_102_444_800_000_i64,
                    "scopes": ["email profile"],
                    "idToken": {"claims": {"sub": "native-id"}, "observed": true}
                })
                .as_object()
                .unwrap()
                .clone()
            );
        }
        assert!(
            id_token
                .model_property("observed")
                .unwrap()
                .strict_equals(&true.into())
        );
        let after = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        assert_eq!(after.internal_fields().unwrap().json().unwrap(), before);
    }
}

struct NativeAccountInfo {
    response: FieldValue,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

#[async_trait]
impl OAuthUserInfoHandler for NativeAccountInfo {
    async fn get_user_info_native(&self, _: OAuthUserInfoRequest) -> AuthResult<FieldValue> {
        self.calls.lock().unwrap().push("get");
        Ok(self.response.clone())
    }
}

#[async_trait]
impl OAuthAccountSubject for NativeAccountInfo {
    async fn resolve_subject_native(
        &self,
        _: &FieldValue,
        _: &FieldValue,
    ) -> AuthResult<FieldValue> {
        self.calls.lock().unwrap().push("subject");
        Err(AuthError::internal(
            "Account-info must not resolve the provider account subject",
        ))
    }
}

#[tokio::test]
async fn test_account_info_spreads_native_response_without_resolving_subject() {
    let config = Arc::new(test_config());
    let db = create_test_database().await;
    let (user_id, session_token, account_id) = setup_user_with_account(
        &db,
        &config,
        "native-account-info@example.com",
        "google",
        Some("stored-access".into()),
        None,
    )
    .await;
    let before = db.get_user_accounts(&user_id).await.unwrap().remove(0);
    let before = before.internal_fields().unwrap().json().unwrap();
    let extension: FieldValue = json!({"kind": "native-extension"}).into();
    let user: FieldValue = FieldMap::from([
        ("name".into(), FieldValue::Number(17.0)),
        ("email".into(), FieldValue::Null),
        ("emailVerified".into(), "yes".into()),
        ("extension".into(), extension.clone()),
    ])
    .into();
    let data: FieldValue = json!({"raw": true}).into();
    let supplied_account: FieldValue = json!({"id": "provider-supplied"}).into();
    let provider_response: FieldValue = FieldMap::from([
        ("extra".into(), extension.clone()),
        ("user".into(), user.clone()),
        ("account".into(), supplied_account.clone()),
        ("data".into(), data.clone()),
        ("optional".into(), FieldValue::Undefined),
    ])
    .into();
    let callbacks = Arc::new(NativeAccountInfo {
        response: provider_response.clone(),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let mut provider = make_test_provider("http://localhost:65535");
    provider.get_user_info = Some(callbacks.clone());
    provider.account_subject = Some(callbacks.clone());
    let mut oauth_config = OAuthConfig::default();
    let _ = oauth_config.providers.insert("google".into(), provider);
    let plugin = OAuthPlugin::with_config(oauth_config);
    let runtime = db
        .with_runtime(config.clone(), Vec::new(), Default::default())
        .unwrap();
    let context = AuthContext::new(config, runtime)
        .expect("fixture context initializes")
        .initialize_request_context()
        .await
        .unwrap();
    let routes = AuthPlugin::<TestSchema>::routes(&plugin);
    let route = routes
        .iter()
        .find(|route| route.path == "/account-info")
        .unwrap()
        .clone();
    let dispatcher = EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), routes);
    let mut request = AuthRequest::new(HttpMethod::Get, "/account-info");
    request.query = Some(json!({"accountId": account_id}));
    let _ = request
        .headers
        .insert("cookie".into(), session_cookie(&session_token));
    let response = dispatcher
        .native(request, route, &context, |request, context| {
            let plugin = &plugin;
            async move {
                plugin
                    .on_request(&request, &context)
                    .await?
                    .ok_or_else(|| AuthError::internal("Account-info endpoint did not match"))
            }
        })
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body = response.body.field_value().unwrap();
    assert!(!body.strict_equals(&provider_response));
    assert!(body.model_property("user").unwrap().strict_equals(&user));
    assert!(body.model_property("data").unwrap().strict_equals(&data));
    assert!(
        body.model_property("extra")
            .unwrap()
            .strict_equals(&extension)
    );
    assert_eq!(
        body.as_object().unwrap().own_keys().unwrap(),
        ["extra", "user", "account", "data", "optional"]
    );
    assert!(body.model_property("optional").unwrap().is_undefined());
    assert_eq!(
        body.json().unwrap(),
        Some(json!({
            "extra": {"kind": "native-extension"},
            "user": {
                "name": 17, "email": null, "emailVerified": "yes",
                "extension": {"kind": "native-extension"}
            },
            "account": {"id": account_id, "providerId": "google", "accountId": "google-account-id"},
            "data": {"raw": true}
        }))
    );
    assert!(
        provider_response
            .model_property("account")
            .unwrap()
            .strict_equals(&supplied_account)
    );
    assert_eq!(*callbacks.calls.lock().unwrap(), ["get"]);
    assert_eq!(response.headers.get_all("Set-Cookie").count(), 0);
    let after = db.get_user_accounts(&user_id).await.unwrap().remove(0);
    assert_eq!(after.internal_fields().unwrap().json().unwrap(), before);
}
