#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthPlugin, AuthRequest, AuthResult, CreateUser, CreateVerification, FieldMap, FieldValue,
    Headers, HttpMethod, OAuthStateStrategy,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use super::super::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthCallbacks, OAuthCodeExchange, OAuthPlugin, OAuthTokenHandler,
    OAuthTokenSet, OAuthUserInfoRequest, proxy::OAuthProxyPlugin, state::OAuthStatePayload,
};
use crate::plugins::{symmetric, test_helpers};

fn profile() -> Value {
    json!({
        "id": "profile-alias", "email": "subject@example.com",
        "name": "Subject Reader", "emailVerified": true,
    })
}

fn assert_native_fields(actual: &FieldMap, expected: &FieldMap) {
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (name, expected) in expected {
        assert!(actual[name].strict_equals(expected), "{name}");
    }
}

struct ExchangeSource {
    fields: FieldMap,
    expected_nonce: Option<&'static str>,
    events: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl OAuthTokenHandler for ExchangeSource {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        self.events.lock().unwrap().push("token");
        Ok(OAuthTokenSet::from_fields(self.fields.clone()))
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for ExchangeSource {
    async fn get_user_info(&self, request: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        self.events.lock().unwrap().push("profile");
        let actual = request.fields();
        let mut expected = self.fields.clone();
        let _ = expected.remove("expectedIdTokenNonce");
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (name, expected) in &expected {
            if name == "user" {
                assert_eq!(actual[name].json()?, Some(json!({"callback": true})));
                assert!(!actual[name].strict_equals(expected));
            } else {
                assert!(actual[name].strict_equals(expected), "{name}");
            }
        }
        Ok(Some(profile()))
    }

    async fn get_user_info_with_context(
        &self,
        request: &OAuthUserInfoRequest,
        context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Option<Value>> {
        assert_eq!(context.expected_nonce(), self.expected_nonce);
        self.get_user_info(request).await
    }
}

#[async_trait]
impl OAuthAccountSubject for ExchangeSource {
    async fn resolve_subject(
        &self,
        tokens: &OAuthUserInfoRequest,
        data: &Value,
    ) -> AuthResult<String> {
        self.events.lock().unwrap().push("subject");
        assert_native_fields(&tokens.fields(), &self.fields);
        assert_eq!(data, &profile());
        Ok("exchange-subject".into())
    }
}

#[tokio::test]
async fn callback_and_proxy_resolve_subject_from_original_exchange_tokens() {
    for proxy_flow in [false, true] {
        let shared: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let source = Arc::new(ExchangeSource {
            fields: FieldMap::from([
                ("extension".into(), shared.clone()),
                ("user".into(), shared.clone()),
                ("expectedIdTokenNonce".into(), shared.clone()),
                ("accessToken".into(), "source-access".into()),
                ("scopes".into(), vec![FieldValue::from("openid")].into()),
                ("raw".into(), shared),
                ("tail".into(), FieldValue::Undefined),
            ]),
            expected_nonce: (!proxy_flow).then_some("callback-nonce"),
            events: Mutex::new(Vec::new()),
        });
        let oauth = OAuthPlugin::new().add_generic_provider(
            "generic",
            GenericOAuthConfig {
                client_id: "client".into(),
                authorization_url: Some("https://provider.example/authorize".into()),
                get_token: Some(source.clone()),
                get_user_info: Some(source.clone()),
                account_subject: Some(source.clone()),
                ..Default::default()
            },
        );
        let proxy = OAuthProxyPlugin::new();
        let mut config = test_helpers::create_test_config().base_url("http://localhost:3000");
        config.account.skip_state_cookie_check = true;
        config.account.store_state_strategy = Some(OAuthStateStrategy::Database);
        let ctx = test_helpers::create_test_context_with_plugins(config, &[&oauth, &proxy]).await;
        let callback_url = if proxy_flow {
            "http://localhost:3000/callback/generic/oauth-proxy?callbackURL=http://localhost:3000/welcome"
        } else {
            "http://localhost:3000/welcome"
        };
        let mut payload = OAuthStatePayload::new(
            callback_url.into(),
            "code-verifier".into(),
            None,
            None,
            None,
            None,
            Default::default(),
        );
        payload.id_token_nonce = Some("callback-nonce".into());
        let plain = serde_json::to_string(&payload).unwrap();
        let state = if proxy_flow {
            let cookie = symmetric::encrypt(ctx.config.encryption_secret(), &plain).unwrap();
            symmetric::encrypt(
                ctx.config.encryption_secret(),
                &json!({
                    "state": "source-state", "stateCookie": cookie, "isOAuthProxy": true,
                })
                .to_string(),
            )
            .unwrap()
        } else {
            let _ = ctx
                .database
                .create_verification(CreateVerification {
                    identifier: "source-state".into(),
                    value: plain.into(),
                    expires_at: (Utc::now() + Duration::minutes(10)).into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            "source-state".into()
        };
        let mut request = AuthRequest::new(HttpMethod::Get, "/callback/generic");
        request.query = Some(json!({
            "state": state, "code": "source-code", "user": "{\"callback\":true}",
        }));
        if proxy_flow {
            let response = proxy.before_request(&request, &ctx).await.unwrap_err();
            assert!(response.is_found_redirect().unwrap());
            let headers = Headers::from_field_value(&response.headers_value().unwrap()).unwrap();
            let location = url::Url::parse(headers.get("location").unwrap()).unwrap();
            let encrypted = location
                .query_pairs()
                .find(|(name, _)| name == "profile")
                .unwrap()
                .1;
            let plain = symmetric::decrypt(ctx.config.encryption_secret(), &encrypted).unwrap();
            let result: Value = serde_json::from_str(&plain).unwrap();
            assert_eq!(result["account"]["accountId"], "exchange-subject");
            assert_eq!(result["userInfo"]["id"], "exchange-subject");
            assert!(
                ctx.database
                    .get_account("generic", "exchange-subject")
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            let response = oauth.on_request(&request, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("location").map(String::as_str),
                Some(callback_url)
            );
            assert!(
                ctx.database
                    .get_account("generic", "exchange-subject")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                ctx.database
                    .get_account("generic", "profile-alias")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            *source.events.lock().unwrap(),
            ["token", "profile", "subject"]
        );
    }
}

struct DirectSource {
    include_user: bool,
    observed: Mutex<Option<FieldMap>>,
    events: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl GenericOAuthUserInfoHandler for DirectSource {
    async fn get_user_info(&self, request: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        self.events.lock().unwrap().push("profile");
        let fields = request.fields();
        let mut expected = vec!["idToken", "accessToken", "refreshToken"];
        if self.include_user {
            expected.push("user");
            assert_eq!(
                fields["user"].json()?,
                Some(json!({"name":{"firstName":"Direct","lastName":"Reader"}}))
            );
        }
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(fields["idToken"].as_str(), Some("direct-id-token"));
        assert_eq!(fields["accessToken"].as_str(), Some("direct-access"));
        assert!(fields["refreshToken"].is_undefined());
        *self.observed.lock().unwrap() = Some(fields);
        Ok(Some(profile()))
    }
}

#[async_trait]
impl OAuthAccountSubject for DirectSource {
    async fn resolve_subject(
        &self,
        tokens: &OAuthUserInfoRequest,
        data: &Value,
    ) -> AuthResult<String> {
        self.events.lock().unwrap().push("subject");
        assert_native_fields(
            &tokens.fields(),
            self.observed.lock().unwrap().as_ref().unwrap(),
        );
        assert_eq!(data, &profile());
        Ok("direct-subject".into())
    }
}

#[tokio::test]
async fn direct_id_token_signin_and_link_keep_their_explicit_subject_sources() {
    for link in [false, true] {
        let source = Arc::new(DirectSource {
            include_user: !link,
            observed: Mutex::new(None),
            events: Mutex::new(Vec::new()),
        });
        let verifier = source.clone();
        let oauth = OAuthPlugin::new()
            .add_generic_provider(
                "generic",
                GenericOAuthConfig {
                    client_id: "client".into(),
                    authorization_url: Some("https://provider.example/authorize".into()),
                    get_user_info: Some(source.clone()),
                    account_subject: Some(source.clone()),
                    ..Default::default()
                },
            )
            .callbacks(OAuthCallbacks::default().verify_id_token(
                "generic",
                move |token, nonce, _| {
                    let verifier = verifier.clone();
                    Box::pin(async move {
                        assert_eq!(token, "direct-id-token");
                        assert_eq!(nonce, Some("verification-nonce"));
                        verifier.events.lock().unwrap().push("verify");
                        Ok(true)
                    })
                },
            ));
        let ctx = test_helpers::create_test_context_with_plugins(
            test_helpers::create_test_config(),
            &[&oauth],
        )
        .await;
        let path = if link {
            "/link-social"
        } else {
            "/sign-in/social"
        };
        let mut request = AuthRequest::new(HttpMethod::Post, path);
        let _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        request.body = Some(serde_json::to_vec(&json!({
            "provider":"generic", "idToken": {
                "token":"direct-id-token", "accessToken":"direct-access", "nonce":"verification-nonce",
                "user":{"name":{"firstName":"Direct","lastName":"Reader"}},
            },
        })).unwrap());
        if link {
            let (_, session) = test_helpers::create_user_and_session(
                &ctx,
                CreateUser::new()
                    .with_email("subject@example.com")
                    .with_name("Subject Reader")
                    .with_email_verified(true),
                Duration::hours(1),
            )
            .await;
            let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
                session.token.typed().unwrap(),
                &ctx.config,
            )
            .unwrap();
            let _ = request
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into());
        }
        let response = oauth.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        assert!(
            ctx.database
                .get_account("generic", "direct-subject")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            *source.events.lock().unwrap(),
            ["verify", "profile", "subject"]
        );
    }
}
