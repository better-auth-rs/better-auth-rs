use super::{google, google_test_support::GoogleFixture, *};
use crate::plugins::test_helpers;
use better_auth_core::{AuthPlugin, AuthUser, wire::UserView};
use serde_json::{Value, json};
use std::sync::Mutex;

fn claims() -> Value {
    json!({
        "sub":"google-normal-subject",
        "email":"google-normal@example.test",
        "email_verified":true,
        "name":"Verified Google User",
        "picture":"https://images.test/verified.png",
        "nonce":"normal-nonce",
        "hd":"example.test"
    })
}

fn expected_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/google-profile-1.7.6.json"
    ))
    .unwrap()
}

fn observed(user: &Value, account: &Value, calls: &[&str]) -> Value {
    json!({"name":user["name"],"image":user["image"],"email":user["email"],"emailVerified":user["emailVerified"],"calls":calls,"accountSubject":account["accountId"]})
}

struct Mapper(Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.0.lock().unwrap().push("map");
        assert_eq!(profile["name"], "Verified Google User");
        assert_eq!(profile["sub"], "google-normal-subject");
        assert_eq!(profile["iss"], "https://accounts.google.com");
        Ok(OAuthProfile {
            name: Some(Some("Mapped Google User".into())),
            ..Default::default()
        })
    }
}

fn request(token: &str) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    request.body = Some(
        serde_json::to_vec(&json!({
            "provider":"google", "idToken":{"token":token,"nonce":"normal-nonce"}
        }))
        .unwrap(),
    );
    request
}

#[tokio::test]
async fn google_direct_and_code_sign_in_map_verified_claims_once() {
    for direct in [true, false] {
        let fixture = GoogleFixture::start(claims()).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut provider = fixture.provider();
        provider
            .authorization_params
            .push(("hd".into(), "example.test".into()));
        provider.map_profile_to_user = Some(Arc::new(Mapper(calls.clone())));
        let plugin = OAuthPlugin::new().add_provider("google", provider);
        let mut config = test_helpers::create_test_config();
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;
        if direct {
            let response = plugin
                .on_request(&request(&fixture.token), &ctx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status, 200);
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["user"]["name"], "Mapped Google User");
            assert_eq!(body["user"]["image"], "https://images.test/verified.png");
        } else {
            let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
            start.body = Some(serde_json::to_vec(&json!({
                "provider":"google","callbackURL":"http://localhost:3000/welcome","disableRedirect":true
            })).unwrap());
            let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
            let state = url
                .query_pairs()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1
                .into_owned();
            let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/google");
            callback.query = Some(json!({"code":"normal-code","state":state}));
            let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome")
            );
        }
        let user = ctx
            .database
            .get_user_by_email("google-normal@example.test")
            .await
            .unwrap()
            .unwrap();
        let view = serde_json::to_value(UserView::from(&user)).unwrap();
        assert_eq!(view["name"], "Mapped Google User");
        assert_eq!(view["image"], "https://images.test/verified.png");
        assert_eq!(view["emailVerified"], true);
        let accounts = ctx
            .database
            .get_user_accounts(&user.id().display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            observed(
                &view,
                &serde_json::to_value(&accounts[0]).unwrap(),
                &calls.lock().unwrap()
            ),
            expected_fixture()[if direct { "direct" } else { "code" }]
        );
        assert_eq!(*calls.lock().unwrap(), ["map"]);
        assert_eq!(
            *fixture.requests.lock().unwrap(),
            if direct {
                vec!["/jwks"]
            } else {
                vec!["/token", "/jwks"]
            }
        );
    }
}

struct ConfiguredVerifier {
    endpoint: String,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl OAuthIdTokenVerifier for ConfiguredVerifier {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String> {
        self.calls.lock().unwrap().push("verify");
        Ok(
            google::verify(token, &["client".into()], nonce, &self.endpoint)
                .await
                .is_some(),
        )
    }
}
struct ConfiguredUserInfo(Arc<Mutex<Vec<&'static str>>>);
#[async_trait]
impl OAuthUserInfoHandler for ConfiguredUserInfo {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0.lock().unwrap().push("get");
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "google-normal-subject".into(),
                email: Some("google-normal@example.test".into()).into(),
                name: Some("Configured Google User".into()),
                image: None,
                email_verified: true,
                additional_fields: Default::default(),
            },
            data: claims(),
        }))
    }
}

#[tokio::test]
async fn google_configured_verifier_keeps_claims_and_userinfo_priority() {
    for custom_userinfo in [false, true] {
        let fixture = GoogleFixture::start(claims()).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut provider = fixture.provider();
        provider.verify_id_token = Some(Arc::new(ConfiguredVerifier {
            endpoint: format!("{}/jwks", fixture.url),
            calls: calls.clone(),
        }));
        provider.map_profile_to_user = Some(Arc::new(Mapper(calls.clone())));
        if custom_userinfo {
            provider.get_user_info = Some(Arc::new(ConfiguredUserInfo(calls.clone())));
        }
        let plugin = OAuthPlugin::new().add_provider("google", provider);
        let ctx = test_helpers::create_test_context().await;
        let response = plugin
            .on_request(&request(&fixture.token), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["user"]["name"],
            if custom_userinfo {
                "Configured Google User"
            } else {
                "Mapped Google User"
            }
        );
        assert_eq!(
            *calls.lock().unwrap(),
            if custom_userinfo {
                vec!["verify", "get"]
            } else {
                vec!["verify", "map"]
            }
        );
        assert_eq!(*fixture.requests.lock().unwrap(), ["/jwks"]);
        let user = ctx
            .database
            .get_user_by_email("google-normal@example.test")
            .await
            .unwrap()
            .unwrap();
        let accounts = ctx
            .database
            .get_user_accounts(&user.id().display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            observed(
                &serde_json::to_value(UserView::from(&user)).unwrap(),
                &serde_json::to_value(&accounts[0]).unwrap(),
                &calls.lock().unwrap()
            ),
            expected_fixture()[if custom_userinfo {
                "customUserInfo"
            } else {
                "customVerifier"
            }]
        );
    }
}

struct FailingProfile(Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl OAuthProfileMapper for FailingProfile {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile["sub"], "google-normal-subject");
        self.0.lock().unwrap().push("map");
        Err(better_auth_core::AuthError::internal(
            "Ordinary profile mapper failed",
        ))
    }
}

#[async_trait]
impl OAuthUserInfoHandler for FailingProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0.lock().unwrap().push("custom");
        Err(better_auth_core::AuthError::internal(
            "Ordinary custom userinfo failed",
        ))
    }
}

#[tokio::test]
async fn verified_direct_sign_in_preserves_mapper_and_custom_handler_errors() {
    for custom in [false, true] {
        let fixture = GoogleFixture::start(claims()).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callbacks = Arc::new(FailingProfile(calls.clone()));
        let mut provider = fixture.provider();
        provider.map_profile_to_user = Some(callbacks.clone());
        if custom {
            provider.get_user_info = Some(callbacks);
        }
        let plugin = OAuthPlugin::new().add_provider("google", provider);
        let ctx = test_helpers::create_test_context().await;
        let error = plugin
            .on_request(&request(&fixture.token), &ctx)
            .await
            .unwrap_err();
        let expected = if custom {
            "Ordinary custom userinfo failed"
        } else {
            "Ordinary profile mapper failed"
        };
        assert!(
            matches!(&error, better_auth_core::AuthError::Internal(message) if message == expected)
        );
        let response = error.to_http_response();
        assert_eq!(response.status, 500);
        assert!(response.body.is_empty());
        assert_eq!(
            *calls.lock().unwrap(),
            [if custom { "custom" } else { "map" }]
        );
        assert_eq!(*fixture.requests.lock().unwrap(), ["/jwks"]);
        assert!(
            ctx.database
                .get_user_by_email("google-normal@example.test")
                .await
                .unwrap()
                .is_none()
        );
    }
}
