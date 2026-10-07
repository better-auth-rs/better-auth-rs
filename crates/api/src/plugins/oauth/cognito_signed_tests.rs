#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Signed local fixtures fail immediately when setup or captured output differs."
)]

use super::google_test_support::GoogleFixture;
use super::*;
use better_auth_core::{AuthError, SchemaValue};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/cognito-1.7.6.json"
    ))
    .unwrap()
}

fn options(server: &GoogleFixture) -> CognitoOptions {
    let mut options = CognitoOptions::new(
        "ordinary.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "us-east-1_Ordinary",
    );
    options.jwks_url = Some(format!("{}/jwks", server.url));
    options
        .additional_client_ids
        .push("ordinary-secondary-client".into());
    options
}

fn provider(server: &GoogleFixture) -> OAuthProvider {
    let mut provider =
        OAuthProvider::cognito("ordinary-client", "ordinary-client-secret", options(server))
            .unwrap();
    provider.token_url = format!("{}/token", server.url);
    provider.user_info_url = Some(format!("{}/userinfo", server.url));
    provider
}

struct Mapper {
    seen: Arc<Mutex<Vec<Value>>>,
    patch: Value,
    fail_first: AtomicBool,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen.lock().unwrap().push(profile.clone());
        if self.fail_first.swap(false, Ordering::SeqCst) {
            return Err(AuthError::internal("ordinary mapper failure"));
        }
        Ok(OAuthProfile {
            name: self
                .patch
                .get("name")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email: self
                .patch
                .get("email")
                .cloned()
                .map(|value| SchemaValue::from_json(Some(value)))
                .transpose()?,
            image: self
                .patch
                .get("image")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email_verified: self
                .patch
                .get("emailVerified")
                .cloned()
                .map(|value| SchemaValue::from_json(Some(value)))
                .transpose()?,
            ..Default::default()
        })
    }
}

fn public_response(response: OAuthUserInfoResponse) -> Value {
    json!({"user": types::AccountInfoUser {
        id: None, name: response.user.name, email: response.user.email, image: response.user.image,
        email_verified: response.user.email_verified, additional_fields: response.user.additional_fields,
    }, "data": response.data})
}

#[tokio::test]
async fn signed_claims_match_pinned_profiles_on_code_direct_and_account_reads() {
    let fixture = fixture();
    for sample in fixture["profileCases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|sample| sample["source"] == "id-token")
    {
        let mut claims = sample["profile"].clone();
        let now = chrono::Utc::now().timestamp();
        claims["iat"] = json!(now);
        claims["exp"] = json!(now + 3600);
        let server = GoogleFixture::start(claims).await;
        let mut expected = sample["result"].clone();
        expected["data"]["iat"] = json!(now);
        expected["data"]["exp"] = json!(now + 3600);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = provider(&server);
        config.map_profile_to_user = Some(Arc::new(Mapper {
            seen: seen.clone(),
            patch: sample["mapperPatch"].clone(),
            fail_first: AtomicBool::new(false),
        }));
        let resolved = resolved::ResolvedProvider {
            config,
            generic: None,
        };
        for entry in ["code", "direct", "account"] {
            let request = OAuthUserInfoRequest {
                id_token: Some(server.token.clone()),
                ..Default::default()
            };
            let response = if entry == "direct" {
                let token = types::OAuthIdTokenRequest {
                    token: server.token.clone(),
                    nonce: None,
                    access_token: None,
                    refresh_token: None,
                    user: None,
                };
                let verified = id_token::verify(&resolved, &token, None).await.unwrap();
                social_profile::fetch_user_info_with_claims(&resolved, request, None, verified)
                    .await
                    .unwrap()
            } else if entry == "code" {
                social_profile::fetch_user_info_for_code(&resolved, request, None)
                    .await
                    .unwrap()
            } else {
                social_profile::fetch_user_info_from_provider(&resolved, request, None)
                    .await
                    .unwrap()
            }
            .unwrap();
            assert_eq!(
                public_response(response),
                expected,
                "{} {entry}",
                sample["name"]
            );
        }
        assert_eq!(*seen.lock().unwrap(), vec![expected["data"].clone(); 3]);
        assert_eq!(
            *server.requests.lock().unwrap(),
            ["/jwks", "/jwks", "/jwks"]
        );
    }
}

#[tokio::test]
async fn signed_mapper_failure_uses_the_separate_http_mapper_stage() {
    let fixture = fixture();
    let sample = &fixture["profileCases"][0];
    let mut claims = sample["profile"].clone();
    claims["iss"] = fixture["metadata"]["issuer"].clone();
    claims["aud"] = fixture["metadata"]["clientId"].clone();
    let server = GoogleFixture::start_with_userinfo(claims, Some(sample["profile"].clone())).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut config = provider(&server);
    config.map_profile_to_user = Some(Arc::new(Mapper {
        seen: seen.clone(),
        patch: json!({}),
        fail_first: AtomicBool::new(true),
    }));
    let response = social_profile::fetch_user_info_for_code(
        &resolved::ResolvedProvider {
            config,
            generic: None,
        },
        OAuthUserInfoRequest {
            id_token: Some(server.token.clone()),
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(public_response(response), sample["result"]);
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(seen.lock().unwrap()[1], sample["profile"]);
    assert_eq!(*server.requests.lock().unwrap(), ["/jwks", "/userinfo"]);
}

#[tokio::test]
async fn signed_code_and_direct_success_persist_normal_users_in_sqlite() {
    for direct in [false, true] {
        let mut claims = fixture()["profileCases"][0]["profile"].clone();
        claims["iss"] = fixture()["metadata"]["issuer"].clone();
        claims["aud"] = json!("ordinary-secondary-client");
        claims["iat"] = json!(chrono::Utc::now().timestamp() - 1800);
        let server = GoogleFixture::start(claims).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = provider(&server);
        config.map_profile_to_user = Some(Arc::new(Mapper {
            seen: seen.clone(),
            patch: json!({"name":"Mapped Cognito Owner"}),
            fail_first: AtomicBool::new(false),
        }));
        let plugin = OAuthPlugin::new().add_provider("cognito", config);
        let mut config = crate::plugins::test_helpers::create_test_config();
        config.account.skip_state_cookie_check = true;
        let ctx = crate::plugins::test_helpers::create_test_context_with_config(config).await;
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        start.body = Some(serde_json::to_vec(&if direct { json!({"provider":"cognito","idToken":{"token":server.token}}) } else { json!({"provider":"cognito","callbackURL":"http://localhost:3000/welcome","disableRedirect":true}) }).unwrap());
        let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        if !direct {
            let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
            let state = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1
                .into_owned();
            let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/cognito");
            callback.query = Some(json!({"code":"ordinary-code","state":state}));
            let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome")
            );
        }
        let user = ctx
            .database
            .get_user_by_email("cognito-owner@example.test")
            .await
            .unwrap()
            .unwrap();
        let user_json = serde_json::to_value(&user).unwrap();
        assert_eq!(user_json["name"], "Mapped Cognito Owner");
        assert_eq!(user_json["emailVerified"], true);
        let accounts = ctx
            .database
            .get_user_accounts(&user.id.display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].provider_id.as_str(), Some("cognito"));
        assert_eq!(
            accounts[0].account_id.as_str(),
            Some("ordinary-cognito-owner")
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(
            *server.requests.lock().unwrap(),
            if direct {
                vec!["/jwks"]
            } else {
                vec!["/token", "/jwks"]
            }
        );
    }
}

struct ApplicationVerifier(CognitoOptions);

#[async_trait]
impl OAuthIdTokenVerifier for ApplicationVerifier {
    async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<bool, String> {
        self.0
            .verify("ordinary-client", token, nonce)
            .await
            .map(|_| true)
            .map_err(|error| error.to_string())
    }
}

#[tokio::test]
async fn application_verified_signed_claims_are_not_verified_a_second_time() {
    let mut claims = fixture()["profileCases"][0]["profile"].clone();
    claims["iss"] = fixture()["metadata"]["issuer"].clone();
    claims["aud"] = json!("ordinary-client");
    claims["nonce"] = json!("ordinary-nonce");
    let server = GoogleFixture::start(claims).await;
    let mut config = provider(&server);
    config.verify_id_token = Some(Arc::new(ApplicationVerifier(options(&server))));
    let resolved = resolved::ResolvedProvider {
        config,
        generic: None,
    };
    let token = types::OAuthIdTokenRequest {
        token: server.token.clone(),
        nonce: Some("ordinary-nonce".into()),
        access_token: None,
        refresh_token: None,
        user: None,
    };
    let verified = id_token::verify(&resolved, &token, None).await.unwrap();
    let response = social_profile::fetch_user_info_with_claims(
        &resolved,
        OAuthUserInfoRequest {
            id_token: Some(server.token.clone()),
            ..Default::default()
        },
        Some("ordinary-nonce"),
        verified,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        public_response(response)["user"],
        fixture()["profileCases"][0]["result"]["user"]
    );
    assert_eq!(*server.requests.lock().unwrap(), ["/jwks"]);
}
