#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Ordinary local contracts fail immediately when fixture setup or captured results change."
)]

use super::*;
use base64::Engine;
use better_auth_core::{AuthError, SchemaValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, atomic::Ordering};

#[path = "paybin_test_support.rs"]
mod support;
use support::{Mapper, Server, fixture, public, resolved};
#[path = "paybin_sqlite_tests.rs"]
mod sqlite;

fn configured(options: &Value) -> OAuthProvider {
    let metadata = &fixture()["metadata"];
    let client = options["clientId"]
        .as_str()
        .unwrap_or(metadata["clientId"].as_str().unwrap());
    let secret = options["clientSecret"]
        .as_str()
        .unwrap_or(metadata["clientSecret"].as_str().unwrap());
    let mut config = options["issuer"].as_str().map_or_else(
        || OAuthProvider::paybin(client, secret),
        |issuer| OAuthProvider::paybin_with_issuer(client, secret, issuer),
    );
    config.scopes = options
        .get("scope")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .unwrap();
    config.disable_default_scope = options["disableDefaultScope"].as_bool().unwrap_or(false);
    config.prompt = options["prompt"].as_str().map(str::to_owned);
    config.redirect_uri = options["redirectURI"].as_str().map(str::to_owned);
    if let Some(endpoint) = options["authorizationEndpoint"].as_str() {
        config.auth_url = endpoint.into();
    }
    config
}

fn authorization(options: &Value, input: &Value) -> AuthResult<String> {
    let challenge = input["codeVerifier"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(value.as_bytes()))
        })
        .unwrap_or_default();
    let scopes: Option<Vec<String>> = input
        .get("scopes")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .unwrap();
    let additional_params = input
        .get("additionalParams")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .unwrap();
    authorization::build_authorization_url(
        &resolved(configured(options)),
        authorization::AuthorizationRequest {
            callback_url: input["redirectURI"].as_str().unwrap(),
            scopes: scopes.as_deref(),
            state: input["state"].as_str().unwrap(),
            code_challenge: &challenge,
            login_hint: input["loginHint"].as_str(),
            nonce: input["idTokenNonce"].as_str(),
            additional_params: additional_params.as_ref(),
        },
    )
}

#[test]
fn authorization_and_configuration_match_pinned_paybin() {
    let fixture = fixture();
    for sample in fixture["scopeCases"].as_array().unwrap() {
        assert_eq!(
            authorization(&sample["options"], &sample["input"]).unwrap(),
            sample["url"].as_str().unwrap(),
            "{}",
            sample["name"]
        );
    }
    for sample in fixture["configurationErrors"].as_array().unwrap() {
        let error = authorization(&sample["options"], &sample["input"]).unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == sample["error"]["message"].as_str().unwrap())
        );
    }
}

fn token_json(token: OAuthTokenSet) -> Value {
    let mut result = serde_json::Map::from_iter([("scopes".into(), json!(token.scopes))]);
    for (key, value) in [
        ("tokenType", token.token_type),
        ("accessToken", token.access_token),
        ("refreshToken", token.refresh_token),
        (
            "idToken",
            token.id_token.map(|_| "<signed ID token>".into()),
        ),
    ] {
        if let Some(value) = value {
            let _ = result.insert(key.into(), value.into());
        }
    }
    if let Some(mut raw) = token.raw {
        raw["id_token"] = "<signed ID token>".into();
        let _ = result.insert("raw".into(), raw);
    }
    Value::Object(result)
}

#[tokio::test]
async fn paybin_grants_use_pinned_post_fields_and_normal_http_errors() {
    let fixture = fixture();
    let server = Server::start(fixture["profileCases"][0]["profile"].clone()).await;
    let resolved = resolved(server.provider());
    for sample in fixture["grants"].as_array().unwrap() {
        server.requests.lock().unwrap().clear();
        server
            .unavailable
            .store(sample.get("error").is_some(), Ordering::SeqCst);
        let result = if sample["name"].as_str().unwrap().starts_with("code") {
            provider_tokens::validate_authorization_code_via_provider(
                &resolved,
                "ordinary-code",
                fixture["metadata"]["redirectURI"].as_str().unwrap(),
                fixture["metadata"]["verifier"].as_str(),
                Some("ordinary-unused-device"),
            )
            .await
        } else {
            provider_tokens::refresh_tokens_via_provider(
                &resolved,
                "ordinary-refresh",
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
        };
        assert_eq!(json!(*server.requests.lock().unwrap()), sample["requests"]);
        if sample.get("error").is_some() {
            assert!(matches!(result, Err(AuthError::Internal(_))));
        } else {
            assert_eq!(token_json(result.unwrap()), sample["response"]);
        }
    }
}

#[tokio::test]
async fn verified_paybin_profiles_and_mapper_data_match_pinned_results() {
    for sample in fixture()["profileCases"].as_array().unwrap() {
        let server = Server::start(sample["profile"].clone()).await;
        let seen = Arc::default();
        let mut config = server.provider();
        config.map_profile_to_user = Some(Arc::new(Mapper {
            patch: sample["patch"].clone(),
            seen: Arc::clone(&seen),
            error: false,
        }));
        let resolved = resolved(config);
        for code_flow in [true, false] {
            let response = if code_flow {
                social_profile::fetch_user_info_for_code(&resolved, server.request(), None).await
            } else {
                social_profile::fetch_user_info_from_provider(&resolved, server.request(), None)
                    .await
            }
            .unwrap()
            .unwrap();
            assert_eq!(response.user.id, sample["profile"]["sub"].as_str().unwrap());
            let result = public(response);
            assert_eq!(
                result["user"], sample["result"]["user"],
                "{}",
                sample["name"]
            );
            assert_eq!(result["data"], server.claims);
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [server.claims.clone(), server.claims.clone()]
        );
        assert_eq!(
            *server.paths.lock().unwrap(),
            [
                "/.well-known/openid-configuration",
                "/keys/active",
                "/.well-known/openid-configuration",
                "/keys/active"
            ]
        );
    }
}

struct CustomInfo {
    mode: String,
    calls: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl OAuthUserInfoHandler for CustomInfo {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.calls.lock().unwrap().push("custom".into());
        if self.mode == "custom error" {
            return Err(AuthError::internal("Ordinary Paybin custom error"));
        }
        if self.mode == "custom null" {
            return Ok(None);
        }
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "ordinary-paybin-owner".into(),
                name: Some("Custom Owner".into()).into(),
                email: Some("custom@example.com".into()).into(),
                image: None,
                email_verified: Some(false).into(),
                additional_fields: Default::default(),
            },
            data: json!({"ordinary":"custom profile"}),
        }))
    }
}

#[tokio::test]
async fn paybin_missing_profile_custom_handlers_and_mapper_keep_original_results() {
    let fixture = fixture();
    let server = Server::start(fixture["profileCases"][0]["profile"].clone()).await;
    for sample in fixture["specialCases"].as_array().unwrap() {
        let mode = sample["mode"].as_str().unwrap();
        let calls = Arc::default();
        let seen = Arc::default();
        let mut provider = server.provider();
        provider.map_profile_to_user = Some(Arc::new(Mapper {
            patch: json!({}),
            seen: Arc::clone(&seen),
            error: true,
        }));
        if mode.starts_with("custom") {
            provider.get_user_info = Some(Arc::new(CustomInfo {
                mode: mode.into(),
                calls: Arc::clone(&calls),
            }));
        }
        let result = social_profile::fetch_user_info_for_code(
            &resolved(provider),
            if mode == "mapper error" {
                server.request()
            } else {
                Default::default()
            },
            None,
        )
        .await;
        let mut events = calls.lock().unwrap().clone();
        events.extend(seen.lock().unwrap().iter().map(|_| "mapper".to_owned()));
        match result {
            Ok(result) => {
                events.push("returned".into());
                assert_eq!(
                    result.map(public),
                    sample.get("result").filter(|v| !v.is_null()).cloned()
                );
            }
            Err(error) => {
                events.push("rejected".into());
                assert!(
                    matches!(error, AuthError::Internal(message) if message == sample["error"]["message"].as_str().unwrap())
                );
            }
        }
        assert_eq!(json!(events), sample["events"]);
    }
}

struct ApplicationVerifier {
    issuer: String,
}
#[async_trait]
impl OAuthIdTokenVerifier for ApplicationVerifier {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String> {
        providers::paybin::verify(&self.issuer, "ordinary-client", token, nonce)
            .await
            .map(|_| true)
            .map_err(|error| error.to_string())
    }
}

#[tokio::test]
async fn application_verified_paybin_profile_uses_the_completed_signature_check() {
    let server = Server::start(fixture()["profileCases"][0]["profile"].clone()).await;
    let mut provider = server.provider();
    provider.verify_id_token = Some(Arc::new(ApplicationVerifier {
        issuer: server.issuer.clone(),
    }));
    let provider = resolved(provider);
    let verified = id_token::verify(
        &provider,
        &types::OAuthIdTokenRequest {
            token: server.token.clone(),
            nonce: None,
            access_token: None,
            refresh_token: None,
            user: None,
        },
    )
    .await
    .unwrap();
    let profile =
        social_profile::fetch_user_info_with_claims(&provider, server.request(), None, verified)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(public(profile)["data"], server.claims);
    assert_eq!(
        *server.paths.lock().unwrap(),
        ["/.well-known/openid-configuration", "/keys/active"]
    );
}

struct CustomRefresh(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl OAuthRefreshTokenHandler for CustomRefresh {
    async fn refresh_access_token(
        &self,
        token: &str,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        self.0.lock().unwrap().push(token.into());
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            refresh_token: Some("custom-refresh".into()),
            scopes: vec!["custom".into()],
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn paybin_custom_refresh_retains_precedence() {
    let calls = Arc::default();
    let mut provider = OAuthProvider::paybin("ordinary-client", "ordinary-client-secret");
    provider.refresh_access_token = Some(Arc::new(CustomRefresh(Arc::clone(&calls))));
    let token = provider_tokens::refresh_tokens_via_provider(
        &resolved(provider),
        "ordinary-refresh",
        &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
    )
    .await
    .unwrap();
    assert_eq!(token_json(token), fixture()["customRefresh"]["response"]);
    assert_eq!(
        json!(*calls.lock().unwrap()),
        fixture()["customRefresh"]["events"]
    );
}
