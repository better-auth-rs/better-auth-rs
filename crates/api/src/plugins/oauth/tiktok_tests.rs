use std::{
    collections::BTreeMap,
    error::Error,
    sync::{Arc, mpsc},
};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::get,
};
use better_auth_core::{AuthError, AuthResult};
use serde_json::{Value, json};

use super::authorization::{AuthorizationRequest, build_authorization_url};
use super::resolved::ResolvedProvider;
use super::social_profile::fetch_user_info_from_provider;
use super::types::AccountInfoUser;
use super::{
    OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn fixture() -> TestResult<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tiktok-1.7.6.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn field<'a>(value: &'a Value, path: &str) -> TestResult<&'a Value> {
    value
        .pointer(path)
        .ok_or_else(|| format!("Missing TikTok fixture field {path}").into())
}

fn string<'a>(value: &'a Value, path: &str) -> TestResult<&'a str> {
    field(value, path)?
        .as_str()
        .ok_or_else(|| format!("Expected TikTok string {path}").into())
}

fn provider(fixture: &Value) -> TestResult<OAuthProvider> {
    Ok(OAuthProvider::tiktok(
        string(fixture, "/metadata/clientKey")?,
        string(fixture, "/metadata/clientSecret")?,
    ))
}

#[tokio::test]
async fn tiktok_authorization_and_grants_match_pinned_capture() -> TestResult<()> {
    let fixture = fixture()?;
    let defaults = provider(&fixture)?;
    assert!(defaults.client_id.is_empty());
    assert_eq!(
        defaults.client_key.as_deref(),
        Some(string(&fixture, "/metadata/clientKey")?)
    );
    assert_eq!(
        defaults.auth_url,
        string(&fixture, "/metadata/authorizationEndpoint")?
    );
    assert_eq!(
        defaults.token_url,
        string(&fixture, "/metadata/tokenEndpoint")?
    );
    assert_eq!(
        defaults.user_info_url.as_deref(),
        Some(string(&fixture, "/metadata/profileEndpoint")?)
    );
    assert!(!defaults.uses_pkce());
    assert!(defaults.forwards_code_verifier());
    for case in field(&fixture, "/authorization")?
        .as_array()
        .ok_or("Missing authorization cases")?
    {
        let options = field(case, "/options")?;
        let mut config = provider(&fixture)?;
        config.scopes = options
            .get("scope")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        config.disable_default_scope = options
            .get("disableDefaultScope")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        config.redirect_uri = options
            .get("redirectURI")
            .and_then(Value::as_str)
            .map(str::to_owned);
        config.prompt = options
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(endpoint) = options.get("authorizationEndpoint").and_then(Value::as_str) {
            config.auth_url = endpoint.to_owned();
        }
        let scopes: Option<Vec<String>> = case
            .get("scopes")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        let additional = case
            .get("additionalParams")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        let provider = ResolvedProvider {
            config: config.resolve(),
            generic: None,
        };
        let actual = build_authorization_url(
            &provider,
            AuthorizationRequest {
                callback_url: string(&fixture, "/metadata/callbackURL")?,
                scopes: scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: "ordinary-challenge",
                login_hint: Some("reader@example.test"),
                nonce: Some("ordinary-nonce"),
                additional_params: additional.as_ref(),
            },
        )?;
        assert_eq!(actual, string(case, "/url")?, "{}", string(case, "/name")?);
    }
    for case in field(&fixture, "/grants")?
        .as_array()
        .ok_or("Missing grant cases")?
    {
        let mut config = provider(&fixture)?;
        config.client_key = Some(string(case, "/clientKey")?.to_owned());
        config.client_secret = string(case, "/clientSecret")?.to_owned();
        config.redirect_uri = case
            .get("redirectURI")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (requests, tokens) = super::social_token_wire_tests::grants(
            config,
            string(&fixture, "/metadata/callbackURL")?,
            string(&fixture, "/metadata/codeVerifier")?,
            field(&fixture, "/tokenResponse")?.clone(),
        )
        .await?;
        assert_eq!(
            json!(requests),
            *field(case, "/requests")?,
            "{}",
            string(case, "/name")?
        );
        assert_eq!(
            tokens,
            *field(case, "/tokens")?,
            "{}",
            string(case, "/name")?
        );
    }
    Ok(())
}

async fn profile(
    State((response, requests)): State<(Value, mpsc::Sender<Value>)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let authorization = headers
        .get("authorization")
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    requests.send(json!({"method":method.as_str(), "path":uri.path(), "query":query, "authorization":authorization}))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(response))
}

struct Callbacks {
    mapper_inputs: mpsc::Sender<Value>,
    calls: mpsc::Sender<&'static str>,
}

#[async_trait]
impl OAuthProfileMapper for Callbacks {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        self.mapper_inputs
            .send(raw.clone())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(OAuthProfile {
            name: Some(Some("Mapped".to_owned()).into()),
            email: Some(Some("mapped@example.test".to_owned()).into()),
            image: Some(None),
            email_verified: Some(Some(true).into()),
            ..Default::default()
        })
    }
}

#[async_trait]
impl OAuthUserInfoHandler for Callbacks {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        assert_eq!(request.access_token.as_deref(), Some("ordinary-access"));
        self.calls
            .send("get")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "custom-tiktok-user".into(),
                name: Some("Custom".to_owned()).into(),
                email: Some("custom@example.test".to_owned()).into(),
                image: Some(None),
                email_verified: Some(true).into(),
                additional_fields: Default::default(),
            },
            data: json!({"data":{"user":{"open_id":"custom-tiktok-user"}}}),
        }))
    }
}

#[tokio::test]
async fn tiktok_profiles_preserve_envelope_and_skip_mapper_like_pinned_capture() -> TestResult<()> {
    let fixture = fixture()?;
    for case in field(&fixture, "/profiles")?
        .as_array()
        .ok_or("Missing profile cases")?
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let (requests, captured) = mpsc::channel();
        let (mapper_inputs, mapped) = mpsc::channel();
        let (calls, called) = mpsc::channel();
        let mut config = provider(&fixture)?;
        let mut endpoint = url::Url::parse(string(&fixture, "/metadata/profileEndpoint")?)?;
        endpoint
            .set_scheme("http")
            .map_err(|()| "Cannot set profile scheme")?;
        endpoint.set_host(Some("127.0.0.1"))?;
        endpoint
            .set_port(Some(listener.local_addr()?.port()))
            .map_err(|()| "Cannot set profile port")?;
        config.user_info_url = Some(endpoint.to_string());
        let router = Router::new()
            .route("/v2/user/info/", get(profile))
            .with_state((field(case, "/profile")?.clone(), requests));
        let callbacks = Arc::new(Callbacks {
            mapper_inputs,
            calls,
        });
        if string(case, "/mode")? != "default" {
            config.map_profile_to_user = Some(callbacks.clone());
        }
        if string(case, "/mode")? == "custom" {
            config.get_user_info = Some(callbacks);
        }
        let provider = ResolvedProvider {
            config: config.resolve(),
            generic: None,
        };
        let explicit_accepts = if provider.config.get_user_info.is_none() {
            let request = provider
                .config
                .user_info_request(endpoint.as_str(), "ordinary-access")
                .build()?;
            vec![
                request
                    .headers()
                    .get("accept")
                    .map(|value| value.to_str())
                    .transpose()?
                    .map(str::to_owned),
            ]
        } else {
            Vec::new()
        };
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let response = fetch_user_info_from_provider(
            &provider,
            OAuthUserInfoRequest {
                access_token: Some("ordinary-access".into()),
                ..Default::default()
            },
            None,
        )
        .await;
        server.abort();
        let response = response?.ok_or("Missing TikTok profile")?;
        assert_eq!(response.user.id, string(case, "/subject")?);
        let user = response.user;
        let user = AccountInfoUser {
            id: provider
                .config
                .account_info_includes_id()
                .then_some(user.id),
            name: user.name,
            email: user.email,
            image: user.image,
            email_verified: user.email_verified,
            additional_fields: user.additional_fields,
        };
        assert_eq!(
            json!({"user":user,"data":response.data}),
            *field(case, "/result")?,
            "{}",
            string(case, "/name")?
        );
        assert_eq!(
            json!(captured.try_iter().collect::<Vec<_>>()),
            *field(case, "/requests")?
        );
        assert_eq!(
            json!(mapped.try_iter().collect::<Vec<_>>()),
            *field(case, "/mapperInputs")?
        );
        assert_eq!(
            json!(called.try_iter().collect::<Vec<_>>()),
            *field(case, "/calls")?
        );
        assert_eq!(json!(explicit_accepts), *field(case, "/explicitAccepts")?);
    }
    Ok(())
}
