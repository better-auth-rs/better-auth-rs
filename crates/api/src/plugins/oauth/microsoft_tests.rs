use std::{
    error::Error,
    sync::{Arc, mpsc},
};

use async_trait::async_trait;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthPlugin, AuthRequest, AuthResult, AuthUser, HttpMethod};
use indexmap::IndexMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::{
    ClientAssertion, ClientAssertionContext, MicrosoftOptions, MicrosoftProfilePhotoSize,
    OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
    authorization::{AuthorizationRequest, build_authorization_url},
    google_test_support::GoogleFixture,
    id_token,
    resolved::ResolvedProvider,
    social_profile::fetch_user_info_from_provider,
    types::AccountInfoUser,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/social-microsoft-1.7.6.json"
    ))?)?)
}

fn options(input: &Value) -> TestResult<MicrosoftOptions> {
    Ok(MicrosoftOptions {
        tenant_id: input["tenantId"].as_str().map(str::to_owned),
        authority: input["authority"].as_str().map(str::to_owned),
        disable_profile_photo: input["disableProfilePhoto"].as_bool().unwrap_or(false),
        profile_photo_size: match input["profilePhotoSize"].as_u64() {
            None | Some(48) => MicrosoftProfilePhotoSize::Size48,
            Some(96) => MicrosoftProfilePhotoSize::Size96,
            Some(_) => return Err("unexpected photo size in Microsoft fixture".into()),
        },
        ..Default::default()
    })
}

fn config(fixture: &Value, input: &Value, options: MicrosoftOptions) -> TestResult<OAuthProvider> {
    let metadata = &fixture["metadata"];
    let mut config = OAuthProvider::microsoft(
        metadata["clientId"]
            .as_str()
            .ok_or("missing Microsoft client ID")?,
        input["clientSecret"].as_str().unwrap_or(
            metadata["clientSecret"]
                .as_str()
                .ok_or("missing Microsoft secret")?,
        ),
        options,
    )?;
    config.client_key = metadata["clientKey"].as_str().map(str::to_owned);
    config.scopes = input
        .get("scope")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?;
    config.disable_default_scope = input["disableDefaultScope"].as_bool().unwrap_or(false);
    config.prompt = input["prompt"].as_str().map(str::to_owned);
    config.redirect_uri = input["redirectURI"].as_str().map(str::to_owned);
    Ok(config)
}

fn resolved(config: OAuthProvider) -> ResolvedProvider {
    ResolvedProvider {
        config: config.resolve(),
        generic: None,
    }
}

fn profile_json(response: OAuthUserInfoResponse, include_id: bool) -> Value {
    let user = response.user;
    let view = AccountInfoUser {
        id: include_id.then_some(user.id),
        name: user.name,
        email: user.email,
        image: user.image,
        email_verified: user.email_verified,
        additional_fields: user.additional_fields,
    };
    json!({"user": view, "data": response.data})
}

#[test]
fn microsoft_authorization_matches_pinned_configuration() -> TestResult<()> {
    let fixture = fixture()?;
    let metadata = &fixture["metadata"];
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(
        metadata["codeVerifier"]
            .as_str()
            .ok_or("missing verifier")?
            .as_bytes(),
    ));
    for sample in fixture["authorization"]
        .as_array()
        .ok_or("missing authorization cases")?
    {
        let provider = resolved(config(
            &fixture,
            &sample["options"],
            options(&sample["options"])?,
        )?);
        let scopes: Option<Vec<String>> = sample
            .get("requestScopes")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        let additional: Option<IndexMap<String, String>> = sample
            .get("additionalParams")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        let url = build_authorization_url(
            &provider,
            AuthorizationRequest {
                callback_url: metadata["callbackURL"].as_str().ok_or("missing callback")?,
                scopes: scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: &challenge,
                login_hint: Some("microsoft@example.test"),
                nonce: Some("ordinary-nonce"),
                additional_params: additional.as_ref(),
            },
        )?;
        assert_eq!(json!(url), sample["url"], "{}", sample["name"]);
    }
    Ok(())
}

struct Assertion(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl ClientAssertion for Assertion {
    async fn get_client_assertion(
        &self,
        context: ClientAssertionContext<'_>,
    ) -> AuthResult<String> {
        let endpoint = url::Url::parse(context.token_endpoint)
            .map_err(|error| better_auth_core::AuthError::internal(error.to_string()))?;
        assert_eq!(endpoint.path(), "/token");
        self.0.lock().await.push(json!({
            "clientId": context.client_id, "grantType": context.grant_type.as_str(),
        }));
        Ok("ordinary-assertion".into())
    }
}

#[tokio::test]
async fn microsoft_code_refresh_and_assertion_match_pinned_requests() -> TestResult<()> {
    let fixture = fixture()?;
    let metadata = &fixture["metadata"];
    for sample in fixture["grants"].as_array().ok_or("missing grant cases")? {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut provider_options = options(&sample["options"])?;
        if sample["assertion"].as_bool().unwrap_or(false) {
            provider_options.client_assertion = Some(Arc::new(Assertion(calls.clone())));
        }
        let config = config(&fixture, &sample["options"], provider_options)?;
        let endpoint = config.token_url.clone();
        let (requests, tokens) = super::social_token_wire_tests::grants(
            config,
            metadata["callbackURL"].as_str().ok_or("missing callback")?,
            metadata["codeVerifier"]
                .as_str()
                .ok_or("missing verifier")?,
            sample["rawResponse"].clone(),
        )
        .await?;
        assert_eq!(json!(requests), sample["requests"], "{}", sample["name"]);
        assert_eq!(tokens, sample["tokens"], "{}", sample["name"]);
        let expected = sample["assertionCalls"]
            .as_array()
            .ok_or("missing assertion calls")?
            .iter()
            .map(|call| {
                assert_eq!(call["tokenEndpoint"], endpoint);
                json!({"clientId": call["clientId"], "grantType": call["grantType"]})
            })
            .collect::<Vec<_>>();
        assert_eq!(*calls.lock().await, expected);
    }
    Ok(())
}

struct PhotoServer {
    url: String,
    requests: mpsc::Receiver<Value>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for PhotoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn photo(
    State(sender): State<mpsc::Sender<Value>>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
) -> Result<([(&'static str, &'static str); 1], Vec<u8>), StatusCode> {
    sender.send(json!({
        "url": format!("https://graph.microsoft.com{uri}"), "method": method.as_str(),
        "authorization": headers.get("authorization").map(|value| value.to_str()).transpose().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    })).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [("content-type", "image/jpeg")],
        vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46],
    ))
}

impl PhotoServer {
    async fn start() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (sender, requests) = mpsc::channel();
        let router = Router::new().fallback(photo).with_state(sender);
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Ok(Self {
            url,
            requests,
            task,
        })
    }
}

struct Mapper {
    inputs: Arc<Mutex<Vec<Value>>>,
    patch: Value,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        self.inputs.lock().await.push(raw.clone());
        Ok(OAuthProfile {
            name: self
                .patch
                .get("name")
                .map(|value| better_auth_core::SchemaValue::from_json(Some(value.clone())))
                .transpose()?,
            image: self
                .patch
                .get("image")
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()?,
            email_verified: self
                .patch
                .get("emailVerified")
                .map(|value| better_auth_core::SchemaValue::from_json(Some(value.clone())))
                .transpose()?,
            additional_fields: better_auth_core::FieldMap::from_json(
                self.patch
                    .get("locale")
                    .map(|value| serde_json::Map::from_iter([("locale".into(), value.clone())]))
                    .unwrap_or_default(),
            )?,
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn microsoft_profile_photo_and_mapper_match_pinned_results() -> TestResult<()> {
    let fixture = fixture()?;
    let server = PhotoServer::start().await?;
    for sample in fixture["profiles"].as_array().ok_or("missing profiles")? {
        let inputs = Arc::new(Mutex::new(Vec::new()));
        let mut provider_options = options(&sample["options"])?;
        let endpoint = url::Url::parse(&provider_options.photo_endpoint())?;
        provider_options.photo_url = Some(format!("{}{}", server.url, endpoint.path()));
        let mut config = config(&fixture, &sample["options"], provider_options)?;
        if let Some(patch) = sample.get("mapped") {
            config.map_profile_to_user = Some(Arc::new(Mapper {
                inputs: inputs.clone(),
                patch: patch.clone(),
            }));
        }
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &sample["profile"],
            &EncodingKey::from_secret(
                fixture["metadata"]["clientSecret"]
                    .as_str()
                    .ok_or("missing secret")?
                    .as_bytes(),
            ),
        )?;
        let response = fetch_user_info_from_provider(
            &resolved(config),
            OAuthUserInfoRequest {
                id_token: Some(token),
                access_token: sample["accessToken"].as_str().map(str::to_owned),
                ..Default::default()
            },
            None,
        )
        .await?
        .ok_or("missing Microsoft profile")?;
        assert_eq!(response.user.id, sample["subject"], "{}", sample["name"]);
        assert_eq!(
            profile_json(response, false),
            sample["result"],
            "{}",
            sample["name"]
        );
        assert_eq!(json!(*inputs.lock().await), sample["mapperInputs"]);
        assert_eq!(
            json!(server.requests.try_iter().collect::<Vec<_>>()),
            sample["requests"]
        );
    }
    Ok(())
}

struct Custom(Arc<Mutex<usize>>);

#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        *self.0.lock().await += 1;
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "application-owner".into(),
                name: Some("Application Owner".into()).into(),
                email: Some("application@example.test".into()).into(),
                image: None,
                email_verified: Some(true).into(),
                additional_fields: Default::default(),
            },
            data: json!({"source":"application"}),
        }))
    }
}

#[tokio::test]
async fn microsoft_custom_handler_precedes_the_profile_mapper() -> TestResult<()> {
    let fixture = fixture()?;
    let server = PhotoServer::start().await?;
    let calls = Arc::new(Mutex::new(0));
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let mut config = config(
        &fixture,
        &json!({}),
        MicrosoftOptions {
            photo_url: Some(server.url.clone()),
            ..Default::default()
        },
    )?;
    config.get_user_info = Some(Arc::new(Custom(calls.clone())));
    config.map_profile_to_user = Some(Arc::new(Mapper {
        inputs: inputs.clone(),
        patch: json!({"name":"Unused"}),
    }));
    let response = fetch_user_info_from_provider(
        &resolved(config),
        OAuthUserInfoRequest {
            access_token: Some("ordinary-access".into()),
            ..Default::default()
        },
        None,
    )
    .await?
    .ok_or("missing custom profile")?;
    assert_eq!(profile_json(response, true), fixture["custom"]["result"]);
    assert_eq!(json!(*calls.lock().await), fixture["custom"]["calls"]);
    assert_eq!(
        json!(inputs.lock().await.len()),
        fixture["custom"]["mapperCalls"]
    );
    assert_eq!(
        json!(server.requests.try_iter().collect::<Vec<_>>()),
        fixture["custom"]["requests"]
    );
    Ok(())
}

#[tokio::test]
async fn microsoft_signed_ordinary_tenants_use_the_shared_oidc_boundary() -> TestResult<()> {
    let fixture = fixture()?;
    for sample in fixture["signed"].as_array().ok_or("missing signed cases")? {
        let claims = json!({"oid":"ordinary-microsoft-owner", "sub":"ordinary-app-subject", "tid":sample["tid"], "iss":format!("{}/{}/v2.0", sample["authority"].as_str().ok_or("missing authority")?, sample["tid"].as_str().ok_or("missing tenant")?), "aud":sample["audience"], "name":"Microsoft Owner", "email":"microsoft@example.test", "nonce":"ordinary-nonce"});
        let server = GoogleFixture::start(claims.clone()).await;
        let options = MicrosoftOptions {
            tenant_id: sample["tenant"].as_str().map(str::to_owned),
            authority: sample["authority"].as_str().map(str::to_owned),
            additional_client_ids: vec![
                fixture["metadata"]["secondaryClientId"]
                    .as_str()
                    .ok_or("missing secondary client")?
                    .into(),
            ],
            disable_profile_photo: true,
            jwks_url: Some(format!("{}/jwks", server.url)),
            ..Default::default()
        };
        let provider = resolved(config(&fixture, &json!({}), options)?);
        let verified = id_token::verify(
            &provider,
            &serde_json::from_value(json!({"token":server.token, "nonce":"ordinary-nonce"}))?,
            None,
        )
        .await?;
        assert_eq!(json!(verified.is_some()), sample["verified"]);
        let response = super::social_profile::fetch_user_info_with_claims(
            &provider,
            OAuthUserInfoRequest {
                id_token: Some(server.token.clone()),
                ..Default::default()
            },
            Some("ordinary-nonce"),
            verified,
        )
        .await?
        .ok_or("missing verified profile")?;
        assert_eq!(response.user.id, "ordinary-microsoft-owner");
        assert_eq!(
            *server.requests.lock().map_err(|_| "poisoned fixture log")?,
            ["/jwks"]
        );
    }
    Ok(())
}

#[tokio::test]
async fn microsoft_signed_direct_and_code_success_persist_the_oid_account() -> TestResult<()> {
    let fixture = fixture()?;
    for direct in [false, true] {
        let server = GoogleFixture::start(json!({
            "oid":"ordinary-microsoft-owner", "sub":"ordinary-app-subject", "tid":"ordinary-tenant",
            "iss":"https://login.microsoftonline.com/ordinary-tenant/v2.0", "aud":fixture["metadata"]["clientId"],
            "name":"Microsoft Owner", "email":"microsoft@example.test", "email_verified":true,
        })).await;
        let options = MicrosoftOptions {
            disable_profile_photo: true,
            jwks_url: Some(format!("{}/jwks", server.url)),
            ..Default::default()
        };
        let mut provider = config(&fixture, &json!({}), options)?;
        provider.token_url = format!("{}/token", server.url);
        let plugin = OAuthPlugin::new().add_provider("microsoft", provider);
        let config = crate::plugins::test_helpers::create_test_config();
        let ctx = crate::plugins::test_helpers::create_test_context_with_config(config).await;
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        start.body = Some(serde_json::to_vec(&if direct {
            json!({"provider":"microsoft","idToken":{"token":server.token}})
        } else {
            json!({"provider":"microsoft","callbackURL":"http://localhost:3000/welcome","disableRedirect":true})
        })?);
        let response = plugin
            .on_request(&start, &ctx)
            .await?
            .ok_or("missing sign-in response")?;
        assert_eq!(response.status, 200);
        if !direct {
            let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
            let url = url::Url::parse(body["url"].as_str().ok_or("missing authorization URL")?)?;
            let state = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .ok_or("missing state")?
                .1
                .into_owned();
            let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/microsoft");
            let cookie = response
                .headers
                .get_all("Set-Cookie")
                .filter_map(|value| value.split(';').next())
                .collect::<Vec<_>>()
                .join("; ");
            assert!(!cookie.is_empty());
            let _ = callback.headers.insert("cookie".into(), cookie);
            callback.query = Some(json!({"code":"ordinary-code", "state":state}));
            let response = plugin
                .on_request(&callback, &ctx)
                .await?
                .ok_or("missing callback response")?;
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome")
            );
        }
        let user = ctx
            .database
            .get_user_by_email("microsoft@example.test")
            .await?
            .ok_or("missing user")?;
        let user_id = user.id().display_string()?;
        let user_json = serde_json::to_value(&user)?;
        assert_eq!(user_json["name"], "Microsoft Owner");
        assert_eq!(user_json["emailVerified"], true);
        let accounts = ctx.database.get_user_accounts(&user_id).await?;
        assert_eq!(accounts.len(), 1);
        let account = accounts.first().ok_or("missing Microsoft account")?;
        assert_eq!(account.provider_id.as_str(), Some("microsoft"));
        assert_eq!(
            account.account_id.as_str(),
            Some("ordinary-microsoft-owner")
        );
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(&user_id)
                .await?
                .len(),
            1
        );
        assert_eq!(
            *server.requests.lock().map_err(|_| "poisoned fixture log")?,
            if direct {
                vec!["/jwks"]
            } else {
                vec!["/token"]
            }
        );
    }
    Ok(())
}
