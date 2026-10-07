use std::{error::Error, sync::Arc};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthPlugin, AuthRequest, AuthResult, AuthUser, HttpMethod};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::{
    GoogleOptions, OAuthConfig, OAuthPlugin, OAuthProfile, OAuthProfileMapper, OAuthProvider,
    authorization::{AuthorizationRequest, build_authorization_url},
    google_test_support::GoogleFixture,
    resolved::ResolvedProvider,
};
use crate::plugins::{
    one_tap::{OneTapConfig, OneTapPlugin},
    test_helpers,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/google-client-ids-1.7.6.json"
    ))?)?)
}

fn string<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing Google fixture string: {key}").into())
}

fn provider(metadata: &Value) -> TestResult<OAuthProvider> {
    let mut provider = OAuthProvider::google_with_options(
        string(metadata, "clientId")?,
        string(metadata, "clientSecret")?,
        GoogleOptions {
            additional_client_ids: serde_json::from_value(metadata["additionalClientIds"].clone())?,
        },
    );
    provider
        .authorization_params
        .push(("hd".into(), string(&metadata["profile"], "hd")?.into()));
    Ok(provider)
}

#[tokio::test]
async fn google_client_ids_keep_primary_authorization_and_grant_requests() -> TestResult<()> {
    let fixture = fixture()?;
    let metadata = &fixture["metadata"];
    let verifier = string(metadata, "codeVerifier")?;
    let callback = string(metadata, "callbackURL")?;
    let configured = provider(metadata)?;
    let resolved = ResolvedProvider {
        config: configured.resolve(),
        generic: None,
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let url = build_authorization_url(
        &resolved,
        AuthorizationRequest {
            callback_url: callback,
            state: "ordinary-state",
            code_challenge: &challenge,
            scopes: None,
            login_hint: None,
            nonce: None,
            additional_params: None,
        },
    )?;
    let url = url::Url::parse(&url)?;
    let query: serde_json::Map<String, Value> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
        .collect();
    assert_eq!(
        json!({"origin": url.origin().ascii_serialization(), "path": url.path(), "query": query}),
        fixture["authorization"]
    );
    let (requests, tokens) = super::social_token_wire_tests::grants(
        configured,
        callback,
        verifier,
        fixture["grants"]["rawResponse"].clone(),
    )
    .await?;
    assert_eq!(json!(requests), fixture["grants"]["requests"]);
    assert_eq!(tokens, fixture["grants"]["tokens"]);
    Ok(())
}

struct Mapper(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.0.lock().await.push(json!({
            "sub": profile["sub"], "aud": profile["aud"],
            "name": profile["name"], "hd": profile["hd"],
        }));
        Ok(OAuthProfile {
            name: Some(Some("Mapped Google Owner".into()).into()),
            ..Default::default()
        })
    }
}

fn post(path: &str, body: Value) -> TestResult<AuthRequest> {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    request.body = Some(serde_json::to_vec(&body)?);
    Ok(request)
}

#[tokio::test]
async fn google_client_ids_sign_in_and_one_tap_match_pinned_successes() -> TestResult<()> {
    let fixture = fixture()?;
    let metadata = &fixture["metadata"];
    for sample in fixture["flows"]
        .as_array()
        .ok_or("missing Google flow cases")?
    {
        let mode = string(sample, "mode")?;
        let mut claims = metadata["profile"].clone();
        claims["aud"] = sample["audience"].clone();
        claims["nonce"] = json!("ordinary-nonce");
        let server = GoogleFixture::start(claims).await;
        let inputs = Arc::new(Mutex::new(Vec::new()));
        let mut configured = provider(metadata)?;
        server.configure(&mut configured);
        configured.map_profile_to_user = Some(Arc::new(Mapper(inputs.clone())));
        let mut ctx = test_helpers::create_test_context().await;
        let mut oauth_config = OAuthConfig::default();
        let _ = oauth_config.providers.insert("google".into(), configured);
        ctx.extensions.insert(oauth_config.clone());
        let plugin = OAuthPlugin::with_config(oauth_config);
        let response = if mode == "oneTap" {
            let one_tap = OneTapPlugin::with_config(OneTapConfig {
                client_id: sample
                    .get("oneTapClientIds")
                    .map(|ids| serde_json::from_value(ids.clone()))
                    .transpose()?,
                google_jwks_url: format!("{}/jwks", server.url),
                ..Default::default()
            });
            one_tap
                .on_request(
                    &post("/one-tap/callback", json!({"idToken":server.token}))?,
                    &ctx,
                )
                .await?
                .ok_or("missing One Tap response")?
        } else if mode == "direct" {
            plugin.on_request(&post("/sign-in/social", json!({
                "provider":"google", "idToken":{"token":server.token, "nonce":"ordinary-nonce"}
            }))?, &ctx).await?.ok_or("missing direct response")?
        } else {
            assert_eq!(mode, "code");
            let start = plugin.on_request(&post("/sign-in/social", json!({
                "provider":"google", "callbackURL":"http://localhost:3000/welcome", "disableRedirect":true
            }))?, &ctx).await?.ok_or("missing code start")?;
            assert_eq!(start.status, 200);
            let body: Value = serde_json::from_slice(&start.body.bytes()?)?;
            let url = url::Url::parse(string(&body, "url")?)?;
            let state = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .ok_or("missing state")?
                .1
                .into_owned();
            let cookie = start
                .headers
                .get_all("Set-Cookie")
                .filter_map(|value| value.split(';').next())
                .collect::<Vec<_>>()
                .join("; ");
            assert!(!cookie.is_empty());
            let mut request = AuthRequest::new(HttpMethod::Get, "/callback/google");
            let _ = request.headers.insert("cookie".into(), cookie);
            request.query = Some(json!({"code":"ordinary-code", "state":state}));
            plugin
                .on_request(&request, &ctx)
                .await?
                .ok_or("missing code callback")?
        };
        let user = ctx
            .database
            .get_user_by_email(string(&metadata["profile"], "email")?)
            .await?
            .ok_or("missing Google user")?;
        let user_id = user.id().display_string()?;
        let user = serde_json::to_value(user)?;
        let accounts = ctx.database.get_user_accounts(&user_id).await?;
        assert_eq!(accounts.len(), 1);
        let account = accounts.first().ok_or("missing Google account")?;
        let result = json!({
            "status": response.status, "location": response.headers.get("Location"),
            "user": {"name":user["name"], "email":user["email"], "emailVerified":user["emailVerified"], "image":user["image"]},
            "account": {"providerId":account.provider_id, "accountId":account.account_id},
            "sessions": ctx.session_manager().list_user_sessions(&user_id).await?.len(),
            "mapperInputs": *inputs.lock().await,
        });
        assert_eq!(result, sample["result"], "{mode}: {}", sample["audience"]);
        let expected_requests = if mode == "code" {
            vec!["/token", "/jwks"]
        } else {
            vec!["/jwks"]
        };
        assert_eq!(
            *server
                .requests
                .lock()
                .map_err(|_| "poisoned Google fixture log")?,
            expected_requests
        );
    }
    Ok(())
}
