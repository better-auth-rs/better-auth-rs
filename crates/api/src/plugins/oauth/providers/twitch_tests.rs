use async_trait::async_trait;
use better_auth_core::AuthResult;
use indexmap::IndexMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::{error::Error, sync::Arc};
use tokio::sync::Mutex;

use crate::plugins::oauth::{
    OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse, TwitchOptions,
    authorization::{AuthorizationRequest, build_authorization_url},
    resolved::ResolvedProvider,
    social_profile::fetch_user_info_from_provider,
    types::AccountInfoUser,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn fixture() -> TestResult<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/social-twitch-1.7.6.json"
    );
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn config(fixture: &Value, options: &Value) -> TestResult<OAuthProvider> {
    let mut provider = OAuthProvider::twitch(
        fixture["clientId"]
            .as_str()
            .ok_or("missing Twitch client ID")?,
        fixture["clientSecret"]
            .as_str()
            .ok_or("missing Twitch client secret")?,
        TwitchOptions {
            claims: options
                .get("claims")
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()?,
        },
    );
    provider.client_key = Some(
        fixture["clientKey"]
            .as_str()
            .ok_or("missing Twitch client key")?
            .into(),
    );
    provider.scopes = options
        .get("scope")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?;
    provider.disable_default_scope = options["disableDefaultScope"].as_bool().unwrap_or(false);
    provider.prompt = options["prompt"].as_str().map(str::to_owned);
    if let Some(url) = options["authorizationEndpoint"].as_str() {
        provider.auth_url = url.into();
    }
    provider.redirect_uri = options["redirectURI"].as_str().map(str::to_owned);
    Ok(provider)
}

fn resolved(config: OAuthProvider) -> ResolvedProvider {
    ResolvedProvider {
        config: config.resolve(),
        generic: None,
    }
}

fn tokens(fixture: &Value, profile: &Value) -> TestResult<OAuthUserInfoRequest> {
    let secret = fixture["clientSecret"]
        .as_str()
        .ok_or("missing Twitch client secret")?;
    Ok(OAuthUserInfoRequest {
        access_token: Some("ordinary-access".into()),
        id_token: Some(jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            profile,
            &EncodingKey::from_secret(secret.as_bytes()),
        )?),
        ..Default::default()
    })
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
fn twitch_authorization_matches_the_pinned_ordinary_contract() -> TestResult<()> {
    let fixture = fixture()?;
    for case in fixture["authorization"]
        .as_array()
        .ok_or("missing Twitch authorization cases")?
    {
        let provider = resolved(config(&fixture, &case["options"])?);
        let scopes: Option<Vec<String>> = case
            .get("requestScopes")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        let additional: Option<IndexMap<String, String>> = case
            .get("additionalParams")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        let actual = build_authorization_url(
            &provider,
            AuthorizationRequest {
                callback_url: fixture["callbackURL"]
                    .as_str()
                    .ok_or("missing Twitch callback URL")?,
                scopes: scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: "ordinary-unused-challenge",
                login_hint: Some("twitch@example.test"),
                nonce: Some("ordinary-nonce"),
                additional_params: additional.as_ref(),
            },
        )?;
        assert_eq!(json!(actual), case["url"], "{}", case["name"]);
    }
    Ok(())
}

#[tokio::test]
async fn twitch_profiles_match_the_pinned_ordinary_contract() -> TestResult<()> {
    let fixture = fixture()?;
    let provider = resolved(config(&fixture, &json!({}))?);
    for case in fixture["profiles"]
        .as_array()
        .ok_or("missing Twitch profiles")?
    {
        let response =
            fetch_user_info_from_provider(&provider, tokens(&fixture, &case["profile"])?, None)
                .await?
                .ok_or("missing Twitch profile")?;
        assert_eq!(json!(response.user.id), case["profile"]["sub"]);
        assert_eq!(
            profile_json(response, false),
            case["result"],
            "{}",
            case["name"]
        );
    }
    Ok(())
}

struct Mapper(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.0.lock().await.push(profile.clone());
        Ok(OAuthProfile {
            name: Some(Some("Mapped Twitch Reader".into()).into()),
            image: Some(None),
            email_verified: Some(Some(false).into()),
            additional_fields: [("locale".into(), "en-GB".into())].into_iter().collect(),
            ..Default::default()
        })
    }
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
                id: "ordinary-twitch-user".into(),
                name: Some("Custom Twitch Reader".into()).into(),
                email: Some("custom-twitch@example.test".into()).into(),
                image: Some(None),
                email_verified: Some(true).into(),
                additional_fields: [("source".into(), "custom".into())].into_iter().collect(),
            },
            data: json!({"sub":"ordinary-twitch-user", "source":"custom"}),
        }))
    }
}

#[tokio::test]
async fn twitch_mapper_and_custom_handler_match_the_pinned_contract() -> TestResult<()> {
    let fixture = fixture()?;
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let mut config = config(&fixture, &json!({}))?;
    config.map_profile_to_user = Some(Arc::new(Mapper(inputs.clone())));
    let response = fetch_user_info_from_provider(
        &resolved(config.clone()),
        tokens(&fixture, &fixture["profiles"][0]["profile"])?,
        None,
    )
    .await?
    .ok_or("missing mapped Twitch profile")?;
    assert_eq!(
        json!(response.user.id),
        fixture["profiles"][0]["profile"]["sub"]
    );
    assert_eq!(json!(*inputs.lock().await), fixture["mapperInputs"]);
    assert_eq!(profile_json(response, false), fixture["mappedResult"]);

    let custom_inputs = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Mutex::new(0));
    config.map_profile_to_user = Some(Arc::new(Mapper(custom_inputs.clone())));
    config.get_user_info = Some(Arc::new(Custom(calls.clone())));
    let response = fetch_user_info_from_provider(
        &resolved(config),
        tokens(&fixture, &fixture["profiles"][0]["profile"])?,
        None,
    )
    .await?
    .ok_or("missing custom Twitch profile")?;
    assert_eq!(profile_json(response, true), fixture["customResult"]);
    assert_eq!(json!(*calls.lock().await), fixture["customCalls"]);
    assert_eq!(
        json!(custom_inputs.lock().await.len()),
        fixture["customMapperCalls"]
    );
    Ok(())
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn twitch_grants_match_the_pinned_ordinary_contract() -> TestResult<()> {
    use std::collections::BTreeMap;

    let fixture = fixture()?;
    let expected = fixture["requests"]
        .as_array()
        .ok_or("missing Twitch grant requests")?
        .iter()
        .map(|request| {
            let body: BTreeMap<String, String> = url::form_urlencoded::parse(
                request["body"]
                    .as_str()
                    .ok_or("missing Twitch form body")?
                    .as_bytes(),
            )
            .into_owned()
            .collect();
            Ok(json!({
                "method": request["method"],
                "contentType": request["headers"]["content-type"],
                "accept": request["headers"]["accept"],
                "authorization": request["headers"].get("authorization"),
                "body": body,
            }))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let (requests, tokens) = crate::plugins::oauth::social_token_wire_tests::grants(
        config(&fixture, &json!({}))?,
        fixture["callbackURL"]
            .as_str()
            .ok_or("missing Twitch callback URL")?,
        fixture["codeVerifier"]
            .as_str()
            .ok_or("missing Twitch code verifier")?,
        fixture["grantTokens"][0]["raw"].clone(),
    )
    .await?;
    assert_eq!(requests, expected);
    assert_eq!(tokens, fixture["grantTokens"]);
    Ok(())
}
