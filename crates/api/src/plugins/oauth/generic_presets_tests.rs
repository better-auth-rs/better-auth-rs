#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Contract tests fail immediately when a captured fixture or provider result changes."
)]

use std::{collections::HashMap, sync::Mutex};

use base64::Engine;
use better_auth_core::{AuthPlugin, AuthRequest, AuthUser, HttpMethod};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
use crate::plugins::{
    oauth::{
        OAuthCodeExchange, OAuthConfig, OAuthPlugin, OAuthProfile, OAuthProfileMapper,
        OAuthTokenHandler, OAuthTokenSet, TokenEndpointAuth, authorization, generic_profile,
        resolved::{ResolvedGenericOAuth, ResolvedOAuthConfig},
    },
    test_helpers,
};

type Events = Arc<Mutex<Vec<&'static str>>>;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/generic-profile-presets-1.7.6.json"
    )))
    .unwrap()
}

fn preset(id: &str) -> Preset {
    match id {
        "gumroad" => Preset::Gumroad,
        "hubspot" => Preset::HubSpot,
        "patreon" => Preset::Patreon,
        "slack" => Preset::Slack,
        "yandex" => Preset::Yandex,
        _ => panic!("Unknown fixture provider: {id}"),
    }
}

fn config(id: &str, fixture: &Value) -> GenericOAuthConfig {
    let id_value = fixture["credentials"]["clientId"].as_str().unwrap();
    let secret = fixture["credentials"]["clientSecret"].as_str().unwrap();
    match id {
        "gumroad" => GenericOAuthConfig::gumroad(id_value, secret),
        "hubspot" => GenericOAuthConfig::hubspot(id_value, secret),
        "patreon" => GenericOAuthConfig::patreon(id_value, secret),
        "slack" => GenericOAuthConfig::slack(id_value, secret),
        "yandex" => GenericOAuthConfig::yandex(id_value, secret),
        _ => panic!("Unknown fixture provider: {id}"),
    }
}

#[tokio::test]
async fn preset_configuration_and_authorization_match_pinned_helpers() {
    let fixture = fixture();
    let input = &fixture["authorization"];
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
        input["codeVerifier"].as_str().unwrap().as_bytes(),
    ));
    let scopes = serde_json::from_value::<Vec<String>>(input["scopes"].clone()).unwrap();
    let additional = serde_json::from_value(input["additionalParams"].clone()).unwrap();
    for case in fixture["configs"].as_array().unwrap() {
        let id = case["provider"].as_str().unwrap();
        let mut config = config(id, &fixture);
        let options = &case["options"];
        if let Some(scopes) = options.get("scopes") {
            config.scopes = serde_json::from_value(scopes.clone()).unwrap();
        }
        if options.get("tokenEndpointAuth").is_some() {
            config.token_endpoint_auth = Some(TokenEndpointAuth::ClientSecretBasic);
        }
        config.redirect_uri = options["redirectURI"].as_str().map(str::to_owned);
        config.end_session_endpoint = options["endSessionEndpoint"].as_str().map(str::to_owned);
        config.post_logout_redirect_uri =
            options["postLogoutRedirectURI"].as_str().map(str::to_owned);
        config.disable_provider_logout =
            options["disableProviderLogout"].as_bool().unwrap_or(false);
        config.disable_implicit_sign_up =
            options["disableImplicitSignUp"].as_bool().unwrap_or(false);
        config.disable_sign_up = options["disableSignUp"].as_bool().unwrap_or(false);
        config.override_user_info = options["overrideUserInfo"].as_bool().unwrap_or(false);
        if let Some(pkce) = options["pkce"].as_bool() {
            config.pkce = pkce;
        }
        let expected = &case["expected"]["config"];
        assert_eq!(config.client_id, expected["clientId"]);
        assert_eq!(json!(config.client_secret), expected["clientSecret"]);
        assert_eq!(json!(config.scopes), expected["scopes"]);
        for (actual, key) in [
            (&config.authorization_url, "authorizationUrl"),
            (&config.token_url, "tokenUrl"),
            (&config.user_info_url, "userInfoUrl"),
            (&config.redirect_uri, "redirectURI"),
            (&config.end_session_endpoint, "endSessionEndpoint"),
            (&config.post_logout_redirect_uri, "postLogoutRedirectURI"),
        ] {
            assert_eq!(actual.as_deref(), expected[key].as_str(), "{id}: {key}");
        }
        assert_eq!(
            config.authentication,
            expected["authentication"].as_str().map(|value| {
                assert_eq!(value, "post");
                TokenEndpointSecretAuthentication::Post
            })
        );
        assert_eq!(
            matches!(
                config.token_endpoint_auth,
                Some(TokenEndpointAuth::ClientSecretBasic)
            ),
            expected["tokenEndpointAuth"]["method"] == "client_secret_basic"
        );
        let resolved = ResolvedOAuthConfig::new(
            &OAuthConfig::default(),
            &HashMap::from([(id.to_owned(), config)]),
            None,
        )
        .await
        .unwrap();
        let url = authorization::build_authorization_url(
            &resolved.providers[id],
            authorization::AuthorizationRequest {
                callback_url: input["redirectURI"].as_str().unwrap(),
                scopes: Some(&scopes),
                state: input["state"].as_str().unwrap(),
                code_challenge: &challenge,
                login_hint: input["loginHint"].as_str(),
                nonce: None,
                additional_params: Some(&additional),
            },
        )
        .unwrap();
        assert_eq!(
            url, case["expected"]["authorizationURL"],
            "{id}: {}",
            case["name"]
        );
    }
}

fn request_value(request: &reqwest::Request) -> Value {
    let headers: Map<String, Value> = request
        .headers()
        .iter()
        .map(|(key, value)| {
            (
                key.as_str().into(),
                Value::String(value.to_str().unwrap().into()),
            )
        })
        .collect();
    json!({
        "url": request.url().as_str(),
        "method": request.method().as_str(),
        "headers": headers,
        "body": std::str::from_utf8(request.body().and_then(reqwest::Body::as_bytes).unwrap_or_default()).unwrap(),
    })
}

async fn local_profile(
    preset: Preset,
    case: &Value,
    request_count: usize,
    events: Events,
) -> (PresetProfile, tokio::task::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut endpoint = url::Url::parse(preset.profile_endpoint()).unwrap();
    endpoint.set_scheme("http").unwrap();
    endpoint.set_host(Some("127.0.0.1")).unwrap();
    endpoint
        .set_port(Some(listener.local_addr().unwrap().port()))
        .unwrap();
    let body = serde_json::to_string(&case["response"]).unwrap();
    let status = case["status"].as_u64().unwrap_or(200);
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
            }
            let request = String::from_utf8(bytes).unwrap();
            let mut lines = request.split("\r\n");
            let mut start = lines.next().unwrap().split(' ');
            let method = start.next().unwrap();
            let path = start.next().unwrap();
            let headers: HashMap<_, _> = lines
                .filter_map(|line| line.split_once(": "))
                .map(|(key, value)| (key.to_ascii_lowercase(), value.to_owned()))
                .collect();
            requests.push(json!({
                "method": method,
                "path": path,
                "authorization": headers.get("authorization"),
                "contentType": headers.get("content-type"),
            }));
            events.lock().unwrap().push("http");
            stream.write_all(format!(
                "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ).as_bytes()).await.unwrap();
        }
        requests
    });
    (
        PresetProfile {
            preset,
            endpoint: endpoint.into(),
        },
        task,
    )
}

struct Mapper {
    inputs: Mutex<Vec<Value>>,
    events: Events,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.inputs.lock().unwrap().push(profile.clone());
        self.events.lock().unwrap().push("map");
        Ok(OAuthProfile {
            name: Some(Some("Mapped Reader".into()).into()),
            email: Some(Some("mapped@example.test".into()).into()),
            email_verified: Some(Some(true).into()),
            additional_fields: [("favoriteColor".into(), "blue".into())]
                .into_iter()
                .collect(),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn preset_requests_profiles_and_json_mapper_inputs_match_pinned_helpers() {
    let fixture = fixture();
    let tokens = OAuthUserInfoRequest {
        access_token: fixture["tokens"]["accessToken"].as_str().map(str::to_owned),
        ..Default::default()
    };
    for case in fixture["cases"].as_array().unwrap() {
        let id = case["provider"].as_str().unwrap();
        let preset = preset(id);
        let expected = &case["expected"];
        let requests = expected["requests"].as_array().unwrap();
        let public_request = PresetProfile {
            preset,
            endpoint: preset.profile_endpoint().into(),
        }
        .request(&tokens)
        .build()
        .unwrap();
        assert_eq!(
            request_value(&public_request),
            requests[0],
            "{id}: {}",
            case["name"]
        );
        let events = Events::default();
        let (local, server) = local_profile(preset, case, requests.len(), events.clone()).await;
        let profile = local
            .get_user_info(&tokens)
            .await
            .unwrap()
            .unwrap_or(Value::Null);
        assert_eq!(profile, expected["profile"], "{id}: {}", case["name"]);
        if !profile.is_null() {
            let mut config = config(id, &fixture);
            assert_eq!(
                config
                    .account_subject
                    .as_ref()
                    .unwrap()
                    .resolve_subject(&tokens, &profile)
                    .await
                    .unwrap(),
                expected["accountId"]
            );
            let mapper = Arc::new(Mapper {
                inputs: Mutex::new(Vec::new()),
                events: events.clone(),
            });
            config.get_user_info = Some(Arc::new(local));
            config.map_profile_to_user = Some(mapper.clone());
            let resolved = ResolvedGenericOAuth {
                config,
                issuer: None,
                is_oidc: false,
                verifier: None,
            };
            let response = generic_profile::fetch_profile(&resolved, &tokens, None, None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                json!({ "user": response.user, "data": response.data }),
                expected["mapped"]
            );
            let mapper_inputs = mapper.inputs.lock().unwrap();
            assert_eq!(json!(*mapper_inputs), expected["mapperInputs"]);
            if id == "yandex" && case["name"] == "avatar" {
                assert_eq!(
                    mapper_inputs[0]
                        .as_object()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>(),
                    expected["mapperInputs"][0]
                        .as_object()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>()
                );
            }
        }
        let actual = server.await.unwrap();
        assert_eq!(actual.len(), requests.len());
        for (actual, expected) in actual.iter().zip(requests) {
            let url = url::Url::parse(expected["url"].as_str().unwrap()).unwrap();
            assert_eq!(
                actual,
                &json!({
                    "method": expected["method"],
                    "path": &url[url::Position::BeforePath..],
                    "authorization": expected["headers"]["authorization"],
                    "contentType": expected["headers"]["content-type"],
                })
            );
        }
        assert_eq!(json!(*events.lock().unwrap()), expected["events"]);
    }
}

struct Tokens;

#[async_trait]
impl OAuthTokenHandler for Tokens {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        Ok(OAuthTokenSet {
            access_token: Some("ordinary-profile-token".into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn preset_callback_persists_the_captured_subject_and_mapped_user() {
    let fixture = fixture();
    for id in ["gumroad", "hubspot", "patreon", "slack", "yandex"] {
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["provider"] == id)
            .unwrap();
        let events = Events::default();
        let (local, server) = local_profile(preset(id), case, 1, events.clone()).await;
        let mut config = config(id, &fixture);
        config.get_token = Some(Arc::new(Tokens));
        config.get_user_info = Some(Arc::new(local));
        config.map_profile_to_user = Some(Arc::new(Mapper {
            inputs: Mutex::new(Vec::new()),
            events,
        }));
        let plugin = OAuthPlugin::new().add_generic_provider(id, config);
        let ctx = test_helpers::create_test_context().await;
        let start = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/social",
            None,
            Some(
                json!({ "provider": id, "callbackURL": "http://localhost:3000/welcome", "disableRedirect": true }),
            ),
        );
        let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
        let response = test_helpers::finalize_response(&ctx, &start, response);
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let cookies = response
            .headers
            .get_all("Set-Cookie")
            .map(|value| value.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let mut callback = AuthRequest::new(HttpMethod::Get, format!("/callback/{id}"));
        callback.query = Some(json!({ "state": state, "code": "ordinary-code" }));
        let _ = callback.headers.insert("cookie".into(), cookies);
        let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
        let response = test_helpers::finalize_response(&ctx, &callback, response);
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers.get("Location").map(String::as_str),
            Some("http://localhost:3000/welcome")
        );
        let user = ctx
            .database
            .get_user_by_email("mapped@example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&user).unwrap()["name"],
            "Mapped Reader"
        );
        assert!(user.email_verified());
        let account = ctx
            .database
            .get_account(id, case["expected"]["accountId"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            account.user_id.typed().unwrap().as_str(),
            user.id().typed().unwrap()
        );
        assert_eq!(
            account.access_token.typed().unwrap().as_deref(),
            Some("ordinary-profile-token")
        );
        assert_eq!(server.await.unwrap().len(), 1);
    }
}
