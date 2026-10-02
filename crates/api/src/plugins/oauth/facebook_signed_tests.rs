#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Ordinary signed fixtures fail immediately when setup or captured values differ."
)]

use super::google_test_support::GoogleFixture;
use super::*;
use better_auth_core::{AuthError, SchemaValue, endpoint_dispatch::EndpointDispatcher};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use serde_json::{Value, json};
use std::sync::Mutex;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/facebook-1.7.6.json"
    ))
    .unwrap()
}

fn provider(server: &GoogleFixture) -> OAuthProvider {
    let mut provider = OAuthProvider::facebook(
        "ordinary-client",
        "ordinary-client-secret",
        FacebookOptions {
            additional_client_ids: vec!["ordinary-secondary-client".into()],
            jwks_url: Some(format!("{}/jwks", server.url)),
            ..Default::default()
        },
    );
    provider.token_url = format!("{}/token", server.url);
    provider
}

struct Mapper {
    seen: Arc<Mutex<Vec<Value>>>,
    sample: Value,
    fail: bool,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen.lock().unwrap().push(profile.clone());
        if self.fail {
            return Err(AuthError::internal(
                self.sample["error"]["message"].as_str().unwrap(),
            ));
        }
        let patch = &self.sample["mapperPatch"];
        Ok(OAuthProfile {
            name: patch
                .get("name")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email: if self.sample["mapperEmailMode"] == "undefined" {
                Some(SchemaValue::Undefined)
            } else {
                patch
                    .get("email")
                    .cloned()
                    .map(|v| SchemaValue::from_json(Some(v)))
            },
            image: patch
                .get("image")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email_verified: patch
                .get("emailVerified")
                .cloned()
                .map(|v| SchemaValue::from_json(Some(v))),
            additional_fields: patch
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    !matches!(key.as_str(), "name" | "email" | "image" | "emailVerified")
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
    }
}

fn public_response(response: OAuthUserInfoResponse) -> Value {
    json!({"user": types::AccountInfoUser {
        id: None, name: response.user.name, email: response.user.email, image: response.user.image,
        email_verified: response.user.email_verified, additional_fields: response.user.additional_fields,
    }, "data": response.data})
}

fn current_claims(sample: &Value) -> Value {
    let mut claims = sample["profile"].clone();
    let now = chrono::Utc::now().timestamp();
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 3600);
    claims
}

#[tokio::test]
async fn limited_signed_profiles_match_pinned_on_code_direct_and_account_reads() {
    for sample in fixture()["profileCases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["source"] == "limited")
    {
        let claims = current_claims(sample);
        let mut expected = sample["result"].clone();
        expected["data"]["iat"] = claims["iat"].clone();
        expected["data"]["exp"] = claims["exp"].clone();
        let server = GoogleFixture::start(claims).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = provider(&server);
        config.map_profile_to_user = Some(Arc::new(Mapper {
            seen: seen.clone(),
            sample: sample.clone(),
            fail: false,
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
                let verified = id_token::verify(
                    &resolved,
                    &types::OAuthIdTokenRequest {
                        token: server.token.clone(),
                        nonce: Some("ordinary-facebook-nonce".into()),
                        access_token: None,
                        refresh_token: None,
                        user: None,
                    },
                )
                .await
                .unwrap();
                social_profile::fetch_user_info_with_claims(
                    &resolved,
                    request,
                    Some("ordinary-facebook-nonce"),
                    verified,
                )
                .await
                .unwrap()
            } else if entry == "code" {
                social_profile::fetch_user_info_for_code(
                    &resolved,
                    request,
                    Some("ordinary-facebook-nonce"),
                )
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
async fn limited_mapper_error_retains_the_original_application_error() {
    let sample = fixture()["specialCases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["mode"] == "limited mapper error")
        .unwrap()
        .clone();
    let server = GoogleFixture::start(current_claims(&sample)).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut config = provider(&server);
    config.map_profile_to_user = Some(Arc::new(Mapper {
        seen: seen.clone(),
        sample: sample.clone(),
        fail: true,
    }));
    let error = social_profile::fetch_user_info_for_code(
        &resolved::ResolvedProvider {
            config,
            generic: None,
        },
        OAuthUserInfoRequest {
            id_token: Some(server.token.clone()),
            ..Default::default()
        },
        Some("ordinary-facebook-nonce"),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(error, AuthError::Internal(ref message) if message == sample["error"]["message"].as_str().unwrap())
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(*server.requests.lock().unwrap(), ["/jwks"]);
}

struct App {
    context: Arc<AuthContext<BundledSchema>>,
    plugins: Arc<Vec<Box<dyn AuthPlugin<BundledSchema>>>>,
    dispatcher: EndpointDispatcher<BundledSchema>,
}

impl App {
    async fn new(provider: OAuthProvider) -> Self {
        let plugin = OAuthPlugin::new().add_provider("facebook", provider);
        let config = Arc::new(crate::plugins::test_helpers::create_test_config());
        let database = crate::plugins::test_helpers::create_test_database().await;
        let mut init = better_auth_core::AuthInitContext::new(config.clone(), database.clone());
        plugin.on_init(&mut init).await.unwrap();
        let parts = init.into_parts();
        let (adapter_config, endpoint_config, model_fields) =
            parts.plugin_fields.clone().resolve(&config);
        let database = database
            .with_runtime(
                Arc::new(adapter_config),
                parts.database_hooks.clone(),
                model_fields,
            )
            .unwrap();
        let mut context = AuthContext::new(Arc::new(endpoint_config), database);
        parts.apply_request_runtime(&mut context);
        context.extensions = parts.extensions;
        context.email_verification_policy = parts.email_verification_policy;
        context.email_provider = parts.email_provider;
        context.secondary_storage = parts.secondary_storage;
        context.password_policy = parts.password_policy;
        context.metadata = parts.metadata;
        let context = Arc::new(context);
        parts.runtime.bind(&context).unwrap();
        let context = context.initialize_request_context().await.unwrap();
        let plugins: Arc<Vec<Box<dyn AuthPlugin<BundledSchema>>>> =
            Arc::new(vec![Box::new(plugin)]);
        let dispatcher = EndpointDispatcher::new(plugins.clone(), Default::default(), []);
        Self {
            context,
            plugins,
            dispatcher,
        }
    }

    async fn call(&self, mut request: AuthRequest) -> AuthResult<AuthResponse> {
        let route = self.plugins[0]
            .routes()
            .into_iter()
            .find(|route| route.matches(request.method(), request.path()))
            .unwrap();
        let allowed = if route.allowed_media_types.is_empty() {
            vec!["application/json".into()]
        } else {
            route.allowed_media_types.clone()
        };
        request.parse_http_body(&allowed)?;
        let mut scope = better_auth_core::hooks::RequestHookContext::from_request(&request);
        scope.is_http = true;
        better_auth_core::hooks::with_request_hook_context_value(scope, async {
            better_auth_core::hooks::set_request_hook_route(request.path(), Some(&route));
            self.dispatcher
                .run(
                    &mut request,
                    true,
                    &self.context,
                    None,
                    |request| async move {
                        self.plugins[0]
                            .on_request(&request, &self.context)
                            .await
                            .map(|response| response.unwrap())
                    },
                )
                .await
        })
        .await
    }
}

fn post(path: &str, body: Value, cookie: &str) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    let _ = request
        .headers
        .insert("origin".into(), "http://localhost:3000".into());
    if !cookie.is_empty() {
        let _ = request.headers.insert("cookie".into(), cookie.into());
    }
    request.body = Some(serde_json::to_vec(&body).unwrap());
    request
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn sign_in(app: &App, direct: Option<Value>) -> AuthResponse {
    let start = app.call(post("/sign-in/social", direct.clone().map_or_else(||
        json!({"provider":"facebook","callbackURL":"http://localhost:3000/welcome","disableRedirect":true}),
        |token| json!({"provider":"facebook","idToken":token})
    ), "")).await.unwrap();
    assert_eq!(start.status, 200);
    if direct.is_some() {
        return start;
    }
    let body: Value = serde_json::from_slice(&start.body).unwrap();
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let cookie = cookies(&start);
    assert!(!cookie.is_empty());
    let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/facebook");
    let _ = callback.headers.insert("cookie".into(), cookie);
    callback.query = Some(json!({"code":"ordinary-code","state":state}));
    let response = app.call(callback).await.unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("Location").map(String::as_str),
        Some("http://localhost:3000/welcome")
    );
    response
}

#[tokio::test]
async fn graph_code_and_opaque_direct_dispatch_persist_and_read_normal_accounts() {
    let fixture = fixture();
    let sample = &fixture["profileCases"][0];
    for direct in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let server =
            super::facebook_contract_tests::Server::start(&fixture, sample, events.clone()).await;
        let app = App::new(server.config(&fixture, sample)).await;
        let response = sign_in(
            &app,
            direct.then(|| json!({"token":"ordinary-access","accessToken":"ordinary-access"})),
        )
        .await;
        let cookie = cookies(&response);
        assert!(!cookie.is_empty());
        let user = app
            .context
            .database
            .get_user_by_email("facebook-owner@example.test")
            .await
            .unwrap()
            .unwrap();
        let user_data = serde_json::to_value(&user).unwrap();
        assert_eq!(user_data["name"], sample["result"]["user"]["name"]);
        assert_eq!(
            user_data["emailVerified"],
            sample["result"]["user"]["emailVerified"]
        );
        let accounts = app
            .context
            .database
            .get_user_accounts(&user.id.display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        let account = serde_json::to_value(&accounts[0]).unwrap();
        assert_eq!(account["providerId"], "facebook");
        assert_eq!(account["accountId"], sample["profile"]["id"]);
        let mut info = AuthRequest::new(HttpMethod::Get, "/account-info");
        let _ = info.headers.insert("cookie".into(), cookie.clone());
        info.query = Some(json!({"accountId":account["id"]}));
        let info = app.call(info).await.unwrap();
        assert_eq!(info.status, 200);
        let info: Value = serde_json::from_slice(&info.body).unwrap();
        assert_eq!(info["user"], sample["result"]["user"]);
        assert_eq!(info["data"], sample["result"]["data"]);
        if !direct {
            let refresh = app
                .call(post(
                    "/refresh-token",
                    json!({"accountId":account["id"]}),
                    &cookie,
                ))
                .await
                .unwrap();
            assert_eq!(refresh.status, 200);
            let result: Value = serde_json::from_slice(&refresh.body).unwrap();
            assert_eq!(
                result["accessToken"],
                fixture["grants"][1]["response"]["accessToken"]
            );
            assert_eq!(
                result["scope"],
                fixture["grants"][0]["rawResponse"]["scope"]
            );
            let updated = app
                .context
                .database
                .get_user_accounts(&user.id.display_string().unwrap())
                .await
                .unwrap();
            let updated = serde_json::to_value(&updated[0]).unwrap();
            assert_eq!(
                updated["accessToken"],
                fixture["grants"][1]["rawResponse"]["access_token"]
            );
            assert_eq!(
                updated["refreshToken"],
                fixture["grants"][1]["rawResponse"]["refresh_token"]
            );
            assert_eq!(updated["scope"], account["scope"]);
        }
        assert_eq!(
            *events.lock().unwrap(),
            if direct {
                vec!["debug", "profile", "debug", "profile"]
            } else {
                vec!["code", "debug", "profile", "debug", "profile", "refresh"]
            }
        );
    }
}

#[tokio::test]
async fn limited_signed_code_and_direct_dispatch_persist_normal_users() {
    let sample = fixture()["profileCases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "limited" && s["name"] == "default")
        .unwrap()
        .clone();
    for direct in [false, true] {
        let server = GoogleFixture::start(current_claims(&sample)).await;
        let app = App::new(provider(&server)).await;
        let response = sign_in(
            &app,
            direct.then(|| json!({"token":server.token,"nonce":"ordinary-facebook-nonce"})),
        )
        .await;
        assert!(!cookies(&response).is_empty());
        let user = app
            .context
            .database
            .get_user_by_email("facebook-owner@example.test")
            .await
            .unwrap()
            .unwrap();
        let data = serde_json::to_value(&user).unwrap();
        assert_eq!(data["name"], sample["result"]["user"]["name"]);
        assert_eq!(
            data["emailVerified"],
            sample["result"]["user"]["emailVerified"]
        );
        let accounts = app
            .context
            .database
            .get_user_accounts(&user.id.display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].provider_id.as_str(), Some("facebook"));
        assert_eq!(
            accounts[0].account_id.as_str(),
            Some("ordinary-facebook-owner")
        );
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
