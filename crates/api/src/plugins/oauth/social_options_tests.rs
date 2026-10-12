#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "contract tests propagate setup failures and assert upstream results"
)]

use super::google_test_support::GoogleFixture;
use super::profile_test_support as profile_test;
use super::*;
use better_auth_core::{AuthError, FieldValue};
use serde_json::{Value, json};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> AuthResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/social-provider-options-1.7.6.json"
    ))?)
}

async fn google_fixture() -> GoogleFixture {
    GoogleFixture::start(json!({"sub":"google-subject","email":"owner@example.test","name":"Owner","picture":"https://images.test/owner.png","email_verified":true})).await
}

fn provider(id: &str) -> AuthResult<OAuthProvider> {
    match id {
        "google" => Ok(OAuthProvider::google("client", "secret")),
        "github" => Ok(OAuthProvider::github("client", "secret")),
        "discord" => Ok(OAuthProvider::discord("client", "secret")),
        _ => Err(AuthError::internal("unknown fixture provider")),
    }
}

async fn resolve(id: &str, provider: OAuthProvider) -> AuthResult<resolved::ResolvedOAuthConfig> {
    resolved::ResolvedOAuthConfig::new(
        &OAuthConfig {
            providers: [(id.to_owned(), provider)].into_iter().collect(),
        },
        &HashMap::new(),
        None,
    )
    .await
}

#[tokio::test]
async fn social_authorization_scope_and_prompt_match_upstream() -> AuthResult<()> {
    let fixture = fixture()?;
    for id in ["google", "github", "discord"] {
        for name in ["defaults", "empty", "merged", "noDefaults", "noScopes"] {
            let mut provider = provider(id)?;
            let request = match name {
                "empty" | "noScopes" => {
                    provider.scopes = Some(vec![]);
                    Some(vec![])
                }
                "merged" => {
                    provider.scopes = Some(vec!["configured".into(), "shared".into()]);
                    provider.prompt = Some("consent".into());
                    Some(vec!["request".into(), "shared".into()])
                }
                "noDefaults" => {
                    provider.scopes = Some(vec!["configured".into()]);
                    Some(vec!["request".into()])
                }
                _ => None,
            };
            provider.disable_default_scope = name == "noDefaults" || name == "noScopes";
            let config = resolve(id, provider).await?;
            let provider = config
                .providers
                .get(id)
                .ok_or_else(|| AuthError::internal("missing resolved provider"))?;
            let url = authorization::build_authorization_url(
                provider,
                authorization::AuthorizationRequest {
                    callback_url: "https://example.test/api/auth/callback/provider",
                    scopes: request.as_deref(),
                    state: "state",
                    code_challenge: "challenge",
                    login_hint: None,
                    nonce: None,
                    additional_params: None,
                },
            )?;
            let params: HashMap<_, _> = url::Url::parse(&url)
                .map_err(|error| AuthError::internal(error.to_string()))?
                .query_pairs()
                .into_owned()
                .collect();
            let actual = json!({"scope":params.get("scope"), "prompt":params.get("prompt")});
            assert_eq!(
                Some(&actual),
                fixture
                    .get("authorization")
                    .and_then(|cases| cases.get(format!("{id}-{name}"))),
                "{id}-{name}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn discord_authorization_omits_standalone_hints_and_gates_configured_permissions()
-> Result<(), Box<dyn std::error::Error>> {
    for (
        configured_bot,
        requested_bot,
        permission,
        request_permission,
        expected_permission,
        request_hints,
    ) in [
        (false, false, None, None, None, false),
        (false, false, Some("8"), None, None, false),
        (true, false, Some("0"), None, Some("0"), false),
        (false, true, Some("8"), None, Some("8"), false),
        (true, false, Some("8"), Some("16"), Some("16"), false),
        (false, false, Some("8"), Some("16"), Some("16"), false),
        (true, false, None, None, None, false),
        (false, false, None, None, None, true),
    ] {
        let mut discord = provider("discord")?;
        if configured_bot {
            discord.scopes = Some(vec!["bot".into()]);
        }
        if let Some(permission) = permission {
            discord
                .authorization_params
                .push(("permissions".into(), permission.into()));
        }
        let request_scopes = requested_bot.then(|| vec!["bot".into()]);
        let mut additional = indexmap::IndexMap::new();
        if let Some(permission) = request_permission {
            let _ = additional.insert("permissions".into(), permission.into());
        }
        if request_hints {
            additional.extend([
                ("login_hint".into(), "request@example.test".into()),
                ("prompt".into(), "consent".into()),
            ]);
        }
        let _ = additional.insert("request_marker".into(), "ordinary".into());
        let resolved = resolve("discord", discord).await?;
        let discord = resolved
            .providers
            .get("discord")
            .ok_or_else(|| AuthError::internal("missing Discord provider"))?;
        let url = authorization::build_authorization_url(
            discord,
            authorization::AuthorizationRequest {
                callback_url: "https://app.example.test/callback/discord",
                scopes: request_scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: "ordinary-challenge",
                login_hint: Some("reader@example.test"),
                nonce: Some("ordinary-nonce"),
                additional_params: Some(&additional),
            },
        )?;
        let actual: HashMap<String, String> =
            url::Url::parse(&url)?.query_pairs().into_owned().collect();
        let mut expected: HashMap<String, String> = [
            ("response_type", "code"),
            ("client_id", "client"),
            ("state", "ordinary-state"),
            (
                "scope",
                if configured_bot || requested_bot {
                    "identify email bot"
                } else {
                    "identify email"
                },
            ),
            ("redirect_uri", "https://app.example.test/callback/discord"),
            ("prompt", "none"),
            ("request_marker", "ordinary"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        if let Some(permission) = expected_permission {
            let _ = expected.insert("permissions".into(), permission.into());
        }
        if request_hints {
            expected.extend([
                ("login_hint".into(), "request@example.test".into()),
                ("prompt".into(), "consent".into()),
            ]);
        }
        assert_eq!(actual, expected);
    }
    Ok(())
}

struct ProfileServer {
    url: String,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<Mutex<Vec<String>>>,
}
impl Drop for ProfileServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ProfileServer {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept local profile request");
                let mut bytes = [0; 4096];
                let count = stream
                    .read(&mut bytes)
                    .await
                    .expect("read local profile request");
                let request = String::from_utf8_lossy(&bytes[..count]);
                let path = request.split_whitespace().nth(1).expect("request path");
                recorded
                    .lock()
                    .expect("profile request log must be available")
                    .push(path.to_owned());
                let body = match path {
                    "/google" => json!({"sub":"google-subject","email":"owner@example.test","name":"Owner","picture":"https://images.test/owner.png","email_verified":true}),
                    "/github" => json!({"id":123,"email":"owner@example.test","name":"Owner","login":"owner","avatar_url":"https://images.test/owner.png"}),
                    "/github/emails" => json!([{"email":"owner@example.test","primary":true,"verified":true}]),
                    "/discord" => json!({"id":"123456789","email":"owner@example.test","username":"Owner","avatar":"portrait","verified":true}),
                    _ => panic!("unexpected local profile path: {path}"),
                }.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write local profile response");
            }
        });
        Ok(Self {
            url,
            task,
            requests,
        })
    }
}

struct Mapper {
    partial: bool,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        self.calls
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("map");
        assert_eq!(raw.get("email"), Some(&json!("owner@example.test")));
        let mut mapped = OAuthProfile {
            additional_fields: [("locale".into(), "zh-TW".into())].into_iter().collect(),
            ..Default::default()
        };
        if !self.partial {
            mapped.name = Some(Some("Mapped".into()).into());
            mapped.image = Some(None);
            mapped.email = Some(Some("mapped@example.test".into()).into());
            mapped.email_verified = Some(Some(false).into());
        }
        Ok(mapped)
    }
}
struct CustomProfile {
    calls: Arc<Mutex<Vec<&'static str>>>,
    data: Value,
}
#[async_trait]
impl OAuthUserInfoHandler for CustomProfile {
    async fn get_user_info_native(&self, _: OAuthUserInfoRequest) -> AuthResult<FieldValue> {
        self.calls
            .lock()
            .map_err(|_| better_auth_core::AuthError::internal("callback log poisoned"))?
            .push("get");
        Ok(json!({
            "user": {
                "name": "Custom",
                "image": "https://images.test/custom.png",
                "email": "custom@example.test",
                "emailVerified": true,
                "locale": "en"
            },
            "data": self.data
        })
        .into())
    }
}

#[tokio::test]
async fn social_profile_mapping_matches_upstream_and_keeps_subject()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let server = ProfileServer::start().await?;
    let google = google_fixture().await;
    for (id, subject) in [
        ("google", "google-subject"),
        ("github", "123"),
        ("discord", "123456789"),
    ] {
        for mode in ["mapped", "partial", "custom"] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let mut provider = if id == "github" {
                OAuthProvider::github_with_endpoints(
                    "client",
                    "secret",
                    "https://provider.test/authorize",
                    "https://provider.test/token",
                    &format!("{}/github", server.url),
                    &format!("{}/github/emails", server.url),
                )
            } else {
                provider(id)?
            };
            provider.user_info_url = Some(format!("{}/{id}", server.url));
            if id == "google" {
                google.configure(&mut provider);
            }
            provider.map_profile_to_user = Some(Arc::new(Mapper {
                partial: mode == "partial",
                calls: calls.clone(),
            }));
            if mode == "custom" {
                let data = match id {
                    "google" => {
                        json!({"sub":"google-subject","email":"owner@example.test","name":"Owner","picture":"https://images.test/owner.png","email_verified":true})
                    }
                    "github" => {
                        json!({"id":123,"email":"owner@example.test","name":"Owner","login":"owner","avatar_url":"https://images.test/owner.png"})
                    }
                    "discord" => {
                        json!({"id":"123456789","email":"owner@example.test","username":"Owner","avatar":"portrait","verified":true})
                    }
                    _ => return Err("Unknown fixture provider".into()),
                };
                provider.get_user_info = Some(Arc::new(CustomProfile {
                    calls: calls.clone(),
                    data,
                }));
            }
            let config = resolve(id, provider).await?;
            assert!(
                calls
                    .lock()
                    .map_err(|_| "callback log poisoned")?
                    .is_empty()
            );
            let profile_request = OAuthUserInfoRequest {
                access_token: (Some("normal-profile-token".into())).into(),
                id_token: ((id == "google").then(|| google.token.clone())).into(),
                ..Default::default()
            };
            let provider = config.providers.get(id).ok_or("missing provider")?;
            let tokens = OAuthTokenSet::from_fields(profile_request.fields());
            let response =
                handlers::fetch_user_info_for_code(provider, profile_request, None).await?;
            assert_eq!(
                profile_test::subject(provider, &tokens, &response)
                    .await
                    .json()?,
                Some(json!(subject))
            );
            let user = profile_test::user(&response);
            let actual =
                json!({"user":user,"calls":*calls.lock().map_err(|_| "callback log poisoned")?});
            assert_eq!(
                Some(&actual),
                fixture
                    .get("profiles")
                    .and_then(|cases| cases.get(format!("{id}-{mode}"))),
                "{id}-{mode}"
            );
        }
    }
    Ok(())
}

struct FailingCallbacks(Arc<Mutex<Vec<&'static str>>>);

#[tokio::test]
async fn google_stored_account_profile_decodes_id_token_and_rejects_missing_token()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::plugins::test_helpers;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use better_auth_core::{CreateAccount, CreateUser};

    // google-github-native.test.mjs exercises upstream getUserInfo with decoded claims and absent idToken.
    // Upstream account.mjs forwards stored tokens and rejects a null provider response with FAILED_TO_GET_USER_INFO.
    let server = ProfileServer::start().await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut provider = provider("google")?;
    provider.user_info_url = Some(format!("{}/google", server.url));
    provider.set_google_jwks_url(format!("{}/google", server.url));
    provider.map_profile_to_user = Some(Arc::new(Mapper {
        partial: true,
        calls: calls.clone(),
    }));
    let config = resolve("google", provider).await?;
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("stored-owner@example.test")
            .with_name("Stored Owner"),
        chrono::Duration::hours(1),
    )
    .await;
    let user_id = user.id.display_string()?;
    let claims = json!({
        "sub":"google-subject", "email":"owner@example.test", "name":"Owner",
        "picture":"https://images.test/owner.png", "email_verified":true,
    });
    let token = format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    );
    for (id, id_token) in [
        ("google-with-id-token", Some(token)),
        ("google-without-id-token", None),
    ] {
        let account = ctx
            .database
            .create_account(CreateAccount {
                id: id.into(),
                user_id: user.id.clone(),
                account_id: id.into(),
                provider_id: "google".into(),
                access_token: Some("normal-account-info-token".into()).into(),
                id_token: id_token.clone().into(),
                ..Default::default()
            })
            .await?;
        let before = serde_json::to_value(ctx.database.get_user_accounts(&user_id).await?)?;
        calls.lock().map_err(|_| "callback log poisoned")?.clear();
        let request = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/account-info",
            Some(session.token.typed()?),
            None,
            [("accountId".into(), account.id.display_string()?)].into(),
        );
        let result = account::handle_account_info(&config, &request, &ctx).await;
        if id_token.is_some() {
            let response = result?;
            assert_eq!(response.status, 200);
            let value = response.body.field_value()?;
            assert_eq!(
                value.json()?,
                Some(json!({
                    "user": {
                        "name":"Owner", "email":"owner@example.test",
                        "image":"https://images.test/owner.png", "emailVerified":true,
                        "locale":"zh-TW",
                    },
                    "data":claims,
                    "account": {
                        "id":account.id, "providerId":"google", "accountId":id,
                    },
                }))
            );
            assert_eq!(
                profile_test::subject(
                    config.providers.get("google").ok_or("missing provider")?,
                    &OAuthTokenSet::default(),
                    &social_profile::ProviderProfile::from(value),
                )
                .await
                .json()?,
                Some(json!("google-subject"))
            );
            assert_eq!(*calls.lock().map_err(|_| "callback log poisoned")?, ["map"]);
        } else {
            let error = result.expect_err("A stored account without idToken has no Google profile");
            assert_eq!(error.status_value()?, FieldValue::from("UNAUTHORIZED"));
            let response = error
                .to_auth_response()
                .expect("fixture response succeeds")
                .into_http_response()?;
            assert_eq!(response.status, 401);
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                json!({"message":"Failed to get user info", "code":"FAILED_TO_GET_USER_INFO"})
            );
            assert!(
                calls
                    .lock()
                    .map_err(|_| "callback log poisoned")?
                    .is_empty()
            );
        }
        assert_eq!(
            serde_json::to_value(ctx.database.get_user_accounts(&user_id).await?)?,
            before,
        );
        assert!(
            server
                .requests
                .lock()
                .map_err(|_| "request log poisoned")?
                .is_empty()
        );
    }
    Ok(())
}

#[async_trait]
impl OAuthProfileMapper for FailingCallbacks {
    async fn map_profile(&self, _: &Value) -> AuthResult<OAuthProfile> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("map");
        Err(AuthError::config("profile mapper failed"))
    }
}
#[async_trait]
impl OAuthUserInfoHandler for FailingCallbacks {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0
            .lock()
            .map_err(|_| better_auth_core::AuthError::internal("callback log poisoned"))?
            .push("get");
        Err(better_auth_core::AuthError::internal(
            "custom user info failed",
        ))
    }
}
#[tokio::test]
async fn social_profile_callback_errors_propagate_without_running_later_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let server = ProfileServer::start().await?;
    let google = google_fixture().await;
    for mode in ["mapper", "custom"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callbacks = Arc::new(FailingCallbacks(calls.clone()));
        let mut provider = provider("google")?;
        provider.user_info_url = Some(format!("{}/google", server.url));
        google.configure(&mut provider);
        provider.map_profile_to_user = Some(callbacks.clone());
        if mode == "custom" {
            provider.get_user_info = Some(callbacks);
        }
        let config = resolve("google", provider).await?;
        let profile_request = OAuthUserInfoRequest {
            access_token: (Some("normal-profile-token".into())).into(),
            id_token: (Some(google.token.clone())).into(),
            ..Default::default()
        };
        let error = handlers::fetch_user_info_for_code(
            config.providers.get("google").ok_or("missing provider")?,
            profile_request,
            None,
        )
        .await
        .expect_err("callback must fail");
        assert!(if mode == "mapper" {
            matches!(error, AuthError::Config(_))
        } else {
            matches!(error, AuthError::Internal(_))
        });
        let actual = json!({"message":error.instrumentation_message().unwrap(),"calls":*calls.lock().map_err(|_| "callback log poisoned")?});
        assert_eq!(
            Some(&actual),
            fixture.get("errors").and_then(|cases| cases.get(mode))
        );
    }
    Ok(())
}
