use async_trait::async_trait;
use better_auth::{
    AuthConfig, BetterAuth,
    plugins::oauth::{
        NativeRequest, OAuthPlugin, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet,
    },
    server_api::EndpointInput,
};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateUser, HttpMethod,
    middleware::RateLimitConfig,
    store::{EphemeralStore, StatelessSchema},
    utils::cookie_utils::sign_cookie_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, OnceLock, mpsc},
};

const ORIGIN: &str = "http://social-refresh-context.test";
const SECRET: &str = "ordinary-refresh-context-secret-at-least-32-characters";
const ACCOUNT_ID: &str = "ordinary-local-account";
const REFRESH_TOKEN: &str = "ordinary-old-refresh";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Http,
    NativeHeaders,
    NativeRequest,
    Standalone,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Case {
    mode: Mode,
    events: Vec<Value>,
    result: Value,
    stored: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

struct Refresh {
    cookie: OnceLock<String>,
    events: mpsc::Sender<Value>,
}

impl Refresh {
    fn headers(&self, headers: Option<&HashMap<String, String>>) -> Value {
        let Some(headers) = headers else {
            return Value::Null;
        };
        let mut headers: Vec<_> = headers
            .iter()
            .map(|(name, value)| {
                let content = if name == "cookie" {
                    assert_eq!(
                        Some(value),
                        self.cookie.get(),
                        "The owner session cookie is unchanged"
                    );
                    "<owner-session-cookie>"
                } else {
                    value.as_str()
                };
                (name.as_str(), content)
            })
            .collect();
        headers.sort();
        json!(headers)
    }
}

#[async_trait]
impl OAuthRefreshTokenHandler for Refresh {
    async fn refresh_access_token(
        &self,
        token: &str,
        context: Option<NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        let request = context.and_then(|context| context.request).map(|request| {
            json!({
                "url": request.url().map(|url| url.as_str()),
                "method": format!("{:?}", request.method()).to_ascii_uppercase(),
                "headers": self.headers(Some(&request.headers)),
            })
        });
        self.events
            .send(json!({
                "token": token, "hasContext": context.is_some(),
                "headers": self.headers(context.and_then(|context| context.headers)),
                "request": request,
            }))
            .map_err(|error| error.to_string())?;
        Ok(OAuthTokenSet {
            access_token: Some("ordinary-new-access".into()),
            refresh_token: Some("ordinary-new-refresh".into()),
            id_token: Some("ordinary-new-id".into()),
            token_type: Some("Bearer".into()),
            scopes: vec!["openid".into(), "email".into()],
            ..Default::default()
        })
    }
}

fn response(response: AuthResponse) -> Result<Value, Box<dyn Error>> {
    let mut headers: Vec<_> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    headers.sort();
    Ok(json!({
        "status": response.status, "headers": headers,
        "body": serde_json::from_slice::<Value>(&response.body.bytes()?)?,
    }))
}

async fn observe(mode: Mode) -> Result<Case, Box<dyn Error>> {
    let (events, received) = mpsc::channel();
    let handler = Arc::new(Refresh {
        cookie: OnceLock::new(),
        events,
    });
    let mut provider = OAuthProvider::google("ordinary-client", "ordinary-secret");
    provider.refresh_access_token = Some(handler.clone());
    if mode == Mode::Standalone {
        let tokens = provider
            .refresh_access_token
            .as_ref()
            .unwrap()
            .refresh_access_token(REFRESH_TOKEN, None)
            .await?;
        return Ok(Case {
            mode,
            events: received.try_iter().collect(),
            stored: Value::Null,
            result: json!({
                "accessToken": tokens.access_token, "refreshToken": tokens.refresh_token,
                "idToken": tokens.id_token, "tokenType": tokens.token_type, "scopes": tokens.scopes,
            }),
        });
    }
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let store = EphemeralStore::new(Arc::new(config.clone()));
    let auth = BetterAuth::<StatelessSchema>::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Refresh owner")
                .with_email("owner@social-refresh-context.test"),
        )
        .await?;
    let login = auth
        .context()
        .session_manager()
        .create_session(&owner, None, None)
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        sign_cookie_value(login.token.typed()?, SECRET)
    );
    handler.cookie.set(cookie.clone()).unwrap();
    let account = auth
        .store()
        .create_account(CreateAccount {
            id: ACCOUNT_ID.to_owned().into(),
            user_id: owner.id.clone(),
            account_id: "ordinary-google-subject".to_owned().into(),
            provider_id: "google".to_owned().into(),
            access_token: Some("ordinary-old-access".to_owned()).into(),
            refresh_token: Some(REFRESH_TOKEN.to_owned()).into(),
            id_token: Some("ordinary-old-id".to_owned()).into(),
            scope: Some("openid email".to_owned()).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(account.id.typed()?, ACCOUNT_ID);
    let mut headers = HashMap::from([
        ("cookie".to_owned(), cookie),
        ("x-refresh-label".to_owned(), "endpoint-label".to_owned()),
    ]);
    let body = json!({ "accountId": ACCOUNT_ID });
    let result = if mode == Mode::Http {
        let _ = headers.insert("content-type".into(), "application/json".into());
        let _ = headers.insert("origin".into(), ORIGIN.into());
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            "/api/auth/refresh-token".into(),
            headers,
            Some(serde_json::to_vec(&body)?),
            Some(json!({ "label": "ordinary" })),
        )
        .with_url(format!("{ORIGIN}/api/auth/refresh-token?label=ordinary").parse()?);
        response(auth.handle_request(request).await?)?
    } else {
        let request = if mode == Mode::NativeRequest {
            Some(
                AuthRequest::from_parts(
                    HttpMethod::Get,
                    "/original-source".into(),
                    HashMap::from([
                        ("x-refresh-label".into(), "original-label".into()),
                        ("accept".into(), "application/json".into()),
                    ]),
                    None,
                    None,
                )
                .with_url(format!("{ORIGIN}/original-source?label=ordinary").parse()?),
            )
        } else {
            None
        };
        response(
            auth.call_endpoint(
                HttpMethod::Post,
                "/refresh-token",
                EndpointInput {
                    body: Some(body),
                    headers: Some(headers),
                    request,
                    ..Default::default()
                },
            )
            .await?,
        )?
    };
    assert_eq!(result["status"], 200);
    let row = auth
        .store()
        .get_account("google", "ordinary-google-subject")
        .await?
        .expect("The refreshed account remains stored");
    assert_eq!(row.user_id, owner.id);
    Ok(Case {
        mode,
        events: received.try_iter().collect(),
        result,
        stored: json!({
            "accessToken": row.access_token.json()?, "refreshToken": row.refresh_token.json()?,
            "idToken": row.id_token.json()?, "scope": row.scope.json()?,
            "belongsToOwner": row.user_id == owner.id,
        }),
    })
}

#[tokio::test]
async fn social_refresh_callbacks_match_upstream_request_context() -> Result<(), Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/social-refresh-context-1.7.6.json"
    ))?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 4);
    for expected in fixture.cases {
        let actual = observe(expected.mode).await?;
        assert_eq!(actual.events.len(), 1);
        assert_eq!(actual, expected);
    }
    Ok(())
}
