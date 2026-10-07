use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing::get,
};
use better_auth_core::{
    AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthUser, HttpMethod,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::super::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthCodeExchange, OAuthPlugin, OAuthProfile, OAuthProfileMapper,
    OAuthTokenHandler, OAuthTokenSet, OAuthUserInfoRequest,
};
use super::{ResolvedGenericOAuth, fetch_user_info};
use crate::plugins::test_helpers;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Records<T> = Arc<Mutex<Vec<T>>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    version: String,
    profile: Value,
    error_body: Value,
    error_headers: BTreeMap<String, String>,
    cases: Vec<Case>,
    preset_absence: Value,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    source: String,
    result: String,
    helper: Value,
    callback: Value,
}

struct Application {
    result: String,
    profile: Value,
    error_body: Value,
    error_headers: BTreeMap<String, String>,
    events: Records<String>,
}

impl Application {
    fn event(&self, event: &str) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .push(event.to_owned());
        Ok(())
    }

    fn error(&self) -> AuthResult<AuthError> {
        let mut response = AuthResponse::json(429, &self.error_body)?;
        for (name, value) in &self.error_headers {
            response.headers.append(name.clone(), value.clone());
        }
        Ok(AuthError::from(response))
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for Application {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        self.event("get")?;
        if self.result == "error" {
            return Err(self.error()?);
        }
        Ok((self.result != "null").then(|| self.profile.clone()))
    }
}

#[async_trait]
impl OAuthProfileMapper for Application {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.event("map")?;
        assert_eq!(profile.get("id"), self.profile.get("id"));
        assert_eq!(profile.get("email"), self.profile.get("email"));
        if self.result == "mapper-error" {
            return Err(self.error()?);
        }
        Ok(OAuthProfile {
            name: Some(Some("Mapped Reader".to_owned()).into()),
            email: Some(Some("mapped@example.test".to_owned()).into()),
            email_verified: Some(Some(true).into()),
            ..Default::default()
        })
    }
}

#[async_trait]
impl OAuthAccountSubject for Application {
    async fn resolve_subject(
        &self,
        _: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        self.event("subject")?;
        assert_eq!(profile.get("email"), self.profile.get("email"));
        profile
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AuthError::internal("Missing ordinary profile subject"))
    }
}

#[async_trait]
impl OAuthTokenHandler for Application {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        self.event("token")?;
        Ok(OAuthTokenSet {
            access_token: Some("ordinary-profile-access".into()),
            ..Default::default()
        })
    }
}

struct Server {
    url: String,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(
        case: &Case,
        fixture: &Fixture,
        events: Records<String>,
        requests: Records<Value>,
    ) -> TestResult<Self> {
        let result = case.result.clone();
        let profile = fixture.profile.clone();
        let app = Router::new().route("/userinfo", get(move |headers: HeaderMap| {
            let (result, profile, events, requests) = (result.clone(), profile.clone(), events.clone(), requests.clone());
            async move {
                events.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.push("http".into());
                requests.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.push(json!({
                    "path": "/userinfo", "method": "GET",
                    "authorization": headers.get("authorization").and_then(|value| value.to_str().ok()),
                }));
                let (status, body) = match result.as_str() {
                    "empty" => (StatusCode::NO_CONTENT, String::new()),
                    "error" => (StatusCode::SERVICE_UNAVAILABLE, json!({"message":"Profile service unavailable"}).to_string()),
                    "null" => (StatusCode::OK, "null".into()),
                    _ => (StatusCode::OK, profile.to_string()),
                };
                Ok::<_, StatusCode>((status, [("content-type", "application/json")], body))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/userinfo", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { url, task })
    }
}

fn config(case: &Case, application: &Arc<Application>, server: &Server) -> GenericOAuthConfig {
    GenericOAuthConfig {
        client_id: "ordinary-client".into(),
        authorization_url: Some("https://provider.example.test/authorize".into()),
        user_info_url: (case.source == "http").then(|| server.url.clone()),
        get_user_info: if case.source == "custom" {
            Some(application.clone())
        } else {
            None
        },
        map_profile_to_user: Some(application.clone()),
        account_subject: Some(application.clone()),
        get_token: Some(application.clone()),
        ..Default::default()
    }
}

fn drain<T>(records: &Records<T>) -> TestResult<Vec<T>> {
    Ok(std::mem::take(
        &mut *records.lock().map_err(|error| error.to_string())?,
    ))
}

fn response_result(response: AuthResponse) -> TestResult<Value> {
    let body = if response.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&response.body.bytes()?)?
    };
    let headers: BTreeMap<_, _> = ["retry-after", "x-profile-error"]
        .into_iter()
        .filter_map(|name| response.headers.get(name).map(|value| (name, value)))
        .collect();
    Ok(json!({
        "status": response.status, "location": response.headers.get("location"), "body": body,
        "headers": headers,
    }))
}

#[tokio::test]
async fn generic_profile_results_match_pinned_helper_and_callback_contracts() -> TestResult {
    let fixture: Fixture = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/generic-profile-results-1.7.6.json",
    ))?)?;
    assert_eq!(fixture.version, "1.7.6");
    for case in &fixture.cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = Server::start(case, &fixture, events.clone(), requests.clone()).await?;
        let application = Arc::new(Application {
            result: case.result.clone(),
            profile: fixture.profile.clone(),
            error_body: fixture.error_body.clone(),
            error_headers: fixture.error_headers.clone(),
            events: events.clone(),
        });
        let provider = ResolvedGenericOAuth {
            config: config(case, &application, &server),
            issuer: None,
            is_oidc: false,
            verifier: None,
        };
        let tokens = OAuthUserInfoRequest {
            access_token: Some("ordinary-profile-access".into()),
            ..Default::default()
        };
        let outcome = match fetch_user_info(&provider, &tokens, None, None).await {
            Ok(None) => json!({"kind":"absent"}),
            Ok(Some(response)) => {
                let user = super::AccountInfoUser {
                    id: None,
                    additional_fields: response.user.additional_fields,
                    email: response.user.email,
                    name: response.user.name,
                    image: response.user.image,
                    email_verified: response.user.email_verified,
                };
                json!({"kind":"profile","user":user,"data":response.data,"subject":response.user.id})
            }
            Err(error) => {
                json!({"kind":"error","response":response_result(error.into_auth_error().to_auth_response())?})
            }
        };
        assert_eq!(
            json!({"outcome":outcome,"events":drain(&events)?,"requests":drain(&requests)?}),
            case.helper,
            "{} helper",
            case.name
        );

        let ctx = test_helpers::create_test_context().await;
        let plugin =
            OAuthPlugin::new().add_generic_provider("generic", config(case, &application, &server));
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social").with_url(
            url::Url::parse("http://localhost:3000/api/auth/sign-in/social")?,
        );
        let _ = start
            .headers
            .insert("content-type".into(), "application/json".into());
        let _ = start
            .headers
            .insert("origin".into(), "http://localhost:3000".into());
        start.body = Some(serde_json::to_vec(&json!({
            "provider":"generic", "callbackURL":"http://localhost:3000/welcome",
            "errorCallbackURL":"http://localhost:3000/error", "disableRedirect":true,
        }))?);
        let mut started = plugin
            .on_request(&start, &ctx)
            .await?
            .ok_or("Missing sign-in response")?;
        ctx.session_manager()
            .finish_response(&start, &mut started)?;
        assert_eq!(started.status, 200);
        let body: Value = serde_json::from_slice(&started.body.bytes()?)?;
        let url = url::Url::parse(
            body.get("url")
                .and_then(Value::as_str)
                .ok_or("Missing authorization URL")?,
        )?;
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .ok_or("Missing state")?
            .1
            .into_owned();
        let cookie = started
            .headers
            .get_all("set-cookie")
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ");
        let mut callback_url = url::Url::parse("http://localhost:3000/api/auth/callback/generic")?;
        callback_url
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", "ordinary-code");
        let mut callback =
            AuthRequest::new(HttpMethod::Get, "/callback/generic").with_url(callback_url);
        callback.query = Some(json!({"state":state,"code":"ordinary-code"}));
        let _ = callback.headers.insert("cookie".into(), cookie);
        let response = match plugin.on_request(&callback, &ctx).await {
            Ok(Some(mut response)) => {
                ctx.session_manager()
                    .finish_response(&callback, &mut response)?;
                response
            }
            Ok(None) => return Err("Missing callback response".into()),
            Err(error) => error.to_auth_response(),
        };
        let mut users = Vec::new();
        let mut accounts = Vec::new();
        let mut sessions = 0;
        for email in ["mapped@example.test", "reader@example.test"] {
            if let Some(user) = ctx.database.get_user_by_email(email).await? {
                let id = user.id().display_string()?;
                let fields = serde_json::to_value(&user)?;
                users.push(json!({"email":fields.get("email"),"name":fields.get("name"),"emailVerified":fields.get("emailVerified")}));
                for account in ctx.database.get_user_accounts(&id).await? {
                    accounts.push(
                        json!({"providerId":account.provider_id,"accountId":account.account_id}),
                    );
                }
                sessions += ctx.database.get_user_sessions(&id).await?.len();
            }
        }
        assert_eq!(
            json!({
                "response":response_result(response)?, "events":drain(&events)?, "requests":drain(&requests)?,
                "storage":{"user":users,"account":accounts,"sessions":sessions},
            }),
            case.callback,
            "{} callback",
            case.name
        );
    }
    let entra = GenericOAuthConfig::microsoft_entra_id(
        "client",
        "secret",
        "11111111-1111-1111-1111-111111111111",
    )?;
    let handler = entra
        .get_user_info
        .as_ref()
        .ok_or("Missing Entra handler")?;
    let tokens = OAuthUserInfoRequest::default();
    let result = handler
        .get_user_info_with_context(&tokens, GenericOAuthProfileContext::new(&entra, None, None))
        .await?;
    let mut preset_absence = vec![json!({"name":"entra-no-token","result":result})];
    for result in ["null", "empty", "error"] {
        let case = Case {
            name: format!("line-{result}"),
            source: "http".into(),
            result: result.into(),
            helper: Value::Null,
            callback: Value::Null,
        };
        let server = Server::start(&case, &fixture, Default::default(), Default::default()).await?;
        let mut line = GenericOAuthConfig::line("client", "secret");
        line.user_info_url = Some(server.url.clone());
        let handler = line.get_user_info.as_ref().ok_or("Missing LINE handler")?;
        let tokens = OAuthUserInfoRequest {
            access_token: Some("ordinary-profile-access".into()),
            ..Default::default()
        };
        let result = handler
            .get_user_info_with_context(&tokens, GenericOAuthProfileContext::new(&line, None, None))
            .await?;
        preset_absence.push(json!({"name":case.name,"result":result}));
    }
    assert_eq!(json!(preset_absence), fixture.preset_absence);
    Ok(())
}
