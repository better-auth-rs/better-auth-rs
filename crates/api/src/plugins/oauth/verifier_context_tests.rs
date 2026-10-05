use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthError, AuthPlugin, AuthRequest, AuthUser, CreateUser, HttpMethod,
    RequestHookContext, endpoint_dispatch::EndpointDispatcher,
    utils::cookie_utils::sign_cookie_value, wire::UserView, with_request_hook_context_value,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, OnceLock, mpsc},
};

use super::{
    NativeRequest, OAuthIdTokenVerifier, OAuthPlugin, google, google_test_support::GoogleFixture,
};
use crate::plugins::test_helpers;

const ORIGIN: &str = "http://social-verifier-context.test";
const SECRET: &str = "ordinary-verifier-context-secret-at-least-32-characters";

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    SignIn,
    Link,
    Standalone,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    Http,
    NativeHeaders,
    NativeRequest,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Case {
    operation: Operation,
    transport: Option<Transport>,
    events: Vec<Value>,
    result: Value,
    stored: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    profile: Value,
    nonce: String,
    cases: Vec<Case>,
}

struct RecordingVerifier {
    endpoint: String,
    token: String,
    cookie: OnceLock<String>,
    events: mpsc::Sender<Value>,
}

impl RecordingVerifier {
    fn headers(&self, value: Option<&HashMap<String, String>>) -> Value {
        let Some(value) = value else {
            return Value::Null;
        };
        let mut headers: Vec<_> = value
            .iter()
            .map(|(name, content)| {
                let content = if name == "cookie" {
                    assert_eq!(
                        Some(content),
                        self.cookie.get(),
                        "The owner session cookie is unchanged"
                    );
                    "<owner-session-cookie>"
                } else {
                    content.as_str()
                };
                (name.as_str(), content)
            })
            .collect();
        headers.sort();
        json!(headers)
    }
}

#[async_trait]
impl OAuthIdTokenVerifier for RecordingVerifier {
    async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
        context: Option<NativeRequest<'_>>,
    ) -> Result<bool, String> {
        assert_eq!(token, self.token, "The signed fixture token is unchanged");
        let accepted = google::verify(token, &["client".into()], nonce, &self.endpoint)
            .await
            .is_some();
        assert!(
            accepted,
            "The default Google verifier accepts the ordinary signed token"
        );
        let request = context.and_then(|context| context.request).map(|request| {
            json!({
                "url": request.url().map(|url| url.as_str()),
                "method": format!("{:?}", request.method()).to_ascii_uppercase(),
                "headers": self.headers(Some(&request.headers)),
            })
        });
        self.events
            .send(json!({
                "tokenMatchesIssued": token == self.token, "nonce": nonce, "accepted": accepted,
                "hasContext": context.is_some(),
                "headers": self.headers(context.and_then(|context| context.headers)),
                "request": request,
            }))
            .map_err(|error| error.to_string())?;
        Ok(accepted)
    }
}

async fn observe(
    operation: Operation,
    transport: Option<Transport>,
    profile: &Value,
    nonce: &str,
) -> TestResult<Case> {
    let mut claims = profile.clone();
    claims["nonce"] = json!(nonce);
    let signed = GoogleFixture::start(claims).await;
    let (events, received) = mpsc::channel();
    let verifier = Arc::new(RecordingVerifier {
        endpoint: format!("{}/jwks", signed.url),
        token: signed.token.clone(),
        cookie: OnceLock::new(),
        events,
    });
    let mut provider = signed.provider();
    provider.verify_id_token = Some(verifier.clone());
    if operation == Operation::Standalone {
        let accepted = provider
            .verify_id_token
            .as_ref()
            .unwrap()
            .verify_id_token(&signed.token, Some(nonce), None)
            .await?;
        assert!(accepted);
        return Ok(Case {
            operation,
            transport,
            events: received.try_iter().collect(),
            result: json!({ "accepted": accepted }),
            stored: Value::Null,
        });
    }
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let context = test_helpers::create_test_context_with_config(config).await;
    let cookie = if operation == Operation::Link {
        let mut user = CreateUser::new()
            .with_name(profile["name"].as_str().ok_or("Missing fixture name")?)
            .with_email(profile["email"].as_str().ok_or("Missing fixture email")?)
            .with_email_verified(true);
        user.image = Some(
            profile["picture"]
                .as_str()
                .ok_or("Missing fixture picture")?
                .to_owned(),
        )
        .into();
        let owner = context.database.create_user(user).await?;
        let session = context
            .session_manager()
            .create_session(&owner, None, None)
            .await?;
        let cookie = format!(
            "better-auth.session_token={}",
            sign_cookie_value(&session.token, SECRET)
        );
        verifier.cookie.set(cookie.clone()).unwrap();
        Some(cookie)
    } else {
        None
    };
    let plugin = OAuthPlugin::new().add_provider("google", provider);
    let path = if operation == Operation::SignIn {
        "/sign-in/social"
    } else {
        "/link-social"
    };
    let mut headers = HashMap::from([("x-verifier-label".to_owned(), "endpoint-label".to_owned())]);
    if let Some(cookie) = cookie {
        let _ = headers.insert("cookie".into(), cookie);
    }
    let body =
        json!({ "provider": "google", "idToken": { "token": signed.token, "nonce": nonce } });
    let http = transport == Some(Transport::Http);
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    if http {
        let _ = headers.insert("content-type".into(), "application/json".into());
        let _ = headers.insert("origin".into(), ORIGIN.into());
        request = request.with_url(format!("{ORIGIN}/api/auth{path}?label=ordinary").parse()?);
        request.query = Some(json!({ "label": "ordinary" }));
    } else if transport == Some(Transport::NativeRequest) {
        let original = AuthRequest::from_parts(
            HttpMethod::Get,
            "/original-source".into(),
            HashMap::from([
                ("accept".into(), "application/json".into()),
                ("x-verifier-label".into(), "original-label".into()),
            ]),
            None,
            None,
        )
        .with_url(format!("{ORIGIN}/original-source?label=ordinary").parse()?);
        request = request.with_original_request(original);
    }
    request = request.with_optional_headers(Some(headers));
    request.body = Some(serde_json::to_vec(&body)?);
    let routes = <OAuthPlugin as AuthPlugin<BundledSchema>>::routes(&plugin);
    let dispatcher = EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), routes);
    let mut scope = RequestHookContext::from_request(&request);
    scope.is_http = http;
    let response = with_request_hook_context_value(
        scope,
        dispatcher.run(&mut request, http, &context, None, |request| {
            let plugin = &plugin;
            let context = &context;
            async move {
                plugin
                    .on_request(&request, context)
                    .await?
                    .ok_or_else(|| AuthError::internal("Missing ordinary OAuth response"))
            }
        }),
    )
    .await?;
    assert_eq!(response.status, 200);
    let mut result = json!({ "status": response.status, "body": serde_json::from_slice::<Value>(&response.body)? });
    assert_eq!(context.database.list_users(Default::default()).await?.1, 1);
    let user = context
        .database
        .get_user_by_email(profile["email"].as_str().ok_or("Missing fixture email")?)
        .await?
        .ok_or("The successful user remains stored")?;
    let user_id = user.id().display_string()?;
    let view = serde_json::to_value(UserView::from(&user))?;
    let accounts = context.database.get_user_accounts(&user_id).await?;
    assert_eq!(accounts.len(), 1);
    let account = &accounts[0];
    assert_eq!(account.user_id.typed()?, &user_id);
    assert_eq!(
        account.id_token.typed()?.as_deref(),
        Some(signed.token.as_str())
    );
    let sessions = context.database.get_user_sessions(&user_id).await?;
    assert_eq!(sessions.len(), 1);
    if operation == Operation::SignIn {
        for (name, marker) in [
            ("id", "<stored-user-id>"),
            ("createdAt", "<stored-createdAt>"),
            ("updatedAt", "<stored-updatedAt>"),
        ] {
            assert_eq!(result["body"]["user"][name], view[name]);
            result["body"]["user"][name] = json!(marker);
        }
        let token = result["body"]["token"]
            .as_str()
            .ok_or("Missing issued session token")?;
        assert!(!token.is_empty());
        let session = context
            .database
            .get_session(token)
            .await?
            .ok_or("The issued session remains stored")?;
        assert_eq!(session.user_id, user_id);
        result["body"]["token"] = json!({ "nonempty": true, "storedForUser": true });
    }
    Ok(Case {
        operation,
        transport,
        events: received.try_iter().collect(),
        result,
        stored: json!({
            "user": { "name": view["name"], "email": view["email"], "emailVerified": view["emailVerified"], "image": view["image"] },
            "account": { "providerId": account.provider_id.json()?, "accountId": account.account_id.json()?,
                "belongsToUser": account.user_id == user_id, "idTokenMatchesIssued": account.id_token.typed()?.as_deref() == Some(signed.token.as_str()) },
            "sessions": sessions.len(),
        }),
    })
}

#[tokio::test]
async fn social_custom_verifiers_match_upstream_request_metadata() -> TestResult<()> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/social-verifier-context-1.7.6.json"
    ))?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 7);
    for expected in fixture.cases {
        let actual = observe(
            expected.operation,
            expected.transport,
            &fixture.profile,
            &fixture.nonce,
        )
        .await?;
        assert_eq!(actual.events.len(), 1);
        assert_eq!(actual, expected);
    }
    Ok(())
}
