use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthUser, CreateUser,
    HttpMethod, RequestHookContext, endpoint_dispatch::EndpointDispatcher,
    utils::cookie_utils::sign_cookie_value, wire::UserView, with_request_hook_context_value,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    error::Error,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
};

use super::{
    NativeRequest, OAuthCallbacks, OAuthIdTokenVerifier, OAuthPlugin, google,
    google_test_support::GoogleFixture,
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum VerifierResult {
    Accept,
    Reject,
    Fail,
    Disabled,
    Both,
}

struct RuntimeMarker(String);

struct RejectingMetadataVerifier(Arc<AtomicUsize>);

#[async_trait]
impl OAuthIdTokenVerifier for RejectingMetadataVerifier {
    async fn verify_id_token(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<NativeRequest<'_>>,
    ) -> Result<bool, String> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(false)
    }
}

async fn exercise_endpoint_verifier(
    signed: &GoogleFixture,
    operation: Operation,
    transport: Transport,
    outcome: VerifierResult,
) -> TestResult<()> {
    const EMAIL: &str = "typed-verifier@example.test";
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let mut context = test_helpers::create_test_context_with_config(config).await;
    let runtime_user = context
        .database
        .create_user(
            CreateUser::new()
                .with_name("Runtime marker")
                .with_email("runtime@example.test"),
        )
        .await?;
    let runtime_id = runtime_user.id().display_string()?;
    let mut owner_id = None;
    let mut headers = HashMap::from([("x-verifier-label".into(), "endpoint-label".into())]);
    if operation == Operation::Link {
        let owner = context
            .database
            .create_user(
                CreateUser::new()
                    .with_name("Typed verifier")
                    .with_email(EMAIL)
                    .with_email_verified(true),
            )
            .await?;
        owner_id = Some(owner.id().display_string()?);
        let session = context
            .session_manager()
            .create_session(&owner, None, None)
            .await?;
        let _ = headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                sign_cookie_value(&session.token, SECRET),
            ),
        );
    }
    let path = if operation == Operation::SignIn {
        "/sign-in/social"
    } else {
        "/link-social"
    };
    let body = json!({ "provider": "google", "idToken": { "token": signed.token, "nonce": "typed-nonce" } });
    let mut raw_body = body.clone();
    raw_body["ignored"] = json!("unvalidated top-level field");
    raw_body["idToken"]["ignored"] = json!("unvalidated nested field");
    let query = match transport {
        Transport::Http => Some(json!({ "label": "endpoint-query" })),
        Transport::NativeHeaders => None,
        Transport::NativeRequest => Some(Value::Null),
    };
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    let http = transport == Transport::Http;
    if http {
        let _ = headers.insert("content-type".into(), "application/json".into());
        let _ = headers.insert("origin".into(), ORIGIN.into());
        request =
            request.with_url(format!("{ORIGIN}/api/auth{path}?label=endpoint-query").parse()?);
    } else if transport == Transport::NativeRequest {
        request = request.with_original_request(
            AuthRequest::new(HttpMethod::Get, "/original-source")
                .with_optional_headers(Some(HashMap::from([(
                    "x-verifier-label".into(),
                    "original-label".into(),
                )])))
                .with_url(format!("{ORIGIN}/original-source?label=original-query").parse()?),
        );
    }
    request = request.with_optional_headers(Some(headers));
    request.body = Some(serde_json::to_vec(&raw_body)?);
    request.query = query.clone();
    request.set_server_context("verifier-state", "before".into())?;

    let calls = Arc::new(AtomicUsize::new(0));
    let recorded_calls = calls.clone();
    let endpoint = format!("{}/jwks", signed.url);
    let expected_owner = owner_id.clone();
    let callbacks = OAuthCallbacks::<BundledSchema>::default().verify_id_token(
        "google",
        move |token, nonce, context| {
            let calls = recorded_calls.clone();
            let endpoint = endpoint.clone();
            let body = body.clone();
            let query = query.clone();
            let owner_id = expected_owner.clone();
            Box::pin(async move {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(context.path, Some(path));
                assert_eq!(context.body, body);
                assert_eq!(context.query(), query.as_ref());
                assert!(context.params.is_empty());
                assert!(context.transaction.is_none());
                assert!(context.response.is_none());
                assert!(context.new_session()?.is_none());
                assert_eq!(context.auth.config.base_url.as_static(), Some(ORIGIN));
                assert_eq!(
                    context.headers().unwrap()["x-verifier-label"],
                    "endpoint-label"
                );
                let runtime = context.auth.extensions.get::<RuntimeMarker>().unwrap();
                let user = context
                    .auth
                    .database
                    .get_user_by_email("runtime@example.test")
                    .await?
                    .unwrap();
                assert_eq!(user.id().display_string()?, runtime.0);
                assert_eq!(
                    context
                        .session
                        .as_ref()
                        .map(|(user, _)| user.id.typed().unwrap()),
                    owner_id.as_ref()
                );
                if let Some((user, session)) = &context.session {
                    assert_eq!(session.user_id, user.id);
                    assert!(
                        context
                            .auth
                            .database
                            .get_session(&session.token)
                            .await?
                            .is_some()
                    );
                }
                match transport {
                    Transport::Http => {
                        let original = context.request.unwrap();
                        assert_eq!(original.path(), path);
                        assert_eq!(
                            original.input_body()?.unwrap()["ignored"],
                            "unvalidated top-level field"
                        );
                    }
                    Transport::NativeHeaders => assert!(context.request.is_none()),
                    Transport::NativeRequest => {
                        let original = context.request.unwrap();
                        assert_eq!(original.path(), "/original-source");
                        assert_eq!(original.method(), &HttpMethod::Get);
                        assert_eq!(original.headers["x-verifier-label"], "original-label");
                    }
                }
                let request = context.input_request().unwrap();
                assert_eq!(
                    request.server_context("verifier-state")?,
                    Some("before".into())
                );
                request.set_server_context("verifier-state", "verified".into())?;
                context.set_header("x-verifier-state", "verified")?;
                assert_eq!(nonce, Some("typed-nonce"));
                let accepted = google::verify(token, &["client".into()], nonce, &endpoint)
                    .await
                    .is_some();
                assert!(
                    accepted,
                    "The callback must verify the signed token before accepting it"
                );
                match outcome {
                    VerifierResult::Accept | VerifierResult::Both => Ok(accepted),
                    VerifierResult::Reject => Ok(false),
                    VerifierResult::Fail => Err(AuthError::internal("private verifier failure")),
                    VerifierResult::Disabled => panic!("Disabled providers must skip the callback"),
                }
            })
        },
    );
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let mut provider = signed.provider();
    provider.disable_id_token_sign_in = outcome == VerifierResult::Disabled;
    if outcome == VerifierResult::Both {
        provider.verify_id_token = Some(Arc::new(RejectingMetadataVerifier(legacy_calls.clone())));
    }
    let plugin = OAuthPlugin::new()
        .add_provider("google", provider)
        .callbacks(callbacks);
    let mut init = AuthInitContext::new(context.config.clone(), context.database.clone());
    init.extensions.insert(RuntimeMarker(runtime_id.clone()));
    plugin.on_init(&mut init).await?;
    context.extensions = init.extensions;
    let dispatcher =
        EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), plugin.routes());
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
                    .ok_or_else(|| AuthError::internal("Missing typed verifier response"))
            }
        }),
    )
    .await
    .unwrap_or_else(|error| error.to_auth_response());
    let accepted = matches!(outcome, VerifierResult::Accept | VerifierResult::Both);
    let disabled = outcome == VerifierResult::Disabled;
    assert_eq!(calls.load(Ordering::SeqCst), usize::from(!disabled));
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        request.server_context("verifier-state")?,
        Some(if disabled { "before" } else { "verified" }.into())
    );
    assert_eq!(
        response.headers.get("x-verifier-state").map(String::as_str),
        (!disabled).then_some("verified")
    );
    if accepted {
        assert_eq!(response.status, 200);
    } else {
        assert_eq!(response.status, if disabled { 404 } else { 401 });
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body)?,
            if disabled {
                json!({ "code": "ID_TOKEN_NOT_SUPPORTED", "message": "id_token not supported" })
            } else {
                json!({ "code": "INVALID_TOKEN", "message": "Invalid token" })
            }
        );
    }
    assert!(
        context
            .database
            .get_user_accounts(&runtime_id)
            .await?
            .is_empty()
    );
    assert!(
        context
            .database
            .get_user_sessions(&runtime_id)
            .await?
            .is_empty()
    );
    let user = context.database.get_user_by_email(EMAIL).await?;
    let stored = accepted || operation == Operation::Link;
    assert_eq!(
        context.database.list_users(Default::default()).await?.1,
        1 + usize::from(stored)
    );
    assert_eq!(user.is_some(), stored);
    if let Some(user) = user {
        let id = user.id().display_string()?;
        if let Some(owner_id) = owner_id {
            assert_eq!(id, owner_id);
        }
        let accounts = context.database.get_user_accounts(&id).await?;
        assert_eq!(accounts.len(), usize::from(accepted));
        if let Some(account) = accounts.first() {
            assert_eq!(account.user_id.typed()?, &id);
            assert_eq!(
                account.id_token.typed()?.as_deref(),
                Some(signed.token.as_str())
            );
        }
        assert_eq!(context.database.get_user_sessions(&id).await?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn social_typed_verifiers_receive_the_active_endpoint() -> TestResult<()> {
    let signed = GoogleFixture::start(json!({
        "sub": "typed-verifier", "name": "Typed verifier", "email": "typed-verifier@example.test",
        "email_verified": true, "nonce": "typed-nonce",
    }))
    .await;
    for operation in [Operation::SignIn, Operation::Link] {
        for transport in [
            Transport::Http,
            Transport::NativeHeaders,
            Transport::NativeRequest,
        ] {
            exercise_endpoint_verifier(&signed, operation, transport, VerifierResult::Accept)
                .await?;
        }
        for outcome in [
            VerifierResult::Reject,
            VerifierResult::Fail,
            VerifierResult::Disabled,
            VerifierResult::Both,
        ] {
            exercise_endpoint_verifier(&signed, operation, Transport::NativeHeaders, outcome)
                .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn social_typed_verifiers_reject_unregistered_provider_names() -> TestResult<()> {
    let context = test_helpers::create_test_context().await;
    let callbacks = OAuthCallbacks::<BundledSchema>::default()
        .verify_id_token("unregistered", |_, _, _| Box::pin(async { Ok(false) }));
    let plugin = OAuthPlugin::new().callbacks(callbacks);
    let mut init = AuthInitContext::new(context.config, context.database);
    let error = plugin.on_init(&mut init).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("OAuth verifier provider unregistered is not registered")
    );
    Ok(())
}
