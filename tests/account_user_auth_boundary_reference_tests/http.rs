use super::*;
use axum::{Router, body::Body, http::Request};
use better_auth::{
    integrations::axum::AxumIntegration,
    plugins::{
        EmailPasswordPlugin,
        oauth::{OAuthPlugin, OAuthProvider},
    },
};
use better_auth_core::{middleware::RateLimitConfig, utils::cookie_utils::verify_cookie_value};
use tower::ServiceExt;

pub(super) struct Harness<S: AuthSchema> {
    pub(super) auth: Arc<BetterAuth<S>>,
    pub(super) flow: Option<super::oauth_flow::Flow>,
}

pub(super) async fn auth<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    config: AuthConfig,
    scenario: &Scenario,
    events: &Events,
) -> TestResult<Harness<S>> {
    let callbacks = Arc::new(callbacks::Callbacks {
        events: events.clone(),
        accounts_one: scenario.accounts_one,
        callback: scenario.callback,
    });
    let flow = if scenario.callback {
        Some(super::oauth_flow::Flow::start(events.clone()).await?)
    } else {
        None
    };
    let mut provider = OAuthProvider::google("fixture-client", "fixture-client-secret");
    if let Some(flow) = &flow {
        assert_eq!(provider.token_url, super::oauth_flow::TOKEN_URL);
        provider.token_url = flow.endpoint.clone();
    }
    provider.verify_id_token = Some(callbacks.clone());
    provider.get_user_info = Some(callbacks.clone());
    provider.override_user_info_on_sign_in = scenario.override_user_info;
    let auth = Arc::new(
        BetterAuth::new(config)
            .store_arc(store)
            .plugin(OAuthPlugin::new().add_provider("google", provider))
            .plugin(EmailPasswordPlugin::new().password_hasher(callbacks.clone()))
            .validate_user_info(callbacks.clone())
            .on_api_error(callbacks)
            .rate_limit(RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await?,
    );
    Ok(Harness { auth, flow })
}

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) headers: Vec<[String; 2]>,
    pub(super) cookies: Vec<String>,
    pub(super) body: String,
}

pub(super) async fn request<S: AuthSchema>(
    auth: Arc<BetterAuth<S>>,
    input: &fixture::Request,
) -> TestResult<Response> {
    let router = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth);
    let mut request = Request::builder()
        .method(input.method.as_str())
        .uri(&input.url);
    for [name, value] in &input.headers {
        request = request.header(name, value);
    }
    let body = if input.body.is_null() {
        Body::empty()
    } else {
        Body::from(serde_json::to_vec(&input.body)?)
    };
    let response = router.oneshot(request.body(body)?).await?;
    let status = response.status().as_u16();
    let mut headers = response
        .headers()
        .iter()
        .map(|(name, value)| Ok([name.to_string(), value.to_str()?.to_owned()]))
        .collect::<TestResult<Vec<_>>>()?;
    headers.sort();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await?
            .to_vec(),
    )?;
    // Axum's transport framing is observed separately from the authentication response headers.
    for [name, value] in &headers {
        if name == "content-length" {
            assert_eq!(value.parse::<usize>()?, body.len());
        }
    }
    headers.retain(|[name, _]| name != "content-length");
    Ok(Response {
        status,
        headers,
        cookies,
        body,
    })
}

pub(super) fn assert_response(
    mut response: Response,
    expected: &fixture::Response,
    anchors: &observe::Anchors,
) -> TestResult {
    assert_eq!(response.status, expected.status);
    for cookie in &mut response.cookies {
        if cookie.starts_with("better-auth.session_token=") {
            normalize_cookie(cookie, anchors)?;
        }
    }
    for [name, value] in &mut response.headers {
        if name == "set-cookie" && value.starts_with("better-auth.session_token=") {
            normalize_cookie(value, anchors)?;
        }
    }
    assert_eq!(response.headers, expected.headers);
    assert_eq!(response.cookies, expected.cookies);
    if expected.body.is_empty() {
        assert_eq!(response.body, "");
    } else {
        let mut actual: Value = serde_json::from_str(&response.body)?;
        assert_eq!(actual["token"].as_str(), anchors.token.as_deref());
        actual["token"] = json!("<session-token>");
        assert_eq!(actual, serde_json::from_str::<Value>(&expected.body)?);
    }
    Ok(())
}

fn normalize_cookie(cookie: &mut String, anchors: &observe::Anchors) -> TestResult {
    let (pair, attributes) = cookie
        .split_once(';')
        .ok_or("Missing session Cookie attributes")?;
    let (name, signed) = pair.split_once('=').ok_or("Missing session Cookie value")?;
    assert_eq!(name, "better-auth.session_token");
    let token = verify_cookie_value(signed, SECRET).ok_or("Invalid session Cookie signature")?;
    assert_eq!(Some(token.as_str()), anchors.token.as_deref());
    assert!(
        anchors.session_id.is_some(),
        "Cookie issuance requires a persisted Session"
    );
    assert_eq!(attributes, " Max-Age=3600; Path=/; HttpOnly; SameSite=Lax");
    *cookie = format!("{name}=<verified-signed-session-token>;{attributes}");
    Ok(())
}
