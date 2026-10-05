use super::{
    OAuthProvider, OAuthTokenSet, OAuthUserInfoRequest,
    authorization::{AuthorizationRequest, build_authorization_url},
    provider_tokens::{refresh_tokens_via_provider, validate_authorization_code_via_provider},
    resolved::ResolvedProvider,
    social_profile::fetch_user_info_for_code,
    types::AccountInfoUser,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthRequest, HttpMethod};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt::Debug, sync::mpsc};
use url::Url;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    issuer: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    url: String,
    method: String,
    content_type: Option<String>,
    authorization: Option<String>,
    body: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    name: String,
    options: Options,
    #[serde(rename = "authorizationURL")]
    authorization_url: String,
    requests: Vec<Request>,
    code_tokens: Value,
    refresh_tokens: Value,
    user_info: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    version: String,
    client_id: String,
    client_secret: String,
    #[serde(rename = "callbackURL")]
    callback_url: String,
    code_verifier: String,
    state: String,
    profile: Value,
    token_response: Value,
    cases: Vec<Case>,
}

#[derive(Clone)]
struct ServerState {
    token_origin: String,
    profile_origin: String,
    token_response: Value,
    profile: Value,
    requests: mpsc::Sender<Request>,
}

async fn respond(
    State(state): State<ServerState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, StatusCode> {
    let (origin, response) = match method {
        Method::POST => (&state.token_origin, state.token_response.clone()),
        Method::GET => (&state.profile_origin, state.profile.clone()),
        _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    let header = |name| {
        headers
            .get(name)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    };
    state
        .requests
        .send(Request {
            url: format!("{origin}{uri}"),
            method: method.to_string(),
            content_type: header("content-type")?,
            authorization: header("authorization")?,
            body: (!body.is_empty()).then(|| {
                url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect()
            }),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(response))
}

fn same<T: Debug + PartialEq>(actual: &T, expected: &T, label: &str) -> TestResult<()> {
    if actual != expected {
        return Err(format!("{label}: actual {actual:?}; expected {expected:?}").into());
    }
    Ok(())
}

fn route_locally(endpoint: &mut String, local_origin: &str) -> TestResult<String> {
    let origin = Url::parse(endpoint)?.origin().ascii_serialization();
    let path = endpoint
        .strip_prefix(&origin)
        .ok_or("Expected a URL origin prefix")?;
    // Preserve the constructed path; restore only the observed request's configured origin.
    *endpoint = format!("{local_origin}{path}");
    Ok(origin)
}

fn token_json(token: OAuthTokenSet) -> Value {
    let mut fields = Map::from_iter([("scopes".into(), json!(token.scopes))]);
    for (name, value) in [
        ("tokenType", token.token_type.map(Value::String)),
        ("accessToken", token.access_token.map(Value::String)),
        ("refreshToken", token.refresh_token.map(Value::String)),
        ("idToken", token.id_token.map(Value::String)),
        (
            "accessTokenExpiresAt",
            token.access_token_expires_at.map(|value| json!(value)),
        ),
        (
            "refreshTokenExpiresAt",
            token.refresh_token_expires_at.map(|value| json!(value)),
        ),
        ("raw", token.raw),
    ] {
        if let Some(value) = value {
            let _ = fields.insert(name.into(), value);
        }
    }
    Value::Object(fields)
}

async fn check_case(fixture: &Fixture, case: &Case) -> TestResult<()> {
    let config = match case.options.issuer.as_deref() {
        Some(issuer) => {
            OAuthProvider::gitlab_with_issuer(&fixture.client_id, &fixture.client_secret, issuer)
        }
        None => OAuthProvider::gitlab(&fixture.client_id, &fixture.client_secret),
    };
    let mut provider = ResolvedProvider {
        config: config.resolve(),
        generic: None,
    };
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(fixture.code_verifier.as_bytes()));
    let authorization = build_authorization_url(
        &provider,
        AuthorizationRequest {
            callback_url: &fixture.callback_url,
            scopes: None,
            state: &fixture.state,
            code_challenge: &code_challenge,
            login_hint: None,
            nonce: None,
            additional_params: None,
        },
    )?;
    same(
        &authorization,
        &case.authorization_url,
        &format!("{} authorization URL", case.name),
    )?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_origin = format!("http://{}", listener.local_addr()?);
    let token_origin = route_locally(&mut provider.config.token_url, &local_origin)?;
    let profile_origin = route_locally(
        provider
            .config
            .user_info_url
            .as_mut()
            .ok_or("Expected the GitLab profile endpoint")?,
        &local_origin,
    )?;
    let (requests, captured) = mpsc::channel();
    let router = Router::new().fallback(respond).with_state(ServerState {
        token_origin,
        profile_origin,
        token_response: fixture.token_response.clone(),
        profile: fixture.profile.clone(),
        requests,
    });
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let code = validate_authorization_code_via_provider(
            &provider,
            "ordinary-code",
            &fixture.callback_url,
            Some(&fixture.code_verifier),
            None,
        )
        .await?;
        same(
            &token_json(code),
            &case.code_tokens,
            &format!("{} code tokens", case.name),
        )?;
        let refresh = refresh_tokens_via_provider(
            &provider,
            "ordinary-refresh",
            &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
        )
        .await?;
        same(
            &token_json(refresh),
            &case.refresh_tokens,
            &format!("{} refresh tokens", case.name),
        )?;
        let info = fetch_user_info_for_code(
            &provider,
            OAuthUserInfoRequest {
                access_token: Some("ordinary-access".into()),
                ..Default::default()
            },
            None,
        )
        .await?
        .ok_or("Expected the ordinary active GitLab profile")?;
        let user = AccountInfoUser {
            id: None,
            name: info.user.name,
            email: info.user.email,
            image: info.user.image,
            email_verified: info.user.email_verified,
            additional_fields: info.user.additional_fields,
        };
        same(
            &json!({"user": user, "data": info.data}),
            &case.user_info,
            &format!("{} profile", case.name),
        )?;
        same(
            &captured.try_iter().collect(),
            &case.requests,
            &format!("{} request targets and forms", case.name),
        )
    }
    .await;
    server.abort();
    result
}

#[tokio::test]
async fn gitlab_issuer_matches_upstream_authorization_grants_and_profile_targets() -> TestResult<()>
{
    let fixture: Fixture = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/gitlab-issuer-1.7.6.json"
    ))?)?;
    same(
        &fixture.version.as_str(),
        &"1.7.6",
        "Pinned upstream version",
    )?;
    same(
        &fixture
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        &vec![
            "omitted",
            "empty",
            "self-hosted",
            "trailing-slash",
            "subpath",
        ],
        "Complete issuer matrix",
    )?;
    for case in &fixture.cases {
        check_case(&fixture, case).await?;
    }
    Ok(())
}
