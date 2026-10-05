use super::provider_tokens::{
    refresh_tokens_via_provider, validate_authorization_code_via_provider,
};
use super::providers::{OAuthProvider, OAuthTokenSet};
use super::resolved::ResolvedProvider;
use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    routing::post,
};
use better_auth_core::{AuthRequest, HttpMethod};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, sync::mpsc};

type TestResult<T> = Result<T, Box<dyn Error>>;

async fn token(
    State((response, requests)): State<(Value, mpsc::Sender<Value>)>,
    method: Method,
    headers: HeaderMap,
    Form(body): Form<BTreeMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let header = |name| {
        headers
            .get(name)
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    };
    requests
        .send(json!({
            "method": method.as_str(),
            "contentType": header("content-type")?,
            "accept": header("accept")?,
            "authorization": header("authorization")?,
            "body": body,
        }))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(response))
}

fn token_json(token: OAuthTokenSet) -> Value {
    let mut fields = serde_json::Map::from_iter([("scopes".into(), json!(token.scopes))]);
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

async fn grants(
    mut config: OAuthProvider,
    callback: &str,
    verifier: &str,
    response: Value,
) -> TestResult<(Vec<Value>, Value)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    config.token_url = format!("http://{}/token", listener.local_addr()?);
    let (requests, captured) = mpsc::channel();
    let router = Router::new()
        .route("/token", post(token))
        .with_state((response, requests));
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let provider = ResolvedProvider {
        config: config.resolve(),
        generic: None,
    };
    let result = async {
        let code = validate_authorization_code_via_provider(
            &provider,
            "ordinary-code",
            callback,
            Some(verifier),
            Some("ordinary-device"),
        )
        .await?;
        let refresh = refresh_tokens_via_provider(
            &provider,
            "ordinary-refresh",
            &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
        )
        .await?;
        Ok((
            captured.try_iter().collect(),
            json!([token_json(code), token_json(refresh)]),
        ))
    }
    .await;
    server.abort();
    result
}

#[tokio::test]
async fn discord_code_and_refresh_match_the_pinned_ordinary_contract() -> TestResult<()> {
    let mut config = OAuthProvider::discord("client", "secret");
    config.redirect_uri = Some("https://app.example.test/configured-callback".into());
    let response = json!({
        "access_token": "ordinary-access",
        "refresh_token": "ordinary-refresh",
        "token_type": "Bearer",
    });
    let (requests, tokens) = grants(
        config,
        "https://app.example.test/callback/discord",
        "ordinary-code-verifier-at-least-forty-three-characters",
        response.clone(),
    )
    .await?;
    assert_eq!(
        requests,
        vec![
            json!({
                "method": "POST", "authorization": null,
                "contentType": "application/x-www-form-urlencoded",
                "accept": "application/json",
                "body": {
                    "grant_type": "authorization_code", "code": "ordinary-code",
                    "redirect_uri": "https://app.example.test/configured-callback",
                    "client_id": "client", "client_secret": "secret",
                },
            }),
            json!({
                "method": "POST", "authorization": null,
                "contentType": "application/x-www-form-urlencoded",
                "accept": "application/json",
                "body": {
                    "grant_type": "refresh_token", "refresh_token": "ordinary-refresh",
                    "client_id": "client", "client_secret": "secret",
                },
            }),
        ]
    );
    assert_eq!(
        tokens,
        json!([
            {"tokenType":"Bearer", "accessToken":"ordinary-access", "refreshToken":"ordinary-refresh", "scopes":[], "raw":response},
            {"tokenType":"Bearer", "accessToken":"ordinary-access", "refreshToken":"ordinary-refresh", "scopes":[]},
        ])
    );
    Ok(())
}

#[tokio::test]
async fn social_line_code_and_refresh_match_the_captured_requests_and_tokens() -> TestResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/social-line-1.7.6.json"
    ))?;
    let expected_requests = fixture["requests"]
        .as_array()
        .ok_or("missing LINE requests")?
        .iter()
        .filter(|request| request["url"] == fixture["endpoints"]["token"])
        .map(|request| {
            let body: BTreeMap<String, String> = url::form_urlencoded::parse(
                request["body"]
                    .as_str()
                    .ok_or("missing LINE request body")?
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
    let code_request = expected_requests
        .first()
        .ok_or("missing LINE code request")?;
    let config = OAuthProvider::line(
        fixture["clientId"]
            .as_str()
            .ok_or("missing LINE client ID")?,
        fixture["clientSecret"]
            .as_str()
            .ok_or("missing LINE client secret")?,
    );
    let (requests, tokens) = grants(
        config,
        fixture["callbackURL"]
            .as_str()
            .ok_or("missing LINE callback URL")?,
        code_request["body"]["code_verifier"]
            .as_str()
            .ok_or("missing LINE verifier")?,
        fixture["grantTokens"][0]["raw"].clone(),
    )
    .await?;
    assert_eq!(requests, expected_requests);
    assert_eq!(tokens, fixture["grantTokens"]);
    Ok(())
}
