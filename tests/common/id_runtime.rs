#![allow(
    clippy::unwrap_used,
    reason = "Contract fixtures fail on unexpected setup or response errors"
)]
use async_trait::async_trait;
use better_auth::{AuthResult, BetterAuth, PasswordHasher};
use better_auth_core::store::StatelessSchema;
use better_auth_core::{AuthRequest, HttpMethod};
use serde_json::Value;
use std::collections::HashMap;

pub(crate) struct Hasher;
#[async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("hashed:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("hashed:{password}"))
    }
}
pub(crate) async fn request(
    auth: &BetterAuth<StatelessSchema>,
    path: &str,
    body: Option<Value>,
    cookie: &str,
) -> (u16, Value, String) {
    let mut headers = HashMap::from([("origin".into(), "http://localhost:3000".into())]);
    if body.is_some() {
        let _ = headers.insert("content-type".into(), "application/json".into());
    }
    if !cookie.is_empty() {
        let _ = headers.insert("cookie".into(), cookie.into());
    }
    let req = AuthRequest::from_parts(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path.into(),
        headers,
        body.map(|body| serde_json::to_vec(&body).unwrap()),
        None,
    )
    .with_url(
        format!("http://localhost:3000/api/auth{path}")
            .parse()
            .unwrap(),
    );
    let response = auth.handle_request(req).await.unwrap();
    let cookie = response
        .headers
        .get_all("set-cookie")
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let bytes = response.body.bytes().unwrap();
    let body = if bytes.is_empty() {
        assert_eq!(
            response.status, 500,
            "Native HTTP errors have an empty body"
        );
        Value::String(String::new())
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (response.status, body, cookie)
}
