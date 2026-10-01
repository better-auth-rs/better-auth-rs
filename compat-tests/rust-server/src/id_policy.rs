use std::sync::{Arc, Mutex};

use better_auth::config::{IdGeneration, IdGenerator};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use better_auth_core::store::{MemoryCacheAdapter, SecondaryStorage};
use better_auth_core::{AuthRequest, HttpMethod};
use serde_json::{Value, json};

fn summary(status: u16, body: &Value, cookie: &str) -> Value {
    let keys = |value: &Value| {
        value.as_object().map(|value| {
            let mut keys: Vec<_> = value.keys().cloned().collect();
            keys.sort();
            keys
        })
    };
    json!({"status":status,"null":body.is_null(),"code":body.get("code"),
        "userKeys":keys(&body["user"]),"sessionKeys":keys(&body["session"]),
        "email":body["user"].get("email"),"hasCookie":!cookie.is_empty()})
}

pub async fn run(input: Value) -> AuthResult<Value> {
    let mode = input["mode"].as_str().unwrap().to_owned();
    let secondary = input["secondary"].as_bool().unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new("runtime-id-probe-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000");
    config.advanced.database.generate_id = Some(if mode == "database" {
        IdGeneration::Database
    } else {
        let calls = calls.clone();
        IdGeneration::Custom(IdGenerator::new(move |request| {
            let mut calls = calls.lock().unwrap();
            calls.push(json!({"model":request.model,"size":request.size}));
            Ok(if mode == "callback-disabled" {
                None
            } else {
                Some(
                    if mode == "callback-empty" || mode == format!("{}-missing", request.model) {
                        String::new()
                    } else {
                        format!("{}-{}", request.model, calls.len())
                    },
                )
            })
        }))
    });
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut builder = BetterAuth::stateless(config)
        .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(crate::jwt_adapter::Hasher)))
        .plugin(SessionManagementPlugin::new());
    if secondary {
        builder = builder.secondary_storage(cache.clone());
    }
    let auth = builder.build().await?;
    let mut results = Vec::new();
    let mut cookie = String::new();
    for (path, body) in [
        (
            "/sign-up/email",
            Some(json!({"email":"id@example.com","name":"ID","password":"long-enough-password"})),
        ),
        ("/get-session", None),
        (
            "/sign-in/email",
            Some(json!({"email":"id@example.com","password":"long-enough-password"})),
        ),
        ("/get-session", None),
    ] {
        let mut request = AuthRequest::new(
            if body.is_some() {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            },
            path,
        )
        .with_url(
            format!("http://localhost:3000/api/auth{path}")
                .parse()
                .unwrap(),
        );
        let _ = request
            .headers
            .insert("origin".into(), "http://localhost:3000".into());
        if let Some(body) = body {
            let _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.body = Some(serde_json::to_vec(&body)?);
        } else if !cookie.is_empty() {
            let _ = request.headers.insert("cookie".into(), cookie.clone());
        }
        let response = auth.handle_request(request).await?;
        cookie = response
            .headers
            .get_all("set-cookie")
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ");
        let body: Value = serde_json::from_slice(&response.body)?;
        results.push(summary(response.status, &body, &cookie));
    }
    let cached_missing_user = cache.get("active-sessions-undefined").await?.is_some();
    Ok(
        json!({"steps":results,"calls":calls.lock().unwrap().clone(),"cachedMissingUser":cached_missing_user}),
    )
}
