use better_auth::{
    AuthBuilder, AuthConfig, AuthResult,
    plugins::{EmailPasswordPlugin, SessionManagementPlugin},
};
use better_auth_core::{
    AuthRequest, AuthResponse, CookieAttributes, CookieOverride, HttpMethod,
    config::CookieCacheConfig, middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};

fn cookies(response: &AuthResponse) -> Value {
    let mut cookies = response
        .headers
        .get_all("set-cookie")
        .map(|value| {
            let mut parts = value.split(';');
            let name = parts.next().unwrap().split('=').next().unwrap();
            let attributes = parts
                .filter_map(|part| {
                    let (name, value) = part
                        .trim()
                        .split_once('=')
                        .map_or((part.trim(), Value::Bool(true)), |(name, value)| {
                            (name, Value::String(value.to_ascii_lowercase()))
                        });
                    (!name.eq_ignore_ascii_case("expires"))
                        .then(|| (name.to_ascii_lowercase(), value))
                })
                .collect::<serde_json::Map<_, _>>();
            json!({"name":name,"attributes":attributes})
        })
        .collect::<Vec<_>>();
    cookies.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!(cookies)
}

pub async fn run() -> AuthResult<Value> {
    let mut config =
        AuthConfig::new("dynamic-cookie-fixture-secret-at-least-thirty-two-characters")
            .base_url("https://auth.example.test");
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        ..Default::default()
    });
    config.advanced.cookie_prefix = Some("tenant".into());
    config.advanced.default_cookie_attributes = CookieAttributes {
        path: Some("/global".into()),
        domain: Some(".example.test".into()),
        max_age: Some(7.0),
        secure: Some(false),
        ..Default::default()
    };
    config.advanced.cookies.get_or_insert_default().insert(
        "session_token".into(),
        CookieOverride {
            name: Some("custom-token".into()),
            attributes: CookieAttributes {
                path: Some("/auth".into()),
                http_only: Some(false),
                max_age: Some(180.0),
                ..Default::default()
            },
        },
    );
    config.advanced.cookies.get_or_insert_default().insert(
        "session_data".into(),
        CookieOverride {
            name: Some("custom-cache".into()),
            attributes: CookieAttributes {
                path: Some("/cache".into()),
                max_age: Some(90.0),
                ..Default::default()
            },
        },
    );
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, db))
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let request = |method, path: &str, body: Option<Value>, cookie: &str| {
        let url = url::Url::parse(&format!("https://auth.example.test/api/auth{path}")).unwrap();
        let mut request = AuthRequest::new(method, url.path()).with_url(url);
        if let Some(body) = body {
            request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.body = Some(serde_json::to_vec(&body).unwrap());
        }
        if !cookie.is_empty() {
            request.headers.insert("cookie".into(), cookie.into());
            request
                .headers
                .insert("origin".into(), "https://auth.example.test".into());
        }
        request
    };
    let signup=auth.handle_request(request(HttpMethod::Post,"/sign-up/email",Some(json!({"email":"cookies@example.test","password":"password123","name":"x".repeat(6000)})),"")).await?;
    let cookie = signup
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let session = auth
        .handle_request(request(HttpMethod::Get, "/get-session", None, &cookie))
        .await?;
    let data: Value = serde_json::from_slice(&session.body)?;
    let logout = auth
        .handle_request(request(
            HttpMethod::Post,
            "/sign-out",
            Some(json!({})),
            &cookie,
        ))
        .await?;
    Ok(
        json!({"signup":{"status":signup.status,"cookies":cookies(&signup)},"session":{"status":session.status,"email":data["user"]["email"]},"logout":{"status":logout.status,"cookies":cookies(&logout)}}),
    )
}
