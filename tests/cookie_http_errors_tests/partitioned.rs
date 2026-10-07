use super::*;
use better_auth_core::utils::cookie_utils::create_clear_chunked_cookies;

fn full_shape(header: &str) -> Value {
    let mut parts = header.split("; ");
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    let mut attributes: Vec<_> = parts.collect();
    attributes.sort_unstable();
    json!({ "name": name, "valueLength": value.len(), "attributes": attributes })
}

fn shapes<'a>(headers: impl IntoIterator<Item = &'a String>) -> Vec<Value> {
    let mut values: Vec<_> = headers
        .into_iter()
        .map(|header| full_shape(header))
        .collect();
    values.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    values
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result propagates setup and transport failures; assertions retain complete fixture diagnostics."
)]
async fn partitioned_attributes_follow_resolution_through_all_cookie_writers() -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/cookie-partitioned-1.7.6.json"))?;
    for (name, expected) in fixture.as_object().unwrap() {
        let input = &expected["input"];
        let mut config = config();
        config.advanced.default_cookie_attributes = CookieAttributes {
            secure: Some(true),
            partitioned: input["global"].as_bool(),
            path: Some("/ordinary".into()),
            domain: Some(".cookie-errors.test".into()),
            ..Default::default()
        };
        for logical in ["ordinary", "session_token"] {
            let _ = config.advanced.cookies.get_or_insert_default().insert(
                logical.into(),
                CookieOverride {
                    name: None,
                    attributes: CookieAttributes {
                        partitioned: input["named"].as_bool(),
                        ..Default::default()
                    },
                },
            );
        }
        let resolved = config.auth_cookie(
            "ordinary",
            CookieAttributes {
                max_age: Some(45.5),
                partitioned: input["caller"].as_bool(),
                ..Default::default()
            },
        );
        let empty_request = AuthRequest::new(HttpMethod::Get, "/");
        let resolved_headers = create_chunked_cookies(&empty_request, &resolved, "display")?;
        let plain = create_session_like_cookie(&resolved.name, "display", Some(45.5), &config)?;
        let mut request = AuthRequest::new(HttpMethod::Get, "/");
        let _ = request.headers.insert(
            "cookie".into(),
            format!("{}=display; {}.5=display", resolved.name, resolved.name),
        );
        let chunks = create_chunked_cookies(&request, &resolved, &"x".repeat(8000))?;
        let clear_chunks = create_clear_chunked_cookies(&request, &resolved)?;
        let cleared = vec![create_clear_cookie(&resolved.name, &config)?];
        let observer = Arc::new(Observer::default());
        let plugin = LastLoginMethodPlugin::new(LastLoginMethodConfig {
            max_age: 90.5,
            ..Default::default()
        })
        .custom_resolve_method(observer.clone())
        .before_store_cookie(observer.clone());
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint {
                dont_remember: Some(false),
            })
            .plugin(plugin)
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await?;
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-contract",
            ))
            .await?;
        let result = json!({
            "input": input,
            "resolved": full_shape(&resolved_headers[0]),
            "plain": full_shape(&plain),
            "chunks": shapes(&chunks),
            "clearChunks": shapes(&clear_chunks),
            "clear": shapes(&cleared),
            "session": {
                "status": response.status,
                "body": serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                "events": *observer.0.lock().unwrap(),
                "headers": shapes(response.headers.get_all("set-cookie")),
            },
        });
        assert_eq!(result, *expected, "{name}");
    }
    Ok(())
}
