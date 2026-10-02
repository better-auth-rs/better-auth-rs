use super::*;
use better_auth::plugins::endpoint_context::EndpointContext;
use better_auth::plugins::last_login_method::{
    BeforeStoreLastLoginCookie, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver,
};

fn response_shape(response: &AuthResponse) -> Value {
    json!({
        "status": response.status,
        "body": String::from_utf8(response.body.clone()).unwrap(),
        "headers": response.headers.get_all("set-cookie").map(|value| shape(value)).collect::<Vec<_>>(),
    })
}

fn sort_headers(value: &mut Value) {
    value["headers"]
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
}

fn semantic_response(value: &Value, anchor: i64) -> Value {
    let mut value = normalize(value, anchor);
    if let Some(text) = value["body"].as_str() {
        if let Ok(body) = serde_json::from_str::<Value>(text) {
            value["body"] = body;
        }
    }
    value
}

#[tokio::test]
async fn explicit_expiration_issuance_and_clear_failures_preserve_prior_headers() {
    let fixture = fixture();
    let source_anchor = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    for (name, expected) in fixture["session"].as_object().unwrap() {
        let now = anchor();
        let input = &expected["input"];
        let mut config = config();
        config.advanced.default_cookie_attributes.expires =
            date(&input["global"], source_anchor, now);
        for (logical, field) in [
            ("session_token", "token"),
            ("dont_remember", "marker"),
            ("session_data", "sessionData"),
        ] {
            override_date(
                &mut config,
                logical,
                date(&input[field], source_anchor, now),
            );
        }
        let observer = Arc::new(Observer::default());
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint {
                input: Some(input.clone()),
                observer: observer.clone(),
            })
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-expires",
            ))
            .await
            .unwrap();
        let mut actual = response_shape(&response);
        let mut expected_response = expected["response"].clone();
        if name == "deleteFuture" {
            // Aggregate cleanup order is a documented pre-existing difference; retain every entry.
            sort_headers(&mut actual);
            sort_headers(&mut expected_response);
        }
        assert_eq!(
            semantic_response(&actual, now),
            semantic_response(&expected_response, source_anchor),
            "{name}"
        );
        assert_eq!(
            json!(*observer.events.lock().unwrap()),
            expected["events"],
            "{name}/events"
        );
    }
}

impl LastLoginMethodResolver<S> for Observer {
    fn resolve(&self, _: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        Ok(Some("email".into()))
    }
}

#[async_trait]
impl BeforeStoreLastLoginCookie<S> for Observer {
    async fn before_store_cookie(&self, _: &EndpointContext<'_, S>, _: &str) -> AuthResult<bool> {
        self.push(json!({ "kind": "before", "hook": self.hook }));
        if self.hook == "error" {
            return Err(AuthError::BadRequest(
                "Ordinary expires beforeStoreCookie error".into(),
            ));
        }
        Ok(self.hook != "veto")
    }
}

#[tokio::test]
async fn last_login_veto_precedes_expiration_validation_and_preserves_error_policy() {
    let fixture = fixture();
    let source_anchor = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    for (name, expected) in fixture["lastLogin"].as_object().unwrap() {
        let now = anchor();
        let input = &expected["input"];
        let mut config = config();
        config.advanced.default_cookie_attributes.expires =
            date(&input["expires"], source_anchor, now);
        let observer = Arc::new(Observer {
            hook: input["hook"].as_str().unwrap().into(),
            ..Default::default()
        });
        config.logger.disabled = Some(false);
        config.logger.level = Some(LogLevel::Error);
        config.logger.log = Some(observer.clone());
        let plugin = LastLoginMethodPlugin::new(LastLoginMethodConfig {
            max_age: 90.5,
            ..Default::default()
        })
        .custom_resolve_method(observer.clone())
        .before_store_cookie(observer.clone());
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint {
                input: None,
                observer: observer.clone(),
            })
            .plugin(plugin)
            .on_api_error(observer.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-expires",
            ))
            .await
            .unwrap();
        assert_eq!(
            semantic_response(&response_shape(&response), now),
            semantic_response(&expected["response"], source_anchor),
            "{name}"
        );
        assert_eq!(
            json!(*observer.events.lock().unwrap()),
            expected["events"],
            "{name}/events"
        );
    }
}
