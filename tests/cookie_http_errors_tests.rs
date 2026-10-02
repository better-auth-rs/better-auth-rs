#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Contract tests compare captured ordinary cookie configuration results"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::plugins::endpoint_context::EndpointContext;
use better_auth::plugins::last_login_method::{
    BeforeStoreLastLoginCookie, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver,
};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::api_error::{ApiErrorHandler, ApiErrorTask};
use better_auth_core::session::SessionData;
use better_auth_core::store::StatelessSchema;
use better_auth_core::utils::cookie_utils::{
    create_chunked_cookies, create_clear_cookie, create_cookie, create_session_like_cookie,
    sign_cookie_value,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    CookieAttributes, CookieOverride, HttpMethod,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

const SECRET: &str = "ordinary-cookie-serialization-fixture-secret-32-characters";
type S = StatelessSchema;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/cookie-http-errors-1.7.6.json")).unwrap()
}

fn age(name: &str) -> Option<f64> {
    match name {
        "omitted" => None,
        "zero" => Some(0.0),
        "negativeZero" => Some(-0.0),
        "fractional" => Some(0.75),
        "negative" => Some(-1.0),
        "boundary" => Some(34_560_000.0),
        "beyondFraction" => Some(34_560_000.25),
        "beyond" => Some(34_560_001.0),
        "nan" => Some(f64::NAN),
        "positiveInfinity" => Some(f64::INFINITY),
        "negativeInfinity" => Some(f64::NEG_INFINITY),
        _ => panic!("unknown captured age case: {name}"),
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url("https://cookie-errors.test");
    config.logger.disabled = Some(true);
    config.advanced.use_secure_cookies = Some(false);
    config.session.expires_in = Some(Duration::seconds(300));
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
}

fn override_age(config: &mut AuthConfig, name: &str, age: Option<f64>) {
    let _ = config.advanced.cookies.get_or_insert_default().insert(
        name.into(),
        CookieOverride {
            name: None,
            attributes: CookieAttributes {
                max_age: age,
                ..Default::default()
            },
        },
    );
}

fn error_message(error: AuthError) -> String {
    match error {
        AuthError::Internal(message) => message,
        error => panic!("expected ordinary serialization error, got {error:?}"),
    }
}

fn shape(header: &str) -> Value {
    let mut parts = header.split("; ");
    let name = parts.next().unwrap().split_once('=').unwrap().0;
    let max_age = parts.find_map(|part| part.strip_prefix("Max-Age="));
    json!({ "name": name, "maxAge": max_age })
}

#[test]
fn cookie_configuration_errors_and_chunk_overhead_match_pinned_writer() {
    let fixtures = fixture();
    for (name, expected) in fixtures["serializers"].as_object().unwrap() {
        let mut config = config();
        override_age(&mut config, "ordinary", age(name));
        let cookie_name = "better-auth.ordinary";
        for mode in ["plain", "signed"] {
            let value = if mode == "signed" {
                sign_cookie_value("display", SECRET)
            } else {
                "display".into()
            };
            let actual = create_session_like_cookie(cookie_name, &value, None, &config);
            match actual {
                Ok(header) => {
                    let mut actual = shape(&header);
                    actual["name"] = json!("ordinary");
                    assert_eq!(actual, expected[mode]["shape"], "{name}/{mode}");
                    assert_eq!(
                        header
                            .split(';')
                            .next()
                            .unwrap()
                            .strip_prefix("better-auth."),
                        expected[mode]["raw"].as_str().unwrap().split(';').next(),
                        "{name}/{mode} value"
                    );
                }
                Err(error) => assert_eq!(
                    json!(error_message(error)),
                    expected[mode]["error"],
                    "{name}/{mode}"
                ),
            }
        }
        let resolved = config.auth_cookie("ordinary", Default::default());
        let chunk = create_chunked_cookies(
            &AuthRequest::new(HttpMethod::Get, "/"),
            &resolved,
            "display",
        );
        let expected = &fixtures["chunks"][name];
        match chunk {
            Ok(headers) => {
                let actual: Vec<_> = headers
                    .iter()
                    .map(|header| {
                        let mut value = shape(header);
                        value["name"] = json!("ordinary");
                        value
                    })
                    .collect();
                assert_eq!(json!(actual), expected["headers"], "{name}/chunks");
            }
            Err(error) => assert_eq!(
                json!(error_message(error)),
                expected["error"],
                "{name}/chunks"
            ),
        }
        // Expiration replaces the configured age with zero before serialization.
        assert_eq!(
            shape(&create_clear_cookie(cookie_name, &config).unwrap())["maxAge"],
            "0",
            "{name}/clear"
        );
    }
    let config = config();
    assert_eq!(
        error_message(create_cookie("ordinary", "display", 34_560_001.0, &config).unwrap_err()),
        fixtures["serializers"]["beyond"]["plain"]["error"]
            .as_str()
            .unwrap(),
    );
}

struct CookieEndpoint {
    dont_remember: Option<bool>,
}

#[async_trait]
impl AuthPlugin<S> for CookieEndpoint {
    fn name(&self) -> &'static str {
        "ordinary-cookie-contract"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/cookie-contract", "cookie_contract")]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if let Some(dont_remember) = self.dont_remember {
            let now = Utc::now();
            let data: SessionData = serde_json::from_value(json!({
                "user": { "id": "ordinary-user", "name": "Ordinary", "email": "ordinary@cookie-errors.test", "emailVerified": true, "createdAt": now, "updatedAt": now },
                "session": { "id": "ordinary-session", "userId": "ordinary-user", "token": "ordinary-output-only", "expiresAt": now + Duration::seconds(300), "createdAt": now, "updatedAt": now },
            }))?;
            let error = context
                .session_manager()
                .set_session_cookie(request, data, Some(dont_remember))
                .await
                .err()
                .map(error_message);
            Ok(Some(AuthResponse::json(
                200,
                &json!({ "error": error, "newSession": request.new_session()?.is_some() }),
            )?))
        } else {
            request.append_response_header(
                "Set-Cookie",
                "better-auth.session_token=ordinary-output-only; Path=/; HttpOnly; SameSite=Lax"
                    .into(),
            )?;
            Ok(Some(AuthResponse::json(200, &json!({ "ok": true }))?))
        }
    }
}

#[tokio::test]
async fn session_cookie_failure_retains_prior_header_and_does_not_publish_new_session() {
    let fixtures = fixture();
    for (name, expected) in fixtures["session"].as_object().unwrap() {
        let mut config = config();
        if matches!(name.as_str(), "overriddenTokenAge" | "omittedTokenAge") {
            override_age(&mut config, "session_token", Some(f64::INFINITY));
        }
        if name == "markerError" {
            override_age(&mut config, "dont_remember", Some(34_560_000.25));
        }
        let dont_remember = !matches!(name.as_str(), "remember" | "overriddenTokenAge");
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint {
                dont_remember: Some(dont_remember),
            })
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-contract",
            ))
            .await
            .unwrap();
        let actual = json!({ "status": response.status, "body": serde_json::from_slice::<Value>(&response.body).unwrap(), "headers": response.headers.get_all("set-cookie").map(|header| shape(header)).collect::<Vec<_>>() });
        assert_eq!(actual, *expected, "{name}");
    }
}

#[derive(Default)]
struct Observer(Mutex<Vec<String>>);

impl LastLoginMethodResolver<S> for Observer {
    fn resolve(&self, _: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        Ok(Some("email".into()))
    }
}

#[async_trait]
impl BeforeStoreLastLoginCookie<S> for Observer {
    async fn before_store_cookie(&self, _: &EndpointContext<'_, S>, _: &str) -> AuthResult<bool> {
        self.0.lock().unwrap().push("before".into());
        Ok(true)
    }
}

impl ApiErrorHandler<S> for Observer {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        let AuthError::Internal(message) = error else {
            panic!("expected ordinary cookie error")
        };
        self.0.lock().unwrap().push(message.clone());
        Ok(None)
    }
}

#[tokio::test]
async fn last_login_overrides_inherited_age_and_keeps_existing_http_error_policy() {
    let fixtures = fixture();
    for (name, expected) in fixtures["lastLogin"].as_object().unwrap() {
        let mut config = config();
        override_age(&mut config, "session_token", Some(120.0));
        let observer = Arc::new(Observer::default());
        let plugin = LastLoginMethodPlugin::new(LastLoginMethodConfig {
            max_age: age(name).unwrap(),
            ..Default::default()
        })
        .custom_resolve_method(observer.clone())
        .before_store_cookie(observer.clone());
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint {
                dont_remember: None,
            })
            .plugin(plugin)
            .on_api_error(observer.clone())
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-contract",
            ))
            .await
            .unwrap();
        let actual = json!({ "status": response.status, "body": String::from_utf8(response.body).unwrap(), "events": *observer.0.lock().unwrap(), "headers": response.headers.get_all("set-cookie").map(|header| shape(header)).collect::<Vec<_>>() });
        assert_eq!(actual, *expected, "{name}");
    }
}

#[path = "cookie_http_errors_tests/partitioned.rs"]
mod partitioned;
