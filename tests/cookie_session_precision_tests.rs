#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Contract tests compare captured ordinary session cookie lifetime results"
)]

use async_trait::async_trait;
use better_auth::SessionData;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::store::StatelessSchema;
use better_auth_core::utils::cookie_utils::{
    create_cookie, create_session_cookie, create_session_cookie_with_max_age,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    CookieCacheConfig, HttpMethod,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

const SECRET: &str = "ordinary-cookie-precision-fixture-secret-more-than-32-characters";
type S = StatelessSchema;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/cookie-session-precision-1.7.6.json")).unwrap()
}

fn config(seconds: f64) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url("https://cookie-precision.test");
    config.logger.disabled = Some(true);
    config.advanced.use_secure_cookies = Some(false);
    config.session.expires_in = Some(Duration::milliseconds((seconds * 1000.0) as i64));
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
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

fn captured_headers(expected: &Value) -> Value {
    json!(
        expected["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|header| {
                let max_age = header["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find_map(|attribute| attribute.as_str().unwrap().strip_prefix("Max-Age="));
                json!({ "name": header["name"], "maxAge": max_age })
            })
            .collect::<Vec<_>>()
    )
}

struct CookieEndpoint {
    dont_remember: bool,
}

#[async_trait]
impl AuthPlugin<S> for CookieEndpoint {
    fn name(&self) -> &'static str {
        "ordinary-cookie-precision"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/cookie-precision", "cookie_precision")]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let now = Utc::now();
        let data: SessionData = serde_json::from_value(json!({
            "user": { "id": "ordinary-user", "name": "Ordinary", "email": "ordinary@cookie-precision.test", "emailVerified": true, "createdAt": now, "updatedAt": now },
            "session": { "id": "ordinary-session", "userId": "ordinary-user", "token": "ordinary-output-only", "expiresAt": now + Duration::seconds(300), "createdAt": now, "updatedAt": now },
        }))?;
        let error = context
            .session_manager()
            .set_session_cookie(request, data, Some(self.dont_remember))
            .await
            .err()
            .map(error_message);
        Ok(Some(AuthResponse::json(
            200,
            &json!({
                "error": error,
                "resolvedExpiresIn": context.config.session.expires_in().as_seconds_f64(),
                "newSession": request.new_session()?.is_some(),
            }),
        )?))
    }
}

#[tokio::test]
async fn dispatcher_preserves_fractional_session_lifetime_until_cookie_validation() {
    let fixtures = fixture();
    for (name, expected) in fixtures.as_object().unwrap() {
        let seconds = expected["input"]["expiresIn"].as_f64().unwrap();
        let auth = BetterAuth::stateless(config(seconds))
            .plugin(CookieEndpoint {
                dont_remember: expected["input"]["dontRemember"].as_bool().unwrap(),
            })
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-precision",
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
        assert_eq!(json!(response.status), expected["status"], "{name}/status");
        assert_eq!(body["error"], expected["body"]["error"], "{name}/error");
        assert_eq!(
            body["newSession"], expected["body"]["newSession"],
            "{name}/newSession"
        );
        assert_eq!(
            body["resolvedExpiresIn"].as_f64(),
            expected["body"]["resolvedExpiresIn"].as_f64(),
            "{name}/resolvedExpiresIn"
        );
        let headers = response
            .headers
            .get_all("set-cookie")
            .map(|header| shape(header))
            .collect::<Vec<_>>();
        assert_eq!(json!(headers), captured_headers(expected), "{name}/headers");
    }
}

#[test]
fn direct_cookie_helpers_keep_explicit_and_configured_fractional_ages() {
    let fixtures = fixture();
    let beyond = &fixtures["beyondFraction-remember"];
    let seconds = beyond["input"]["expiresIn"].as_f64().unwrap();
    let config = config(seconds);
    for result in [
        create_session_cookie("ordinary-output-only", &config),
        create_session_cookie_with_max_age(Some("ordinary-output-only"), Some(seconds), &config),
        create_cookie("ordinary", "display", seconds, &config),
    ] {
        assert_eq!(
            json!(error_message(result.unwrap_err())),
            beyond["body"]["error"]
        );
    }
    let ordinary = &fixtures["ordinaryFraction-remember"];
    let header = create_session_cookie_with_max_age(
        Some("ordinary-output-only"),
        ordinary["input"]["expiresIn"].as_f64(),
        &config,
    )
    .unwrap();
    assert_eq!(json!([shape(&header)]), captured_headers(ordinary));
}
