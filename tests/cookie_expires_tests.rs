#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Compare the captured ordinary Cookie contract and report exact fixture failures"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::SessionData;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::api_error::{ApiErrorHandler, ApiErrorTask};
use better_auth_core::observability::{LogArgument, LogLevel, LogSink};
use better_auth_core::store::StatelessSchema;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, remove_set_cookie_entries, render_cookie,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    CookieAttributes, CookieOverride, HttpMethod,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

type S = StatelessSchema;
const SECRET: &str = "ordinary-cookie-expires-evidence-secret-more-than-32-characters";

#[path = "cookie_expires_tests/chunks.rs"]
mod chunks;
#[path = "cookie_expires_tests/http.rs"]
mod http;
#[path = "cookie_expires_tests/projection.rs"]
mod projection;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/cookie-expires-1.7.6.json")).unwrap()
}

fn anchor() -> i64 {
    Utc::now().timestamp() * 1000
}

fn date(value: &Value, source_anchor: i64, now_anchor: i64) -> Option<DateTime<Utc>> {
    value.as_str().map(|text| {
        let recorded: DateTime<Utc> = text.parse().unwrap();
        DateTime::from_timestamp_millis(recorded.timestamp_millis() - source_anchor + now_anchor)
            .unwrap()
    })
}

fn normalize(value: &Value, anchor: i64) -> Value {
    match value {
        Value::String(text) => {
            if let Some(date) = text.strip_prefix("Expires=") {
                let date = DateTime::parse_from_rfc2822(date).unwrap();
                return json!(format!(
                    "ExpiresOffset={}",
                    date.timestamp_millis() - anchor
                ));
            }
            match text.parse::<DateTime<Utc>>() {
                Ok(date) => json!({ "millisecondsFromAnchor": date.timestamp_millis() - anchor }),
                Err(_) => value.clone(),
            }
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| normalize(item, anchor)).collect())
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let mut result = normalize(value, anchor);
                    if key == "attributes" {
                        if let Value::Array(attributes) = &mut result {
                            attributes.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                        }
                    }
                    (key.clone(), result)
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn shape(header: &str) -> Value {
    let mut parts = header.split("; ");
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    json!({ "name": name, "valueLength": value.len(), "attributes": parts.collect::<Vec<_>>(), "serializedLength": header.len() })
}

fn error_shape(error: &AuthError) -> Value {
    match error {
        AuthError::Internal(message) => json!({ "name": "Error", "message": message }),
        error => panic!("expected ordinary serializer error: {error}"),
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url("https://cookie-expires.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.use_secure_cookies = Some(false);
    config.session.expires_in = Some(Duration::seconds(300));
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
}

fn override_date(config: &mut AuthConfig, name: &str, expires: Option<DateTime<Utc>>) {
    let _ = config.advanced.cookies.get_or_insert_default().insert(
        name.into(),
        CookieOverride {
            name: None,
            attributes: CookieAttributes {
                expires,
                ..Default::default()
            },
        },
    );
}

#[test]
fn expiration_precedence_and_complete_writer_attributes_match_capture() {
    let fixture = fixture();
    let source_anchor = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    let now = anchor();
    for (name, expected) in fixture["resolution"].as_object().unwrap() {
        let input = &expected["input"];
        let mut config = config();
        config.advanced.default_cookie_attributes.expires =
            date(&input["global"], source_anchor, now);
        override_date(
            &mut config,
            "ordinary",
            date(&input["named"], source_anchor, now),
        );
        let resolved = config.auth_cookie(
            "ordinary",
            CookieAttributes {
                max_age: Some(45.5),
                expires: date(&input["caller"], source_anchor, now),
                ..Default::default()
            },
        );
        assert_eq!(
            json!(resolved.attributes.expires.is_some()),
            expected["resolved"]["expiresOwn"],
            "{name}"
        );
        let expected_date = date(
            &expected["resolved"]["attributes"]["expires"],
            source_anchor,
            now,
        );
        assert_eq!(resolved.attributes.expires, expected_date, "{name}");
        let actual = render_cookie("display", &resolved).unwrap();
        assert_eq!(
            normalize(&shape(&actual), now),
            normalize(&expected["writer"]["value"], source_anchor),
            "{name}"
        );
    }
}

#[derive(Default)]
struct Observer {
    hook: String,
    events: Mutex<Vec<Value>>,
}

impl Observer {
    fn push(&self, event: Value) {
        self.events.lock().unwrap().push(event);
    }
}

impl LogSink for Observer {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Error(error) => {
                    json!({ "name": "Error", "message": error.to_string() })
                }
                LogArgument::Text(text) => json!(text),
                LogArgument::Value(value) => (*value).clone(),
            })
            .collect();
        self.push(json!({ "kind": "log", "level": level.as_str(), "message": message.to_string(), "args": arguments }));
    }
}

impl ApiErrorHandler<S> for Observer {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        let mut event = error_shape(error);
        event["kind"] = json!("api-error");
        self.push(event);
        Ok(None)
    }
}

struct CookieEndpoint {
    input: Option<Value>,
    observer: Arc<Observer>,
}

#[async_trait]
impl AuthPlugin<S> for CookieEndpoint {
    fn name(&self) -> &'static str {
        "ordinary-cookie-expires"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/cookie-expires", "cookie_expires")]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let Some(input) = &self.input else {
            request.append_response_header(
                "Set-Cookie",
                "better-auth.session_token=ordinary-output-only; Path=/; HttpOnly; SameSite=Lax"
                    .into(),
            )?;
            self.observer.push(json!({ "kind": "endpoint-write" }));
            return Ok(Some(AuthResponse::json(200, &json!({ "ok": true }))?));
        };
        request.append_response_header("Set-Cookie", "ordinary-prior=display; Path=/".into())?;
        self.observer.push(json!("prior"));
        let result = if input["deleteSession"].as_bool() == Some(true) {
            better_auth_api::plugins::helpers::delete_session_cookies(
                request,
                &context.config,
                false,
                None,
            )
        } else if input["clear"].as_bool() == Some(true) {
            (|| {
                let cookie = context.config.auth_cookie("ordinary", Default::default());
                remove_set_cookie_entries(request, None, &cookie.name)?;
                request.append_response_header(
                    "Set-Cookie",
                    create_clear_cookie(&cookie.name, &context.config)?,
                )
            })()
        } else {
            let now = Utc::now();
            let data: SessionData = serde_json::from_value(json!({
                "user": { "id": "ordinary-user", "name": "Ordinary", "email": "ordinary@cookie-expires.test", "emailVerified": true, "createdAt": now, "updatedAt": now },
                "session": { "id": "ordinary-session", "userId": "ordinary-user", "token": "ordinary-output-only", "expiresAt": now + Duration::seconds(300), "createdAt": now, "updatedAt": now },
            }))?;
            context
                .session_manager()
                .set_session_cookie(request, data, input["dontRemember"].as_bool())
                .await
        };
        let error = result.as_ref().err().map(error_shape);
        self.observer.push(json!(if result.is_ok() {
            "writer:complete"
        } else {
            "writer:error"
        }));
        Ok(Some(AuthResponse::json(
            200,
            &json!({ "error": error, "newSession": request.new_session()?.is_some() }),
        )?))
    }
}
