use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::plugins::endpoint_context::EndpointContext;
use better_auth::plugins::last_login_method::{
    BeforeStoreLastLoginCookie, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver,
};
use better_auth::{AuthConfig, BetterAuth, SessionData};
use better_auth_core::request_runtime::ResolvedCookie;
use better_auth_core::store::StatelessSchema;
use better_auth_core::utils::cookie_utils::{create_chunked_cookies, create_clear_chunked_cookies};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    CookieAttributes, CookieOverride, HttpMethod, SameSite,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

const SECRET: &str = "ordinary-cookie-attribute-mutation-secret-at-least-32-characters";
type S = StatelessSchema;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capture {
    chunks: Vec<ChunkCase>,
    last_login: Vec<LastLoginCase>,
}

#[derive(Deserialize)]
struct Snapshot {
    name: String,
    attributes: Vec<(String, Value)>,
}

impl Snapshot {
    fn value(&self) -> Value {
        json!({ "name": self.name, "attributes": self.attributes.iter().cloned().collect::<serde_json::Map<_, _>>() })
    }
}

#[derive(Deserialize)]
struct ChunkCase {
    input: ChunkInput,
    before: Snapshot,
    headers: Vec<String>,
    after: Snapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChunkInput {
    secure: bool,
    partitioned: bool,
    action: String,
    incoming: Vec<(String, String)>,
    value_length: usize,
}

#[derive(Deserialize)]
struct LastLoginCase {
    input: LastLoginInput,
    before: Snapshot,
    response: CapturedResponse,
    events: Vec<Value>,
    after: Snapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LastLoginInput {
    session_name: String,
    last_login_name: String,
    secure: bool,
    partitioned: bool,
}

#[derive(Deserialize)]
struct CapturedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    cookies: Vec<String>,
    body: String,
}

fn capture() -> AuthResult<Capture> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/cookie-attribute-mutation-1.7.6.json"
    ))?)
}

fn config(secure: bool, partitioned: bool) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url("https://cookie-attributes.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.session.expires_in = Some(Duration::seconds(300));
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config.advanced.use_secure_cookies = Some(false);
    config.advanced.default_cookie_attributes = CookieAttributes {
        secure: Some(secure),
        same_site: Some(SameSite::Lax),
        path: Some("/ordinary".into()),
        http_only: Some(true),
        domain: Some(".cookie-attributes.test".into()),
        partitioned: Some(partitioned),
        ..Default::default()
    };
    config
}

fn snapshot(cookie: &ResolvedCookie) -> AuthResult<Value> {
    let attributes = &cookie.attributes;
    let max_age = attributes
        .max_age
        .map(better_auth_core::FieldValue::Number)
        .unwrap_or(better_auth_core::FieldValue::Null)
        .json()?;
    Ok(json!({ "name": cookie.name, "attributes": {
        "secure": attributes.secure,
        "sameSite": attributes.same_site.as_ref().map(|value| match value {
            SameSite::Lax => "lax", SameSite::Strict => "strict", SameSite::None => "none",
        }),
        "path": attributes.path, "httpOnly": attributes.http_only,
        "domain": attributes.domain, "partitioned": attributes.partitioned,
        "maxAge": max_age,
    } }))
}

fn session_snapshot(config: &AuthConfig) -> AuthResult<Value> {
    snapshot(&config.auth_cookie(
        "session_token",
        CookieAttributes {
            max_age: Some(config.session.expires_in().as_seconds_f64()),
            ..Default::default()
        },
    ))
}

#[test]
fn chunk_attribute_mutations_preserve_pinned_header_order_and_caller_attributes() -> AuthResult<()>
{
    let cases = capture()?.chunks;
    assert_eq!(cases.len(), 6);
    for case in cases {
        let config = config(case.input.secure, case.input.partitioned);
        let cookie = config.auth_cookie(
            "ordinary",
            CookieAttributes {
                max_age: Some(45.5),
                ..Default::default()
            },
        );
        assert_eq!(snapshot(&cookie)?, case.before.value());
        let mut request = AuthRequest::new(HttpMethod::Get, "/");
        if !case.input.incoming.is_empty() {
            let _ = request.headers.insert(
                "cookie".into(),
                case.input
                    .incoming
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let actual = match case.input.action.as_str() {
            "issue" | "replace" => {
                create_chunked_cookies(&request, &cookie, &"x".repeat(case.input.value_length))?
            }
            "clear" => create_clear_chunked_cookies(&request, &cookie)?,
            action => {
                return Err(AuthError::internal(format!(
                    "Unknown chunk action: {action}"
                )));
            }
        };
        assert_eq!(actual, case.headers, "{}", case.input.action);
        assert_eq!(snapshot(&cookie)?, case.after.value());
    }
    // Prepared JavaScript object identities stay in the fixture; this API exposes headers and borrowed attributes.
    Ok(())
}

#[derive(Default)]
struct Observer(Mutex<Vec<Value>>);

impl Observer {
    fn push(&self, value: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Cookie observer lock poisoned"))?
            .push(value);
        Ok(())
    }

    fn events(&self) -> AuthResult<Vec<Value>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| AuthError::internal("Cookie observer lock poisoned"))?
            .clone())
    }
}

fn callback_headers(context: &EndpointContext<'_, S>) -> AuthResult<Vec<String>> {
    Ok(context
        .response
        .ok_or_else(|| AuthError::internal("Missing LastLogin response"))?
        .headers
        .get_all("set-cookie")
        .cloned()
        .collect())
}

impl LastLoginMethodResolver<S> for Observer {
    fn resolve(&self, context: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        self.push(json!({ "kind": "resolve", "path": context.path,
            "session": session_snapshot(&context.auth.config)?, "headers": callback_headers(context)?,
        }))?;
        Ok(Some("email".into()))
    }
}

#[async_trait]
impl BeforeStoreLastLoginCookie<S> for Observer {
    async fn before_store_cookie(
        &self,
        context: &EndpointContext<'_, S>,
        method: &str,
    ) -> AuthResult<bool> {
        self.push(json!({ "kind": "before-store", "method": method,
            "session": session_snapshot(&context.auth.config)?, "headers": callback_headers(context)?,
        }))?;
        Ok(true)
    }
}

struct CookieEndpoint(Arc<Observer>);

#[async_trait]
impl AuthPlugin<S> for CookieEndpoint {
    fn name(&self) -> &'static str {
        "cookie-attribute-mutation"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/cookie-attributes", "cookie_attributes")]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.0.push(
            json!({ "kind": "endpoint-before", "session": session_snapshot(&context.config)? }),
        )?;
        request
            .append_response_header("Set-Cookie", "ordinary_prior=before; Path=/sentinel".into())?;
        let now = Utc::now();
        let data: SessionData = serde_json::from_value(json!({
            "user": { "id": "ordinary-user", "name": "Ordinary", "email": "ordinary@cookie-attributes.test",
                "emailVerified": true, "createdAt": now, "updatedAt": now },
            "session": { "id": "ordinary-session", "userId": "ordinary-user", "token": "ordinary-output-only",
                "expiresAt": now + Duration::seconds(300), "createdAt": now, "updatedAt": now },
        }))?;
        context
            .session_manager()
            .set_session_cookie(request, data, Some(false))
            .await?;
        self.0.push(
            json!({ "kind": "endpoint-after", "session": session_snapshot(&context.config)? }),
        )?;
        request
            .append_response_header("Set-Cookie", "ordinary_after=after; Path=/sentinel".into())?;
        Ok(Some(AuthResponse::json(
            200,
            &json!({ "newSession": request.new_session()?.is_some() }),
        )?))
    }
}

fn callback_events(events: Vec<Value>) -> AuthResult<Vec<Value>> {
    let mut callbacks = Vec::new();
    for mut event in events {
        let kind = event
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Missing captured cookie event kind"))?;
        if kind == "write" {
            continue;
        }
        let session = event
            .get_mut("session")
            .ok_or_else(|| AuthError::internal("Missing captured cookie event session"))?;
        *session = serde_json::from_value::<Snapshot>(session.clone())?.value();
        callbacks.push(event);
    }
    Ok(callbacks)
}

#[tokio::test]
async fn last_login_uses_original_session_attributes_and_preserves_prior_headers() -> AuthResult<()>
{
    let cases = capture()?.last_login;
    assert_eq!(cases.len(), 6);
    for case in cases {
        let mut config = config(case.input.secure, case.input.partitioned);
        let _ = config.advanced.cookies.get_or_insert_default().insert(
            "session_token".into(),
            CookieOverride {
                name: Some(case.input.session_name.clone()),
                attributes: CookieAttributes::default(),
            },
        );
        assert_eq!(session_snapshot(&config)?, case.before.value());
        let observer = Arc::new(Observer::default());
        let auth = BetterAuth::stateless(config)
            .plugin(CookieEndpoint(observer.clone()))
            .plugin(
                LastLoginMethodPlugin::new(LastLoginMethodConfig {
                    cookie_name: case.input.last_login_name,
                    max_age: 90.5,
                    ..Default::default()
                })
                .custom_resolve_method(observer.clone())
                .before_store_cookie(observer.clone()),
            )
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await?;
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/cookie-attributes",
            ))
            .await?;
        assert_eq!(response.status, case.response.status);
        assert_eq!(
            response.body.bytes()?.as_ref(),
            case.response.body.as_bytes()
        );
        let mut headers = response
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect::<Vec<_>>();
        // WHATWG Headers sorts names but retains the order of repeated Set-Cookie values.
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            headers, case.response.headers,
            "{}",
            case.input.session_name
        );
        assert_eq!(
            response
                .headers
                .get_all("set-cookie")
                .cloned()
                .collect::<Vec<_>>(),
            case.response.cookies
        );
        assert_eq!(observer.events()?, callback_events(case.events)?);
        assert_eq!(
            session_snapshot(&auth.context().config)?,
            case.after.value()
        );
    }
    // Writer interception identity, property order, and statusText remain JavaScript observations.
    // Session snapshots resolve the same explicit lifetime used by the Rust session writer.
    Ok(())
}
