//! Real native dispatch paired with the complete Better Auth 1.7.6 Session capture.
//! Native status provenance, effective HTTP status, headers, storage, and hook events remain distinct observations.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Pinned contract setup and complete observations must fail immediately on a mismatch"
)]

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    BeforeRequestAction, CreateSession, FieldDate, FieldMap, FieldValue, FromFieldMap, Headers,
    HttpMethod,
    config::{CookieCacheConfig, CookieCacheRefresh, CookieCacheStrategy},
    endpoint_dispatch::EndpointDispatcher,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    session::NativeSessionData,
    store::{
        EphemeralStore, StatelessSchema, StoreCapabilities,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
        schema::EntityRole,
    },
    utils::cookie_utils::{sign_cookie_value, verify_cookie_value},
    wire::SessionView,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use super::SessionManagementPlugin;
use crate::plugins::test_helpers::initialize_test_context;

const NOW: i64 = 2_000_000_000_000;
const ORIGIN: &str = "http://session-management-native.test";
const SECRET: &str = "session-management-native-contract-secret-at-least-32-characters";

fn object<const N: usize>(entries: [(&str, FieldValue); N]) -> FieldValue {
    entries
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect::<FieldMap>()
        .into()
}

fn iso(milliseconds: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(milliseconds)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn revive(value: &Value, shift: i64) -> AuthResult<FieldValue> {
    Ok(match value {
        Value::Object(fields) if fields.get("type") == Some(&json!("undefined")) => {
            FieldValue::Undefined
        }
        Value::Object(fields) if fields.get("type") == Some(&json!("date")) => {
            let date = fields["value"]
                .as_str()
                .unwrap()
                .parse::<DateTime<Utc>>()
                .unwrap();
            FieldDate::from_milliseconds((date.timestamp_millis() + shift) as f64).into()
        }
        Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| Ok((key.clone(), revive(value, shift)?)))
            .collect::<AuthResult<FieldMap>>()?
            .into(),
        Value::Array(values) => values
            .iter()
            .map(|value| revive(value, shift))
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        value => FieldValue::from_json(value.clone())?,
    })
}

fn observe(value: &FieldValue, shift: i64) -> AuthResult<Value> {
    Ok(match value {
        FieldValue::Undefined => json!({"type":"undefined"}),
        FieldValue::Date(date) => {
            json!({"type":"date", "value":iso(date.milliseconds() as i64 - shift)})
        }
        FieldValue::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| observe(value, shift))
                .collect::<AuthResult<_>>()?,
        ),
        FieldValue::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| Ok((key.clone(), observe(value, shift)?)))
                .collect::<AuthResult<_>>()?,
        ),
        FieldValue::String(value) => value.parse::<DateTime<Utc>>().map_or_else(
            |_| json!(value),
            |date| json!(iso(date.timestamp_millis() - shift)),
        ),
        value => value
            .json()?
            .ok_or_else(|| AuthError::internal("Unexpected unobservable Session value"))?,
    })
}

fn snapshot(value: Option<&NativeSessionData>) -> FieldValue {
    value.map_or(FieldValue::Null, |value| {
        FieldMap::from(value.clone()).into()
    })
}

fn returned(response: &AuthResponse) -> AuthResult<FieldValue> {
    let value = response.body.field_value()?;
    Ok(if response.is_api_error() {
        let message = value
            .as_object()
            .and_then(|fields| fields.get("message"))
            .and_then(FieldValue::as_str)
            .unwrap_or("");
        object([
            ("kind", "api-error".into()),
            ("name", "APIError".into()),
            ("message", message.into()),
            (
                "status",
                f64::from(response.api_error_status().unwrap()).into(),
            ),
            ("body", value),
        ])
    } else {
        object([("kind", "value".into()), ("value", value)])
    })
}

#[derive(Default)]
struct Hooks {
    recording: AtomicBool,
    seed: Mutex<Option<FieldMap>>,
    injected: Mutex<Option<NativeSessionData>>,
    events: Mutex<Vec<FieldValue>>,
    stateless: bool,
}

impl Hooks {
    fn record(&self, value: FieldValue) {
        if self.recording.load(Ordering::SeqCst) {
            self.events.lock().unwrap().push(value);
        }
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if !self.recording.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let injected = self.injected.lock().unwrap().clone();
        self.record(object([
            ("phase", "before".into()),
            ("path", request.path().into()),
            ("session", snapshot(injected.as_ref())),
        ]));
        Ok(
            injected.map(|session| BeforeRequestAction::InjectNativeSession {
                session: Box::new(session),
            }),
        )
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        if !self.recording.load(Ordering::SeqCst) {
            return Ok(());
        }
        let selected = request.native_session_snapshot()?;
        if self.stateless
            && let Some(injected) = self.injected.lock().unwrap().as_ref()
        {
            let actual = selected.as_ref().unwrap();
            assert!(
                actual.user.strict_equals(&injected.user),
                "Native User identity must survive dispatch"
            );
            assert!(
                actual
                    .session
                    .created_at
                    .field_value()
                    .strict_equals(&injected.session.created_at.field_value())
            );
        }
        self.record(object([
            ("phase", "after".into()),
            ("path", request.path().into()),
            ("session", snapshot(selected.as_ref())),
            ("returned", returned(response)?),
        ]));
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_session(
        &self,
        _: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        assert!(
            !self.recording.load(Ordering::SeqCst),
            "Session management must not create a Session"
        );
        Ok(DatabaseHookUpdate::Patch(
            self.seed.lock().unwrap().take().unwrap(),
        ))
    }
    async fn before_delete_session(
        &self,
        data: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record(object([
            ("phase", "delete.before".into()),
            ("data", FieldMap::from(data.clone()).into()),
        ]));
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        data: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record(object([
            ("phase", "delete.after".into()),
            ("data", FieldMap::from(data.clone()).into()),
        ]));
        Ok(())
    }
}

struct Clock {
    shift: i64,
    start: i64,
    end: i64,
}

impl Clock {
    fn cache(&self, encoded: &str, actual: bool) -> AuthResult<Value> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let value = FieldValue::parse_json(std::str::from_utf8(&bytes).unwrap())?;
        let fields = value.as_object().unwrap();
        let payload = fields.get("session").unwrap().as_object().unwrap();
        let expires = fields.get("expiresAt").unwrap().as_f64().unwrap() as i64;
        let signature = URL_SAFE_NO_PAD
            .decode(fields.get("signature").unwrap().as_str().unwrap())
            .unwrap();
        let mut signed = payload.clone();
        let _ = signed.insert("expiresAt".into(), (expires as f64).into());
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(FieldValue::from(signed).stringify()?.unwrap().as_bytes());
        mac.verify_slice(&signature).unwrap();
        let updated = payload.get("updatedAt").unwrap().as_f64().unwrap() as i64;
        if actual {
            assert!(
                (self.start..=self.end).contains(&updated),
                "Cache issuance must occur during the request"
            );
            assert!(
                (self.start + 300_000..=self.end + 300_000).contains(&expires),
                "Cache expiry must preserve its 300-second lifetime"
            );
        } else {
            assert_eq!(updated, NOW);
            assert_eq!(expires, NOW + 300_000);
        }
        let mut normalized = observe(&value, if actual { self.shift } else { 0 })?;
        normalized["session"]["updatedAt"] = json!(NOW);
        normalized["expiresAt"] = json!(NOW + 300_000);
        normalized["signature"] = json!("<verified-hmac-sha256>");
        Ok(normalized)
    }

    fn cookie(&self, value: &str, actual: bool) -> AuthResult<Value> {
        let mut pieces = value.split(';').map(str::trim);
        let (name, value) = pieces.next().unwrap().split_once('=').unwrap();
        let mut attributes = BTreeMap::new();
        for part in pieces {
            let (name, value) = part
                .split_once('=')
                .map_or((part, None), |(name, value)| (name, Some(value)));
            let name = name.to_ascii_lowercase();
            let value = value.map(|value| {
                if name == "samesite" {
                    value.to_ascii_lowercase()
                } else {
                    value.into()
                }
            });
            assert!(
                attributes.insert(name, value).is_none(),
                "Cookie attributes must not repeat"
            );
        }
        let payload = if value.is_empty() {
            json!("")
        } else if name == "better-auth.session_data" {
            self.cache(value, actual)?
        } else if name == "better-auth.session_token" {
            let token = verify_cookie_value(value, SECRET).unwrap();
            assert_eq!(token, "7");
            json!({"signedToken":token})
        } else {
            json!(value)
        };
        Ok(json!({"name":name, "value":payload, "attributes":attributes}))
    }

    fn headers(
        &self,
        entries: &[(String, String)],
        cookies: &[String],
        actual: bool,
    ) -> AuthResult<Value> {
        let mut ordinary = BTreeMap::<String, Vec<String>>::new();
        let mut cookie_entries = Vec::new();
        for (name, value) in entries {
            if name.eq_ignore_ascii_case("set-cookie") {
                cookie_entries.push(value.clone());
            } else {
                ordinary
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(value.clone());
            }
        }
        assert!(
            cookie_entries == cookies
                || (!cookies.is_empty() && cookie_entries == vec![cookies.join(", ")]),
            "Header iteration and getSetCookie must retain the same complete cookies"
        );
        let ordinary = ordinary
            .into_iter()
            .map(|(name, values)| (name, values.join(", ")))
            .collect::<Vec<_>>();
        let cookies = cookies
            .iter()
            .map(|cookie| self.cookie(cookie, actual))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(json!({"entries":ordinary, "cookies":cookies}))
    }

    fn actual_headers(&self, headers: &Headers) -> AuthResult<Value> {
        self.headers(
            &headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Vec<_>>(),
            &headers.get_all("set-cookie").cloned().collect::<Vec<_>>(),
            true,
        )
    }

    fn expected_headers(&self, headers: &Value) -> AuthResult<Value> {
        let entries: Vec<(String, String)> = serde_json::from_value(headers["entries"].clone())?;
        let cookies: Vec<String> = serde_json::from_value(headers["cookies"].clone())?;
        self.headers(&entries, &cookies, false)
    }
}

fn storage(raw: &EphemeralStore, shift: i64) -> AuthResult<Value> {
    let mut values = serde_json::Map::new();
    for (name, role) in [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ] {
        let rows = raw
            .storage_rows(role)?
            .into_iter()
            .map(FieldValue::from)
            .collect::<Vec<_>>();
        let _ = values.insert(name.into(), observe(&rows.into(), shift)?);
    }
    Ok(Value::Object(values))
}

async fn create_session(
    context: &AuthContext<StatelessSchema>,
    hooks: &Hooks,
    row: FieldMap,
) -> AuthResult<()> {
    let session = SessionView::from_field_values(row.clone())?;
    *hooks.seed.lock().unwrap() = Some(row);
    let _ = context
        .database
        .create_session(CreateSession {
            user_id: session.user_id,
            expires_at: session.expires_at.field_value().as_date().unwrap().clone(),
            ip_address: Some("192.0.2.1".into()),
            user_agent: Some("session-management-contract".into()),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    assert!(hooks.seed.lock().unwrap().is_none());
    Ok(())
}

async fn dispatch(
    context: &AuthContext<StatelessSchema>,
    dispatcher: &EndpointDispatcher<StatelessSchema>,
    path: &str,
    headers: HashMap<String, String>,
    body: FieldValue,
) -> AuthResult<AuthResponse> {
    let plugin = SessionManagementPlugin::new();
    let method = if ["/list-sessions", "/get-session"].contains(&path) {
        HttpMethod::Get
    } else {
        HttpMethod::Post
    };
    let route = AuthPlugin::<StatelessSchema>::routes(&plugin)
        .into_iter()
        .find(|route| route.matches(&method, path))
        .unwrap();
    let request = AuthRequest::from_parts(
        method,
        path.into(),
        headers,
        body.stringify()?.map(String::into_bytes),
        None,
    );
    dispatcher
        .native(request, route, context, |request| async move {
            plugin
                .on_request(&request, context)
                .await?
                .ok_or_else(|| AuthError::internal("Session contract route was not handled"))
        })
        .await
}

async fn check(case: &Value) -> AuthResult<()> {
    let name = case["name"].as_str().unwrap();
    let stateless = case["deployment"] == "stateless";
    let start = Utc::now().timestamp_millis();
    let mut clock = Clock {
        shift: start - NOW,
        start,
        end: start,
    };
    let hooks = Arc::new(Hooks {
        stateless,
        ..Default::default()
    });
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.session.fresh_age = Some(Duration::seconds(60));
    config.session.disable_session_refresh = Some(true);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        max_age: Some(Duration::seconds(300)),
        strategy: Some(CookieCacheStrategy::Compact),
        refresh: Some(CookieCacheRefresh::Disabled),
        ..Default::default()
    });
    let config = Arc::new(config);
    let raw = Arc::new(EphemeralStore::new(config.clone()).with_hooks(vec![hooks.clone()]));
    let plugin = SessionManagementPlugin::new();
    let mut context = initialize_test_context(config, raw.clone(), &[&plugin]).await?;
    context.extensions.insert(StoreCapabilities {
        database: !stateless,
        secondary: false,
    });
    let dispatcher = EndpointDispatcher::new(
        Arc::new(Vec::new()),
        EndpointHooks {
            before: Some(hooks.clone()),
            after: Some(hooks.clone()),
        },
        AuthPlugin::<StatelessSchema>::routes(&plugin),
    );
    let before = revive(&case["before"], clock.shift)?;
    let fields = before.as_object().unwrap();
    for row in fields.get("user").unwrap().as_array().unwrap().iter() {
        let _ = context
            .database
            .create_user_fields_optional(row.as_object().unwrap().clone())
            .await?
            .unwrap();
    }
    for row in fields.get("session").unwrap().as_array().unwrap().iter() {
        create_session(&context, &hooks, row.as_object().unwrap().clone()).await?;
    }
    assert_eq!(case["before"]["account"], json!([]), "{name}");
    assert_eq!(case["before"]["verification"], json!([]), "{name}");
    let mut headers = HashMap::from([("origin".into(), ORIGIN.into())]);
    if !stateless {
        let _ = headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                sign_cookie_value("7", SECRET)
            ),
        );
    }
    if case["source"] == "cookie" {
        let revoked = case["revoked"] == true;
        if revoked {
            let row = revive(&case["cacheSetup"]["response"]["session"], clock.shift)?;
            create_session(&context, &hooks, row.as_object().unwrap().clone()).await?;
        }
        let response = dispatch(
            &context,
            &dispatcher,
            "/get-session",
            headers.clone(),
            FieldValue::Undefined,
        )
        .await?;
        clock.end = Utc::now().timestamp_millis();
        assert_eq!(
            observe_native_status(&response, clock.shift)?,
            case["cacheSetup"]["nativeStatus"],
            "{name} cache setup native status"
        );
        assert_eq!(
            json!(response.status),
            case["cacheSetup"]["status"],
            "{name} effective HTTP status"
        );
        assert_eq!(
            observe(&response.body.field_value()?, clock.shift)?,
            case["cacheSetup"]["response"],
            "{name} cache setup body"
        );
        assert_eq!(
            clock.actual_headers(&response.headers)?,
            clock.expected_headers(&case["cacheSetup"]["headers"])?,
            "{name} cache setup headers"
        );
        let cached = response
            .headers
            .get_all("set-cookie")
            .map(|value| value.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let signed = headers.get("cookie").unwrap();
        let _ = headers.insert("cookie".into(), format!("{signed}; {cached}"));
        if revoked {
            context.database.delete_session("7").await?;
        }
    }
    assert_eq!(
        storage(&raw, clock.shift)?,
        case["before"],
        "{name} complete initial storage"
    );
    let injected = revive(&case["input"]["injected"], clock.shift)?;
    if !injected.is_undefined() {
        let fields = injected.as_object().unwrap();
        *hooks.injected.lock().unwrap() = Some(NativeSessionData {
            session: SessionView::from_field_values(
                fields.get("session").unwrap().as_object().unwrap().clone(),
            )?,
            user: fields.get("user").unwrap().clone(),
        });
    }
    hooks.recording.store(true, Ordering::SeqCst);
    let result = dispatch(
        &context,
        &dispatcher,
        case["path"].as_str().unwrap(),
        headers,
        revive(&case["input"]["body"], clock.shift)?,
    )
    .await;
    clock.end = Utc::now().timestamp_millis();
    hooks.recording.store(false, Ordering::SeqCst);
    let result = match result {
        Ok(response) => {
            let mut result = observe(&returned(&response)?, clock.shift)?;
            result["nativeStatus"] = observe_native_status(&response, clock.shift)?;
            result["status"] = json!(response.status);
            result["headers"] = clock.actual_headers(&response.headers)?;
            result
        }
        Err(AuthError::TypeError(message)) => {
            json!({"kind":"error", "name":"TypeError", "message":message, "headers":{"entries":[], "cookies":[]}})
        }
        Err(error) if error.is_api_error() => {
            let response = error.to_auth_response();
            let mut result = observe(&returned(&response)?, clock.shift)?;
            let headers = response
                .captured_headers()
                .or_else(|| response.api_error_headers())
                .unwrap_or(&response.headers);
            result["headers"] = clock.actual_headers(headers)?;
            result
        }
        Err(error) => return Err(error),
    };
    let mut expected = case["result"].clone();
    expected["headers"] = clock.expected_headers(&case["result"]["headers"])?;
    assert_eq!(result, expected, "{name} complete native result");
    let events = hooks.events.lock().unwrap().clone();
    assert_eq!(
        observe(&events.into(), clock.shift)?,
        case["events"],
        "{name} complete Hook events"
    );
    assert_eq!(
        storage(&raw, clock.shift)?,
        case["after"],
        "{name} complete final storage"
    );
    Ok(())
}

fn observe_native_status(response: &AuthResponse, shift: i64) -> AuthResult<Value> {
    let value = match response.native_status() {
        better_auth_core::NativeResponseStatus::Undefined => FieldValue::Undefined,
        better_auth_core::NativeResponseStatus::Value(status) => {
            FieldValue::Number(f64::from(status))
        }
        better_auth_core::NativeResponseStatus::Absent => {
            panic!("Endpoint status property is absent")
        }
    };
    observe(&value, shift)
}

#[tokio::test]
async fn native_session_management_matches_all_60_upstream_cases() -> AuthResult<()> {
    let path = std::env::var_os("BETTER_AUTH_SESSION_MANAGEMENT_NATIVE_FIXTURE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/session-management-native-1.7.6.json")
        });
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|error| {
            AuthError::internal(format!(
                "Read captured Session fixture {}: {error}",
                path.display()
            ))
        })?)?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["now"], NOW);
    assert_eq!(fixture["storageSurface"], "complete-adapter-view");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 60);
    for case in cases {
        check(case).await?;
    }
    Ok(())
}
