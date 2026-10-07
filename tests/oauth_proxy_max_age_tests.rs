#![expect(
    clippy::indexing_slicing,
    reason = "The captured contract requires complete response, callback, and storage fields."
)]

use better_auth::{AuthConfig, BetterAuth, plugins::OAuthProxyPlugin};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    CreateVerification, FieldDate, FieldMap, FieldValue, HttpMethod,
    id::{IdGeneration, IdGenerator},
    store::EphemeralStore,
    utils::{cookie_utils::sign_cookie_value, symmetric},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[path = "oauth_proxy_max_age_tests/hooks.rs"]
mod hooks;
#[path = "support/device_where_values.rs"]
mod values;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://oauth-proxy-max-age.test";
const SECRET: &str = "oauth-proxy-max-age-contract-secret-at-least-thirty-two-characters";

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    fn push(&self, value: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Proxy callback lock poisoned"))?
            .push(value);
        Ok(())
    }
    fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|_| {
            AuthError::internal("Proxy callback lock poisoned")
        })?))
    }
}

fn config(events: Events) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.session.expires_in = Some(Duration::seconds(3600));
    config.session.disable_session_refresh = Some(true);
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            let id = "proxy-session-1";
            let mut input = json!({"model": request.model});
            if let Some(size) = request.size {
                input["size"] = size.into();
            }
            events.push(json!({"kind":"generate-id", "input": input, "id": id}))?;
            Ok(Some(id.into()))
        })));
    config
}

async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>, case: &Value, now: i64) -> TestResult {
    let created = FieldDate::from_milliseconds((now - 120_000) as f64);
    let _ = store
        .create_user(CreateUser {
            id: Some("proxy-owner".into()),
            name: Some("Proxy Owner".into()).into(),
            email: Some("owner@oauth-proxy-max-age.test".into()),
            email_verified: Some(true),
            image: None::<String>.into(),
            created_at: Some(created.clone()),
            updated_at: Some(created.clone()),
            ..Default::default()
        })
        .await?;
    let _ = store
        .create_account(CreateAccount {
            id: "proxy-account".into(),
            account_id: "proxy-subject".into(),
            provider_id: "fixture".into(),
            user_id: "proxy-owner".into(),
            access_token: Some("proxy-old-access".into()).into(),
            refresh_token: Some("proxy-old-refresh".into()).into(),
            id_token: Some("proxy-old-id".into()).into(),
            access_token_expires_at: None::<FieldDate>.into(),
            refresh_token_expires_at: None::<FieldDate>.into(),
            scope: Some("openid email".into()).into(),
            password: None::<String>.into(),
            created_at: created.clone().into(),
            updated_at: created.clone().into(),
            ..Default::default()
        })
        .await?;
    let _ = store
        .create_verification(CreateVerification {
            id: "proxy-verification".into(),
            identifier: "proxy-max-age-state".into(),
            value: case["before"]["verification"][0]["value"]
                .as_str()
                .ok_or("Missing state JSON")?
                .to_owned()
                .into(),
            expires_at: FieldDate::from_milliseconds((now + 600_000) as f64).into(),
            created_at: created.clone().into(),
            updated_at: created.into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

async fn snapshot<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    config: &AuthConfig,
) -> TestResult<Value> {
    let (users, count) = store
        .list_users(better_auth_core::ListUsersParams {
            limit: Some(100.0),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let mut user_rows = Vec::new();
    let mut sessions = Vec::new();
    let mut accounts = Vec::new();
    for user in users {
        let view = better_auth_core::wire::UserView::with_internal_fields(
            &user,
            &config.user,
            &Default::default(),
        )
        .await?;
        user_rows.push(values::observe(&FieldMap::from(view).into())?);
        for account in store.get_user_accounts(user.id.typed()?).await? {
            accounts.push(values::observe(&account.internal_fields()?.into())?);
        }
        for session in store.get_user_sessions(user.id.typed()?).await? {
            sessions.push(values::observe(&FieldMap::from(session).into())?);
        }
    }
    let verification = store
        .get_verification_by_identifier("proxy-max-age-state")
        .await?
        .map(|row| values::observe(&row.fields()?.into()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    Ok(
        json!({"user": user_rows, "session": sessions, "account": accounts, "verification": verification}),
    )
}

fn date_millis(value: &Value) -> TestResult<i64> {
    Ok(value
        .get("value")
        .and_then(Value::as_str)
        .ok_or("Missing Date observation")?
        .parse::<DateTime<Utc>>()?
        .timestamp_millis())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Captured dates must remain inside the observed request interval."
)]
fn normalize_dates(
    row: &mut Value,
    expected: &Value,
    fields: &[(&str, i64)],
    start: i64,
    end: i64,
) -> TestResult {
    for (name, offset) in fields {
        let timestamp = date_millis(&row[*name])? - offset;
        assert!(
            (start..=end).contains(&timestamp),
            "{name} must derive from the observed request interval"
        );
        row[*name] = expected[*name].clone();
    }
    Ok(())
}

fn replace_string(value: &mut Value, source: &str, replacement: &str) {
    match value {
        Value::String(text) => *text = text.replace(source, replacement),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| replace_string(value, source, replacement)),
        Value::Object(fields) => fields
            .values_mut()
            .for_each(|value| replace_string(value, source, replacement)),
        _ => {}
    }
}

async fn contract(case: &Value, now: i64) -> TestResult {
    let events = Events::default();
    let recording = Arc::new(AtomicBool::new(false));
    let config = config(events.clone());
    let raw: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
        Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let raw = raw.with_runtime(
        Arc::new(config.clone()),
        vec![Arc::new(hooks::Hooks {
            events: events.clone(),
            recording: recording.clone(),
        })],
        Default::default(),
    )?;
    seed(raw.as_ref(), case, now).await?;
    assert_eq!(snapshot(raw.as_ref(), &config).await?, case["before"]);
    assert!(events.take()?.is_empty());
    let FieldValue::Number(max_age) = values::revive(&case["maxAge"])? else {
        return Err("Missing numeric maxAge".into());
    };
    let auth = BetterAuth::new(config.clone())
        .store_arc(raw.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
        .plugin(OAuthProxyPlugin::new().max_age(max_age))
        .build()
        .await?;
    assert_eq!(snapshot(raw.as_ref(), &config).await?, case["before"]);
    assert!(events.take()?.is_empty());

    // Exact one-millisecond boundaries use the production predicate's fixed-clock unit contract.
    // HTTP uses safe interior ages and verifies the request remained in the same acceptance interval.
    let safe_age = match case["ageMillis"].as_i64() {
        Some(60_000) => 30_000,
        Some(60_001) => 90_000,
        Some(-10_000) => -5_000,
        Some(-10_001) => -60_000,
        _ => return Err("Unknown captured age".into()),
    };
    let timestamp = Utc::now().timestamp_millis() - safe_age;
    let mut payload = case["payload"].clone();
    payload["timestamp"] = timestamp.into();
    let plaintext = serde_json::to_string(&payload)?;
    let encrypted = symmetric::encrypt(SECRET, &plaintext)?;
    assert_eq!(symmetric::decrypt(SECRET, &encrypted)?, plaintext);
    let url = case["input"]["url"]
        .as_str()
        .ok_or("Missing request URL")?
        .replace("<encrypted-profile>", &encrypted)
        .parse()?;
    let headers: HashMap<String, String> =
        serde_json::from_value::<Vec<(String, String)>>(case["input"]["headers"].clone())?
            .into_iter()
            .collect();
    assert_eq!(
        headers.get("cookie"),
        Some(&format!(
            "better-auth.state={}",
            sign_cookie_value("proxy-max-age-state", SECRET)
        ))
    );
    let request = AuthRequest::from_parts(
        HttpMethod::Get,
        "/api/auth/callback/fixture/oauth-proxy".into(),
        headers,
        None,
        Some(json!({"callbackURL": payload["callbackURL"], "profile": encrypted})),
    )
    .with_url(url);
    recording.store(true, Ordering::SeqCst);
    let start = Utc::now().timestamp_millis();
    let response = auth.handle_request(request).await?;
    let end = Utc::now().timestamp_millis();
    recording.store(false, Ordering::SeqCst);
    let accepted = case["accepted"].as_bool().ok_or("Missing acceptance")?;
    for clock in [start, end] {
        let age = (clock - timestamp) as f64 / 1000.0;
        assert_eq!(
            !(age > max_age || age < -10.0),
            accepted,
            "HTTP must remain inside the selected clock interval"
        );
    }
    let mut after = snapshot(raw.as_ref(), &config).await?;
    let mut observed_events = events.take()?;
    let mut headers: Vec<_> = response
        .headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
        .collect();
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let mut observed = json!({"status": response.status, "headers": headers,
        "cookies": response.headers.get_all("set-cookie").cloned().collect::<Vec<_>>(), "body": String::from_utf8(response.body.bytes()?.into_owned())?});
    if accepted {
        let session = after["session"][0].clone();
        let account = after["account"][0].clone();
        let token = session["token"].as_str().ok_or("Missing Session token")?;
        assert_eq!(token.len(), 32);
        assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        let signed = sign_cookie_value(token, SECRET);
        assert_eq!(
            observed["cookies"][1],
            format!(
                "better-auth.session_token={signed}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"
            )
        );
        for event in &mut observed_events {
            match (event["model"].as_str(), event["phase"].as_str()) {
                (Some("account"), Some("after")) => {
                    assert_eq!(event["data"], account);
                    normalize_dates(
                        &mut event["data"],
                        &case["after"]["account"][0],
                        &[("updatedAt", 0)],
                        start,
                        end,
                    )?;
                }
                (Some("session"), _) => {
                    let mut expected = session.clone();
                    if event["phase"] == "before" {
                        let _ = expected
                            .as_object_mut()
                            .ok_or("Missing Session object")?
                            .remove("id");
                    }
                    assert_eq!(event["data"], expected);
                    normalize_dates(
                        &mut event["data"],
                        &case["after"]["session"][0],
                        &[("createdAt", 0), ("updatedAt", 0), ("expiresAt", 3_600_000)],
                        start,
                        end,
                    )?;
                }
                _ => {}
            }
        }
        normalize_dates(
            &mut after["account"][0],
            &case["after"]["account"][0],
            &[("updatedAt", 0)],
            start,
            end,
        )?;
        normalize_dates(
            &mut after["session"][0],
            &case["after"]["session"][0],
            &[("createdAt", 0), ("updatedAt", 0), ("expiresAt", 3_600_000)],
            start,
            end,
        )?;
        replace_string(&mut observed, &signed, "<session-token>.<session-hmac>");
        replace_string(&mut after, token, "<session-token>");
        for event in &mut observed_events {
            replace_string(event, token, "<session-token>");
        }
    }
    let mut expected = case["completion"]["value"].clone();
    // AuthResponse stores the numeric status; JavaScript's statusText has no Rust counterpart.
    let _ = expected
        .as_object_mut()
        .ok_or("Missing HTTP response")?
        .remove("statusText");
    assert_eq!(observed, expected, "{}", case["scenario"]);
    assert_eq!(json!(observed_events), case["events"]);
    assert_eq!(after, case["after"]);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract requires the complete captured case inventory."
)]
async fn proxy_max_age_matches_captured_http_lifecycle_inside_each_clock_interval() -> TestResult {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/oauth-proxy-max-age-1.7.6.json"))?;
    assert_eq!(fixture["version"], "1.7.6");
    let now = fixture["now"].as_i64().ok_or("Missing captured clock")?;
    let cases = fixture["cases"].as_array().ok_or("Missing Proxy cases")?;
    assert_eq!(cases.len(), 16);
    for case in cases {
        contract(case, now).await?;
    }
    Ok(())
}
