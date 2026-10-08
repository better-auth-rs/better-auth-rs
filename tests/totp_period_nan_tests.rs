#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture shape and contract assertions must fail immediately; setup errors propagate."
)]

use async_trait::async_trait;
use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth,
    plugins::{TwoFactorConfig, TwoFactorPlugin},
};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateSession, CreateTwoFactor, CreateUser, FieldDate, HttpMethod,
    ListUsersParams, TwoFactor, UserView,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema},
    utils::{
        cookie_utils::sign_cookie_value,
        symmetric::{decrypt, encrypt},
    },
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "email_verification_payload_tests/hooks.rs"]
mod hooks;
#[path = "support/device_where_values.rs"]
mod values;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://totp-period-nan.test";
const AUTH_SECRET: &str = "totp-period-nan-contract-secret-longer-than-32-characters";
const TOKEN: &str = "nan-owner-session-token";

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    fn push(&self, event: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("TOTP recorder poisoned"))?
            .push(event);
        Ok(())
    }

    fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|_| {
            AuthError::internal("TOTP recorder poisoned")
        })?))
    }
}

struct Runtime {
    auth: BetterAuth<StatelessSchema>,
    events: Events,
    replacements: Vec<(String, String)>,
}

fn iso(date: DateTime<Utc>) -> String {
    date.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn normalize(value: &mut Value, replacements: &[(String, String)]) {
    match value {
        Value::String(text) => {
            for (source, replacement) in replacements {
                *text = text.replace(source, replacement);
            }
        }
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| normalize(value, replacements)),
        Value::Object(fields) => fields
            .values_mut()
            .for_each(|value| normalize(value, replacements)),
        _ => {}
    }
}

impl Runtime {
    async fn new(fixture: &Value, digits: usize, enabled: bool) -> TestResult<Self> {
        let events = Events::default();
        let mut config = AuthConfig::new(AUTH_SECRET).base_url(ORIGIN);
        config.app_name = fixture["issuer"].as_str().expect("issuer").to_owned();
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        config.session.expires_in = Some(Duration::hours(1));
        config.session.disable_session_refresh = Some(true);
        config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
            enabled: Some(false),
            ..Default::default()
        });
        let generated = events.clone();
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |input| {
                assert!(input.size.is_none());
                let id = match input.model {
                    "session" => "nan-session".to_owned(),
                    "twoFactor" if enabled => "nan-factor".to_owned(),
                    "twoFactor" => format!("nan-{digits}-enrollment-twoFactor-1"),
                    model => {
                        return Err(AuthError::internal(format!(
                            "Unexpected generated model: {model}"
                        )));
                    }
                };
                generated
                    .push(json!({"kind":"generate-id", "input":{"model":input.model}, "id":id}))?;
                Ok(Some(id))
            })));
        let backup = events.clone();
        let factor = TwoFactorConfig {
            allow_passwordless: true,
            totp_period: f64::NAN,
            totp_digits: digits,
            backup_code_options: better_auth::plugins::two_factor::BackupCodeOptions {
                generate: Some(Arc::new(move || {
                    let codes = vec![
                        "ordinary-backup-one".to_owned(),
                        "ordinary-backup-two".to_owned(),
                    ];
                    backup
                        .push(json!({"kind":"backup-codes", "codes":codes}))
                        .expect("record backup generation");
                    codes
                })),
                ..Default::default()
            },
            ..Default::default()
        };
        let store = EphemeralStore::new(Arc::new(config.clone()))
            .with_hooks(vec![Arc::new(hooks::DatabaseObserver(events.clone()))]);
        let auth = AuthBuilder::new(config)
            .store(store)
            .rate_limit(better_auth_core::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(TwoFactorPlugin::with_config(factor))
            .build()
            .await?;
        assert!(events.take()?.is_empty());
        let now = DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
            .expect("current millisecond clock");
        let expiry = now + Duration::hours(1);
        let date: FieldDate = now.into();
        let user = auth
            .store()
            .create_user(CreateUser {
                id: Some("nan-owner".into()),
                name: Some("NaN TOTP Owner".into()).into(),
                email: Some(fixture["account"].as_str().expect("account").to_owned()),
                email_verified: Some(true),
                image: None.into(),
                created_at: Some(date.clone()),
                updated_at: Some(date.clone()),
                ..Default::default()
            })
            .await?;
        assert_eq!(user.created_at, date);
        assert_eq!(user.updated_at, date);
        let update_started = Utc::now().timestamp_millis();
        let user = if enabled {
            auth.store()
                .update_user(
                    "nan-owner",
                    better_auth_core::UpdateUser {
                        two_factor_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await?
        } else {
            user
        };
        let updated = user.updated_at.date_milliseconds()? as i64;
        if enabled {
            assert!((update_started..=Utc::now().timestamp_millis()).contains(&updated));
        }
        assert_eq!(user.two_factor_enabled, Some(enabled));
        let session = auth
            .store()
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: "nan-owner".into(),
                expires_at: expiry.into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: [
                    ("token".into(), TOKEN.into()),
                    ("ipAddress".into(), better_auth_core::FieldValue::Null),
                    ("userAgent".into(), better_auth_core::FieldValue::Null),
                    ("createdAt".into(), date.clone().into()),
                    ("updatedAt".into(), date.into()),
                ]
                .into(),
            })
            .await?;
        assert_eq!(session.token, TOKEN);
        assert_eq!(
            session.created_at.date_milliseconds().unwrap(),
            now.timestamp_millis() as f64
        );
        assert_eq!(
            session.updated_at.date_milliseconds().unwrap(),
            now.timestamp_millis() as f64
        );
        assert_eq!(
            session.expires_at.date_milliseconds().unwrap(),
            expiry.timestamp_millis() as f64
        );
        let captured = DateTime::from_timestamp_millis(
            fixture["timestampMillis"].as_i64().expect("capture clock"),
        )
        .expect("captured date");
        let _ = events.take()?;
        Ok(Self {
            auth,
            events,
            replacements: vec![
                (iso(now), iso(captured)),
                (iso(expiry), iso(captured + Duration::hours(1))),
                (
                    iso(DateTime::from_timestamp_millis(updated).expect("stored user update time")),
                    iso(captured),
                ),
            ],
        })
    }

    async fn factor(&self) -> TestResult<TwoFactor> {
        Ok(self
            .auth
            .store()
            .get_two_factor_by_user_id("nan-owner")
            .await?
            .expect("stored factor"))
    }

    async fn snapshot(&self) -> TestResult<Value> {
        let (users, count) = self
            .auth
            .store()
            .list_users(ListUsersParams::default())
            .await?;
        assert_eq!(count, 1);
        assert_eq!(users.len(), 1);
        let mut users_projected = Vec::new();
        for user in &users {
            users_projected.push(self.auth.context().internal_user_view(user).await?);
        }
        let sessions = self.auth.store().get_user_sessions("nan-owner").await?;
        assert_eq!(sessions.len(), 1);
        let mut sessions_projected = Vec::new();
        for session in &sessions {
            sessions_projected.push(self.auth.context().session_view(session).await?);
        }
        let accounts = self.auth.store().get_user_accounts("nan-owner").await?;
        let mut factors = Vec::new();
        if let Some(factor) = self
            .auth
            .store()
            .get_two_factor_by_user_id("nan-owner")
            .await?
        {
            assert!(factor.locked_until.is_undefined());
            let value = serde_json::to_value(factor)?;
            assert!(
                !value
                    .as_object()
                    .expect("factor object")
                    .contains_key("lockedUntil")
            );
            factors.push(value);
        }
        let mut state = json!({"user":users_projected,"session":sessions_projected,"account":accounts,"twoFactor":factors});
        normalize(&mut state, &self.replacements);
        Ok(state)
    }

    async fn assert_snapshot(&self, expected: &Value) -> TestResult {
        assert_eq!(expected["verification"], json!([]));
        let captured = values::revive(expected)?;
        assert_eq!(values::observe(&captured)?, *expected);
        let mut expected = captured.json()?.expect("JSON snapshot");
        let _ = expected
            .as_object_mut()
            .expect("snapshot object")
            .remove("verification");
        assert_eq!(self.snapshot().await?, expected);
        Ok(())
    }

    async fn request(&self, observation: &Value, code: Option<&str>) -> TestResult<Value> {
        self.assert_snapshot(&observation["before"]).await?;
        let input = &observation["input"];
        assert_eq!(input["method"], "POST");
        let url = input["url"].as_str().expect("request URL");
        let mut request = AuthRequest::new(
            HttpMethod::Post,
            format!("/api/auth{}", observation["name"].as_str().expect("route")),
        )
        .with_url(url.parse()?);
        for header in input["headers"].as_array().expect("request headers") {
            let _ = request.headers.insert(
                header[0].as_str().expect("header name").into(),
                header[1].as_str().expect("header value").into(),
            );
        }
        assert_eq!(
            request.headers.get("cookie"),
            Some(&format!(
                "better-auth.session_token={}",
                sign_cookie_value(TOKEN, AUTH_SECRET)
            ))
        );
        let mut body: Value = serde_json::from_str(input["body"].as_str().expect("request body"))?;
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        request.body = Some(serde_json::to_vec(&body)?);
        let response = self.auth.handle_request(request).await?;
        let mut headers: Vec<_> = response
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        headers.sort();
        let mut actual = json!({"status":response.status,"headers":headers,"cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>(),"body":serde_json::from_slice::<Value>(&response.body.bytes()?)?});
        let captured = &observation["outcome"];
        assert_eq!(captured["kind"], "returned");
        assert_eq!(
            captured["value"]["statusText"],
            if captured["value"]["status"] == 401 {
                "UNAUTHORIZED"
            } else {
                ""
            }
        );
        let expected = json!({"status":captured["value"]["status"],"headers":captured["value"]["headers"],"cookies":captured["value"]["cookies"],"body":serde_json::from_str::<Value>(captured["value"]["body"].as_str().expect("captured body"))?});
        if observation["name"] != "/two-factor/enable" {
            normalize(&mut actual, &self.replacements);
            assert_eq!(actual, expected);
            self.assert_snapshot(&observation["after"]).await?;
            assert_eq!(json!(self.events.take()?), observation["events"]);
        }
        Ok(actual)
    }
}

#[tokio::test]
async fn nan_period_http_operations_match_pinned_responses_storage_and_callbacks() -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/totp-period-nan-1.7.6.json"))?;
    let secret = fixture["secret"].as_str().expect("fixture secret");
    for case in fixture["cases"].as_array().expect("captured cases") {
        let digits = usize::try_from(case["options"]["digits"].as_u64().expect("digits"))?;
        let mut server = Runtime::new(&fixture, digits, true).await?;
        let key = server.auth.context().config.encryption_secret();
        let encrypted_secret = encrypt(key, secret)?;
        let codes = json!(["ordinary-backup-one", "ordinary-backup-two"]);
        let encrypted_codes = encrypt(key, &serde_json::to_string(&codes)?)?;
        assert_eq!(decrypt(key, &encrypted_secret)?, secret);
        assert_eq!(
            serde_json::from_str::<Value>(&decrypt(key, &encrypted_codes)?)?,
            codes
        );
        let _ = server
            .auth
            .store()
            .create_two_factor(CreateTwoFactor {
                user_id: "nan-owner".into(),
                secret: encrypted_secret.clone(),
                backup_codes: encrypted_codes.clone(),
                verified: true,
                additional_fields: Default::default(),
            })
            .await?;
        server.replacements.extend([
            (encrypted_secret, "<stored-secret-ciphertext>".into()),
            (encrypted_codes, "<stored-backup-ciphertext>".into()),
        ]);
        let _ = server.events.take()?;
        let generation = &case["server"]["generation"];
        server.assert_snapshot(&generation["before"]).await?;
        let default = TwoFactorPlugin::with_config(TwoFactorConfig {
            totp_digits: digits,
            ..Default::default()
        });
        let start = Utc::now().timestamp_millis();
        let before = default.generate_totp(secret)?;
        let code =
            better_auth::plugins::two_factor::TwoFactorApi::from_context(server.auth.context())?
                .generate_totp(Some(generation["input"]["body"].clone()))
                .await?;
        let after = default.generate_totp(secret)?;
        assert!(Utc::now().timestamp_millis() - start < 30_000);
        assert!(
            code == before || code == after,
            "NaN uses a 30-second counter within the observed clock interval"
        );
        assert_eq!(code.len(), digits);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        server.assert_snapshot(&generation["after"]).await?;
        assert_eq!(json!(server.events.take()?), generation["events"]);
        let _ = server.request(&case["server"]["uri"], None).await?;
        let _ = server
            .request(&case["server"]["verification"], Some(&code))
            .await?;
        let _ = server.request(&case["server"]["invalid"], None).await?;

        let mut enrollment = Runtime::new(&fixture, digits, false).await?;
        let mut response = enrollment
            .request(&case["enrollment"]["enable"], None)
            .await?;
        let factor = enrollment.factor().await?;
        let key = enrollment.auth.context().config.encryption_secret();
        let generated_secret = decrypt(key, factor.secret.typed()?)?;
        assert_eq!(generated_secret.len(), 32);
        assert!(
            generated_secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&decrypt(key, factor.backup_codes.typed()?)?)?,
            codes
        );
        let uri = response["body"]["totpURI"]
            .as_str()
            .expect("enrollment URI")
            .to_owned();
        let encoded = uri
            .split("?secret=")
            .nth(1)
            .and_then(|query| query.split('&').next())
            .expect("complete enrollment URI secret");
        assert_eq!(encoded.len(), 52);
        assert!(
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        );
        enrollment.replacements.extend([
            (
                factor.secret.typed()?.clone(),
                "<enrollment-secret-ciphertext>".into(),
            ),
            (
                factor.backup_codes.typed()?.clone(),
                "<enrollment-backup-ciphertext>".into(),
            ),
            (encoded.into(), "<enrollment-secret-base32>".into()),
        ]);
        normalize(&mut response, &enrollment.replacements);
        let expected = &case["enrollment"]["enable"]["outcome"]["value"];
        assert_eq!(
            response,
            json!({"status":expected["status"],"headers":expected["headers"],"cookies":expected["cookies"],"body":serde_json::from_str::<Value>(expected["body"].as_str().expect("enrollment body"))?})
        );
        enrollment
            .assert_snapshot(&case["enrollment"]["enable"]["after"])
            .await?;
        assert_eq!(
            json!(enrollment.events.take()?),
            case["enrollment"]["enable"]["events"]
        );
        let _ = enrollment.request(&case["enrollment"]["uri"], None).await?;
    }
    eprintln!(
        "TOTP pairing checks exact fixed-clock codes in the API unit contract and dynamic HTTP values after clock and ciphertext validation. Raw Memory enumeration, JavaScript error properties, object identity, and HTTP statusText are upstream-only; Rust compares complete JSON bodies, headers, reachable stored records, and callback order. Enrollment Base32 decoding is checked with the existing API codec."
    );
    Ok(())
}
