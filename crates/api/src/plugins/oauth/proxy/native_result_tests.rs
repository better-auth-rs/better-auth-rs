#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Paired with contracts/oauth-proxy-native-result.mjs before HTTP serialization.

#![expect(
    clippy::unwrap_used,
    reason = "Native contract assertions fail immediately on missing properties or poisoned test log locks"
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    CreateVerification, FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue, HttpMethod,
    OAuthStateStrategy, ResponseBody, Utf16String,
    observability::logger::{LogArgument, LogLevel, LogSink, LoggerConfig},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use chrono::{Duration, Utc};

use super::OAuthProxyPlugin;
use crate::plugins::{symmetric, test_helpers};

const ORIGIN: &str = "http://preview.proxy-result.test";
const PRODUCTION: &str = "http://production.proxy-result.test";
const SECRET: &str = "oauth-proxy-native-result-secret-at-least-thirty-two-characters";
const STATE: &str = "native-proxy-state";
const URL: &str =
    "https://provider.test/authorize?before=a%20b&state=native-proxy-state&state=discarded&after=~";
const PLAINTEXT: &str =
    " { \"callbackURL\": \"http://preview.proxy-result.test/complete\", \"extra\": 1 } \n";

#[derive(Default)]
struct Logs(Mutex<Vec<(String, String, Vec<String>)>>);

impl LogSink for Logs {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> better_auth_core::AuthResult<()> {
        self.0.lock().unwrap().push((
            level.as_str().into(),
            message.to_string(),
            arguments.iter().map(ToString::to_string).collect(),
        ));
        Ok(())
    }
}

struct Fixture {
    context: AuthContext<StatelessSchema>,
    store: Arc<EphemeralStore>,
    reads: Arc<AtomicUsize>,
    logs: Arc<Logs>,
}

impl Fixture {
    async fn new(
        strategy: OAuthStateStrategy,
        persisted: bool,
        output: Option<FieldValue>,
        fail_read: bool,
    ) -> AuthResult<Self> {
        let reads = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(false));
        let logs = Arc::new(Logs::default());
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.account.store_state_strategy = Some(strategy);
        config.logger = LoggerConfig {
            log: Some(logs.clone()),
            ..Default::default()
        }
        .into();
        let observed_reads = reads.clone();
        let observed_armed = armed.clone();
        let _ = config.verification.additional_fields.insert(
            "value".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        if !observed_armed.load(Ordering::SeqCst) {
                            return Ok(value);
                        }
                        let _ = observed_reads.fetch_add(1, Ordering::SeqCst);
                        if fail_read {
                            return Err(AuthError::internal("proxy lookup original failure"));
                        }
                        Ok(output.clone().unwrap_or(value))
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let context =
            test_helpers::initialize_test_context(config, store.clone(), &[&plugin()]).await?;
        if persisted {
            let _ = context
                .database
                .create_verification(CreateVerification {
                    identifier: STATE.to_owned().into(),
                    value: PLAINTEXT.to_owned().into(),
                    expires_at: (Utc::now() + Duration::minutes(5)).into(),
                    ..Default::default()
                })
                .await?;
        }
        armed.store(true, Ordering::SeqCst);
        logs.0.lock().unwrap().clear();
        Ok(Self {
            context,
            store,
            reads,
            logs,
        })
    }

    fn assert_logs(&self, level: &str, message: &str, arguments: usize) {
        let logs = self.logs.0.lock().unwrap();
        assert_eq!(logs.len(), 1, "{logs:?}");
        let (actual_level, actual_message, actual_arguments) = logs.first().unwrap();
        assert_eq!(actual_level, level);
        assert_eq!(actual_message, message);
        assert_eq!(actual_arguments.len(), arguments);
    }
}

fn plugin() -> OAuthProxyPlugin {
    OAuthProxyPlugin::new()
        .current_url(ORIGIN.to_owned())
        .production_url(PRODUCTION.to_owned())
}

fn request() -> AuthRequest {
    AuthRequest::new(HttpMethod::Post, "/sign-in/social")
}

fn object(url: FieldValue) -> FieldValue {
    FieldMap::from([("url".into(), url), ("kept".into(), FieldValue::Undefined)]).into()
}

fn returned(response: &AuthResponse) -> AuthResult<FieldValue> {
    assert!(response.is_native());
    response.body.field_value()
}

fn assert_package(response: &AuthResponse, plaintext: &str) -> AuthResult<()> {
    let value = returned(response)?.model_property("url")?;
    let url = url::Url::parse(value.as_str().unwrap()).unwrap();
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        pairs
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        ["before", "state", "after"]
    );
    assert_eq!(pairs.first().unwrap().1, "a b");
    assert_eq!(pairs.last().unwrap().1, "~");
    let encrypted = pairs
        .iter()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .as_str();
    let package: serde_json::Value = serde_json::from_str(&symmetric::decrypt(SECRET, encrypted)?)?;
    assert_eq!(
        package
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["state", "stateCookie", "isOAuthProxy"]
    );
    assert_eq!(
        package.get("state").and_then(serde_json::Value::as_str),
        Some(STATE)
    );
    assert_eq!(
        package
            .get("isOAuthProxy")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        symmetric::decrypt(
            SECRET,
            package
                .get("stateCookie")
                .and_then(serde_json::Value::as_str)
                .unwrap()
        )?,
        plaintext
    );
    assert!(value.as_str().unwrap().contains("before=a+b&"));
    assert!(value.as_str().unwrap().ends_with("&after=%7E"));
    Ok(())
}

#[tokio::test]
async fn native_result_shallow_copy_preserves_values_order_identity_and_status() -> AuthResult<()> {
    for status in [None, Some(201), Some(401)] {
        let fixture = Fixture::new(OAuthStateStrategy::Database, true, None, false).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let function: FieldValue = FieldFunction::contextual(move |_, _| {
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::internal(
                "proxy must not serialize returned fields",
            ))
        })
        .into();
        let shared = FieldObject::from(FieldMap::new());
        shared.set("self", FieldValue::Object(shared.clone()))?;
        let original: FieldValue = FieldMap::from([
            ("9".into(), "nine".into()),
            ("url".into(), URL.into()),
            ("2".into(), "two".into()),
            ("left".into(), FieldValue::Object(shared.clone())),
            ("date".into(), FieldValue::Date(FieldDate::invalid())),
            ("missing".into(), FieldValue::Undefined),
            ("nan".into(), FieldValue::Number(f64::NAN)),
            ("right".into(), FieldValue::Object(shared.clone())),
            ("toJSON".into(), function),
        ])
        .into();
        let before = fixture.store.storage_rows(EntityRole::Verification)?;
        let mut response =
            AuthResponse::native(status, original.clone()).with_header("x-proxy", "kept");
        let headers = response.headers.clone();
        let native_status = response.native_status();
        plugin()
            .after_request(&request(), &mut response, &fixture.context)
            .await?;
        let after = returned(&response)?;
        assert!(!after.strict_equals(&original));
        assert_eq!(
            after.as_object().unwrap().own_keys()?,
            [
                "2", "9", "url", "left", "date", "missing", "nan", "right", "toJSON"
            ]
        );
        for name in ["left", "right", "date", "missing", "toJSON"] {
            assert!(
                after
                    .model_property(name)?
                    .strict_equals(&original.model_property(name)?),
                "{name}"
            );
        }
        assert!(after.model_property("nan")?.as_f64().unwrap().is_nan());
        assert_eq!(original.model_property("url")?, URL.into());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(response.native_status(), native_status);
        assert_eq!(response.status, status.unwrap_or(200));
        assert_eq!(response.headers, headers);
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.store.storage_rows(EntityRole::Verification)?,
            before
        );
        assert!(fixture.logs.0.lock().unwrap().is_empty());
        assert_package(&response, PLAINTEXT)?;
        let _ = shared.delete("self")?;
    }
    Ok(())
}

#[tokio::test]
async fn native_result_guards_skip_without_serialization_or_state_lookup() -> AuthResult<()> {
    let mut values = vec![
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        7.0.into(),
        "text".into(),
        FieldMap::new().into(),
        Vec::<FieldValue>::new().into(),
        FieldDate::invalid().into(),
        FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
    ];
    for url in [
        FieldValue::Undefined,
        FieldValue::Null,
        7.0.into(),
        "".into(),
        "https://provider.test/authorize".into(),
        "https://provider.test/authorize?state=&state=native-proxy-state".into(),
    ] {
        values.push(object(url));
    }
    for original in values {
        let fixture = Fixture::new(OAuthStateStrategy::Database, true, None, true).await?;
        let mut response = AuthResponse::native(None, original.clone());
        plugin()
            .after_request(&request(), &mut response, &fixture.context)
            .await?;
        assert!(returned(&response)?.strict_equals(&original));
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
        assert!(fixture.logs.0.lock().unwrap().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn native_result_url_errors_escape_before_state_try_and_utf16_uses_usvstring()
-> AuthResult<()> {
    let fixture = Fixture::new(OAuthStateStrategy::Database, true, None, false).await?;
    let original = object("not a URL".into());
    let mut response = AuthResponse::native(None, original.clone());
    let error = plugin()
        .after_request(&request(), &mut response, &fixture.context)
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::TypeError(_)));
    assert!(returned(&response)?.strict_equals(&original));
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert!(fixture.logs.0.lock().unwrap().is_empty());
    let mut units: Vec<_> = format!("{URL}#").encode_utf16().collect();
    units.push(0xd800);
    let mut response = AuthResponse::native(None, object(Utf16String::from_units(units).into()));
    plugin()
        .after_request(&request(), &mut response, &fixture.context)
        .await?;
    assert!(
        returned(&response)?
            .model_property("url")?
            .as_str()
            .unwrap()
            .ends_with("#%EF%BF%BD")
    );
    Ok(())
}

#[tokio::test]
async fn native_result_state_truthiness_and_failures_preserve_original() -> AuthResult<()> {
    for (persisted, output, fail_read, error) in [
        (false, None, false, false),
        (true, Some(FieldValue::Undefined), false, false),
        (true, Some(FieldValue::Null), false, false),
        (true, Some(false.into()), false, false),
        (true, Some(0.0.into()), false, false),
        (true, Some(FieldValue::Number(f64::NAN)), false, false),
        (true, Some("".into()), false, false),
        (true, Some(7.0.into()), false, true),
        (true, Some(FieldMap::new().into()), false, true),
        (true, None, true, true),
    ] {
        let fixture =
            Fixture::new(OAuthStateStrategy::Database, persisted, output, fail_read).await?;
        let original = object(URL.into());
        let before = fixture.store.storage_rows(EntityRole::Verification)?;
        let mut response = AuthResponse::native(403, original.clone());
        plugin()
            .after_request(&request(), &mut response, &fixture.context)
            .await?;
        assert!(returned(&response)?.strict_equals(&original));
        assert_eq!(
            fixture.store.storage_rows(EntityRole::Verification)?,
            before
        );
        fixture.assert_logs(
            if error { "error" } else { "warn" },
            if error {
                "Failed to prepare OAuth proxy state:"
            } else {
                "No OAuth state found for proxy"
            },
            usize::from(error),
        );
        if fail_read {
            assert!(
                fixture
                    .logs
                    .0
                    .lock()
                    .unwrap()
                    .first()
                    .unwrap()
                    .2
                    .first()
                    .unwrap()
                    .contains("proxy lookup original failure")
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_result_cookie_state_preserves_plaintext_and_catches_decryption_errors()
-> AuthResult<()> {
    for payload in [None, Some(""), Some(PLAINTEXT), Some("invalid-ciphertext")] {
        let fixture = Fixture::new(OAuthStateStrategy::Cookie, false, None, false).await?;
        let original = object(URL.into());
        let mut response = AuthResponse::native(202, original.clone());
        if let Some(payload) = payload {
            let encrypted = if payload == "invalid-ciphertext" {
                payload.to_owned()
            } else {
                symmetric::encrypt(SECRET, payload)?
            };
            response.headers.append(
                "set-cookie",
                format!(
                    "better-auth.oauth_state={}; Path=/; HttpOnly",
                    urlencoding::encode(&encrypted)
                ),
            );
        }
        let headers = response.headers.clone();
        plugin()
            .after_request(&request(), &mut response, &fixture.context)
            .await?;
        assert_eq!(response.headers, headers);
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
        if payload == Some(PLAINTEXT) {
            assert_package(&response, PLAINTEXT)?;
            assert!(fixture.logs.0.lock().unwrap().is_empty());
        } else {
            assert!(returned(&response)?.strict_equals(&original));
            let error = payload == Some("invalid-ciphertext");
            fixture.assert_logs(
                if error { "error" } else { "warn" },
                if error {
                    "Failed to prepare OAuth proxy state:"
                } else {
                    "No OAuth state found for proxy"
                },
                usize::from(error),
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_result_cookie_uses_last_value_and_decodes_ciphertext() -> AuthResult<()> {
    let fixture = Fixture::new(OAuthStateStrategy::Cookie, false, None, false).await?;
    let ciphertext = symmetric::encrypt(SECRET, PLAINTEXT)?;
    let encoded: String = ciphertext
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect();
    let mut response = AuthResponse::native(None, object(URL.into()));
    response.headers.append(
        "set-cookie",
        "better-auth.oauth_state=invalid-ciphertext; Path=/",
    );
    response.headers.append(
        "set-cookie",
        format!("better-auth.oauth_state={encoded}; Path=/"),
    );
    let headers = response.headers.clone();
    plugin()
        .after_request(&request(), &mut response, &fixture.context)
        .await?;
    assert_package(&response, PLAINTEXT)?;
    assert_eq!(response.headers, headers);
    assert!(fixture.logs.0.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn native_result_after_hook_rechecks_skip_and_ignores_explicit_json_bytes() -> AuthResult<()>
{
    let fixture = Fixture::new(OAuthStateStrategy::Database, true, None, false).await?;
    for same_origin in [false, true] {
        let proxy = if same_origin {
            OAuthProxyPlugin::new()
                .current_url(ORIGIN.to_owned())
                .production_url(ORIGIN.to_owned())
        } else {
            plugin()
        };
        let mut req = request();
        fixture.context.set_base_url(PRODUCTION);
        if !same_origin {
            let _ = req.headers.insert("x-skip-oauth-proxy".into(), "1".into());
        }
        let original = object(URL.into());
        let mut response = AuthResponse::native(None, original.clone());
        proxy
            .after_request(&req, &mut response, &fixture.context)
            .await?;
        assert!(returned(&response)?.strict_equals(&original));
        assert_eq!(fixture.context.base_url(), PRODUCTION);
    }
    let bytes = serde_json::to_vec(&serde_json::json!({"url": URL}))?;
    let mut response = AuthResponse::new(201).with_header("x-proxy", "explicit");
    response.body = ResponseBody::Bytes(bytes.clone());
    plugin()
        .after_request(&request(), &mut response, &fixture.context)
        .await?;
    assert!(!response.is_native());
    assert_eq!(response.status, 201);
    assert_eq!(response.body.bytes()?.as_ref(), bytes);
    assert_eq!(
        response.headers.get("x-proxy").map(String::as_str),
        Some("explicit")
    );
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert!(fixture.logs.0.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn native_api_error_body_url_is_not_an_error_object_url() -> AuthResult<()> {
    let fixture = Fixture::new(OAuthStateStrategy::Database, true, None, false).await?;
    let original = object(URL.into());
    let error: AuthError = AuthResponse::native(400, original.clone()).into();
    let mut response = error.to_auth_response().expect("fixture response succeeds");
    let before = fixture.store.storage_rows(EntityRole::Verification)?;
    plugin()
        .after_request(&request(), &mut response, &fixture.context)
        .await?;
    assert!(response.is_api_error().unwrap());
    assert_eq!(
        response.api_error_status()?,
        better_auth_core::SchemaValue::Typed(400)
    );
    assert!(response.api_error_body()?.strict_equals(&original));
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.storage_rows(EntityRole::Verification)?,
        before
    );
    assert!(fixture.logs.0.lock().unwrap().is_empty());
    Ok(())
}
