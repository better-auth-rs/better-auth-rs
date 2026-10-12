#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
// Full adapter/internal event traces remain unpaired. The observer documents separate JavaScript
// host metadata, header-symbol reflection, and typed callback representation boundaries.
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned endpoint contracts must fail immediately on invalid fixture shapes or missing observations."
)]

use super::*;
use crate::plugins::test_helpers::ReplayFailures;
use crate::plugins::test_helpers::{self, native_observation::NativeObservation, native_session};
use better_auth_core::{
    ApiErrorClass, AuthConfig, AuthPlugin, FieldDate, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    endpoint_input::ValidatedBody,
    id::{IdGeneration, IdGenerator},
    observability::{LogArgument, LogLevel, LogSink},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[path = "native_error_contract_observation.rs"]
mod observation;
#[path = "../../../../../tests/support/store_facade.rs"]
mod store_facade;
mod intercepted_store {
    super::store_facade::define_test_store!(
        "../core/src/store/mod.rs",
        "../core/src/store/runtime.rs"
    );
}

use intercepted_store::{StoreInterceptions, TestStore};

const NOW: i64 = 2_000_000_000_000;
const ORIGIN: &str = "http://passkey-native-errors.test";
const RP_ID: &str = "passkey-native-errors.test";
const SECRET: &str = "passkey-native-errors-secret-at-least-thirty-two-characters";

struct State {
    original: FieldValue,
    original_body: FieldValue,
    callback_failure: bool,
    verification: Mutex<Vec<Json>>,
    logs: Mutex<Vec<Json>>,
}

impl State {
    fn new(case: &Json) -> AuthResult<Self> {
        let name = case["name"].as_str().unwrap();
        let original_body: FieldValue = FieldMap::from([
            ("marker".into(), name.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
            (
                "message".into(),
                "Original verification callback failure".into(),
            ),
        ])
        .into();
        let original = if case["scenario"]["failure"] == "callback-api-error" {
            AuthError::from_status("CONFLICT", original_body.clone()).into_thrown_value()?
        } else {
            FieldMap::from([
                ("marker".into(), name.into()),
                ("ownUndefined".into(), FieldValue::Undefined),
                (
                    "nested".into(),
                    FieldMap::from([("retained".into(), true.into())]).into(),
                ),
            ])
            .into()
        };
        Ok(Self {
            original,
            original_body,
            callback_failure: matches!(
                case["scenario"]["failure"].as_str(),
                Some("callback-api-error" | "callback-object-error")
            ),
            verification: Mutex::default(),
            logs: Mutex::default(),
        })
    }
}

struct Callback(Arc<State>);

#[async_trait::async_trait]
impl PasskeyUserResolver for Callback {
    async fn resolve(
        &self,
        _: PasskeyEndpoint<'_>,
        _: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationUser> {
        Ok(PasskeyRegistrationUser {
            id: "owner".into(),
            name: "owner@passkey-native-errors.test".into(),
            display_name: Some("Owner".to_owned()).into(),
        })
    }
}

#[async_trait::async_trait]
impl PasskeyRegistrationHook for Callback {
    async fn after_verification(
        &self,
        _: PasskeyEndpoint<'_>,
        verification: &PasskeyRegistrationVerification,
        user: &PasskeyRegistrationUser,
        client_data: &Json,
        context: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationResult> {
        assert_eq!(user.id, "owner");
        assert_eq!(user.name, "owner@passkey-native-errors.test");
        assert_eq!(user.display_name, Some("Owner".to_owned()));
        assert!(context.is_none());
        self.0
            .verification
            .lock()
            .unwrap()
            .push(observation::registration(verification, client_data));
        if self.0.callback_failure {
            return Err(AuthError::from_thrown(self.0.original.clone()));
        }
        Ok(PasskeyRegistrationResult::default())
    }
}

#[async_trait::async_trait]
impl PasskeyAuthenticationHook for Callback {
    async fn after_verification(
        &self,
        _: PasskeyEndpoint<'_>,
        verification: &PasskeyAuthenticationVerification,
        client_data: &Json,
    ) -> AuthResult<()> {
        self.0
            .verification
            .lock()
            .unwrap()
            .push(observation::authentication(verification, client_data)?);
        if self.0.callback_failure {
            return Err(AuthError::from_thrown(self.0.original.clone()));
        }
        Ok(())
    }
}

struct Logger(Arc<State>);

impl LogSink for Logger {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        let values = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Native(value) => Ok((*value).clone()),
                LogArgument::Error(error) => {
                    observation::logged_error(error.downcast_ref::<AuthError>().unwrap())
                }
                _ => Err(AuthError::internal(
                    "Passkey error logs must retain native values",
                )),
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.0.logs.lock().unwrap().push(json!({
            "level":level.as_str(),
            "message":message.to_string(),
            "arguments":values.iter().map(observation::error).collect::<AuthResult<Vec<_>>>()?,
            "sameOriginal":values.iter().map(|value| value.strict_equals(&self.0.original)).collect::<Vec<_>>(),
        }));
        Ok(())
    }
}

fn tables(case: &Json) -> AuthResult<Vec<(String, Vec<FieldMap>)>> {
    let records = |value: &Json| {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                observation::revive(row)?
                    .as_object()
                    .unwrap()
                    .snapshot_fields()
            })
            .collect::<AuthResult<Vec<_>>>()
    };
    let challenge = if case["scenario"]["failure"] == "missing-challenge" {
        Vec::new()
    } else {
        vec![
            observation::revive(&case["input"]["challenge"])?
                .as_object()
                .unwrap()
                .snapshot_fields()?,
        ]
    };
    let passkey = if case["input"]["credential"].is_null() {
        Vec::new()
    } else {
        vec![
            observation::revive(&case["input"]["credential"])?
                .as_object()
                .unwrap()
                .snapshot_fields()?,
        ]
    };
    Ok(vec![
        ("user".into(), records(&case["runtime"]["before"]["user"])?),
        ("session".into(), Vec::new()),
        ("account".into(), Vec::new()),
        ("verification".into(), challenge),
        ("passkey".into(), passkey),
    ])
}

fn stored(store: &EphemeralStore) -> AuthResult<Json> {
    let mut observer = NativeObservation::default();
    let state: FieldValue = [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
        ("passkey", EntityRole::Passkey),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()?
    .into();
    observer.observe(&state)
}

async fn replay_case(case: &Json) -> AuthResult<(Json, Json)> {
    let state = Arc::new(State::new(case)?);
    let callback = Arc::new(Callback(state.clone()));
    let plugin = PasskeyPlugin::new()
        .rp_id(RP_ID)
        .rp_name("Native errors")
        .registration(PasskeyRegistrationOptions {
            require_session: false,
            resolve_user: Some(callback.clone()),
            after_verification: Some(callback.clone()),
            ..Default::default()
        })
        .authentication(PasskeyAuthenticationOptions {
            after_verification: Some(callback),
            ..Default::default()
        });
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.telemetry.enabled = false;
    config.session.disable_session_refresh = Some(true);
    let generated = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            let sequence = generated.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(Some(format!("{}-{sequence}", request.model)))
        })));
    config.logger = better_auth_core::LoggerConfig {
        level: Some(LogLevel::Error),
        log: Some(Arc::new(Logger(state.clone()))),
        ..Default::default()
    }
    .into();
    let failure = case["scenario"]["failure"].as_str().unwrap();
    let now = chrono::DateTime::from_timestamp_millis(NOW).unwrap();
    // The source freezes its process clock and forwards a token override before real session creation.
    let interceptions = StoreInterceptions {
        credential_query_error: (failure == "query-original").then(|| state.original.clone()),
        consume_verification_error_after: (failure == "consume-after-original")
            .then(|| state.original.clone()),
        passkey_update_error_after: (failure == "update-after-original")
            .then(|| state.original.clone()),
        null_session: failure == "null-session",
        missing_user: failure == "missing-user",
        session_overrides: FieldMap::from([
            (
                "token".into(),
                case["input"]["sessionToken"].as_str().unwrap().into(),
            ),
            ("createdAt".into(), now.into()),
            ("updatedAt".into(), now.into()),
            (
                "expiresAt".into(),
                (now + config.session.expires_in()).into(),
            ),
        ]),
    };
    let config = Arc::new(config);
    let store = Arc::new(EphemeralStore::from_storage(config.clone(), tables(case)?)?);
    let database = Arc::new(TestStore::new(store.clone(), interceptions));
    let mut context = test_helpers::initialize_test_context(config, database, &[&plugin])
        .await?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    context
        .extensions
        .insert(Arc::new(EndpointDispatcher::<StatelessSchema>::new(
            Arc::new(Vec::new()),
            Default::default(),
            AuthPlugin::<StatelessSchema>::routes(&plugin),
        )));
    let setup = if case["scenario"]["failure"] == "consumed-challenge" {
        context
            .database
            .consume_verification_by_identifier(
                case["input"]["challenge"]["identifier"].as_str().unwrap(),
            )
            .await?
            .map(|record| record.fields().map(FieldValue::from))
            .transpose()?
            .unwrap_or(FieldValue::Null)
    } else {
        FieldValue::Undefined
    };
    let setup = NativeObservation::default().observe(&setup)?;
    let before = stored(&store)?;
    let mut body = FieldMap::from([(
        "response".into(),
        observation::revive(&case["input"]["response"])?,
    )]);
    let path = if case["scenario"]["operation"] == "registration" {
        let _ = body.insert("name".into(), "Owner key".into());
        "/passkey/verify-registration"
    } else {
        "/passkey/verify-authentication"
    };
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    request.headers = case["input"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|header| {
            (
                header[0].as_str().unwrap().into(),
                header[1].as_str().unwrap().into(),
            )
        })
        .collect();
    request.set_endpoint_body(ValidatedBody::unvalidated_native(body.into()));
    let result = native_session::dispatch_plugin(&request, &context, &plugin).await;
    let error = result
        .err()
        .ok_or_else(|| AuthError::internal("Frozen failure returned successfully"))?;
    let outcome = observation::outcome(&error, &state)?;
    let after = stored(&store)?;
    let verification = case["runtime"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["phase"] == "verification")
        .map(|event| {
            assert_eq!(event["value"]["credentialPublicKeyIsUint8Array"], case["scenario"]["operation"] == "registration");
            json!({"verification":event["value"]["verification"],"clientData":event["value"]["clientData"]})
        })
        .collect::<Vec<_>>();
    let http = if error.is_api_error_instance(ApiErrorClass::BetterAuth) {
        let response = error.to_http_response()?;
        json!({
            "status":response.status,
            "body":serde_json::from_slice::<Json>(&response.body.bytes()?)?,
            "cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>(),
        })
    } else {
        Json::Null
    };
    let source_outcome = &case["runtime"]["outcome"];
    let source_http = if source_outcome["coreAPIError"] == true {
        json!({
            "status":source_outcome["error"]["properties"]["statusCode"],
            "body":observation::revive(&source_outcome["error"]["properties"]["body"])?.json()?.unwrap(),
            "cookies":[],
        })
    } else {
        Json::Null
    };
    Ok((
        json!({
            "setupConsumption":setup,
            "before":before,
            "outcome":outcome,
            "after":after,
            "verification":*state.verification.lock().unwrap(),
            "logs":*state.logs.lock().unwrap(),
            "publishedSession":request.new_session()?.is_some(),
            "http":http,
        }),
        json!({
            "setupConsumption":case["runtime"]["setupConsumption"],
            "before":case["runtime"]["before"],
            "outcome":observation::source_outcome(source_outcome),
            "after":case["runtime"]["after"],
            "verification":verification,
            "logs":observation::source_logs(&case["runtime"]["logs"]),
            "publishedSession":false,
            "http":source_http,
        }),
    ))
}

#[tokio::test]
async fn native_error_fixture_preserves_frozen_inputs_errors_and_complete_storage() -> AuthResult<()>
{
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/passkey-native-errors-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["contract"], "passkey-native-errors");
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (actual, expected) = replay_case(case).await?;
        failures.record(name, || {
            observation::assert_replay(&actual, &expected, name)
        });
    }
    failures.finish();
    Ok(())
}
