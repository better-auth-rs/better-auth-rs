#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::observability::{LogArgument, LogLevel, LogSink};
use crate::{AuthConfig, AuthContext, store::EphemeralStore};
use parking_lot::Mutex;
use serde_json::{Value as Json, json};

#[path = "native_contract/inputs.rs"]
mod inputs;
use crate::native_test_observation as observation;
#[path = "native_contract/properties.rs"]
mod properties;

use observation::{NativeObservation, assert_replay};

type Observer = Arc<Mutex<NativeObservation>>;
const ISO: &str = "2030-01-02T03:04:05.000Z";

struct Log {
    level: LogLevel,
    message: String,
    arguments: Vec<Option<FieldValue>>,
}

#[derive(Default)]
struct Sink {
    logs: Mutex<Vec<Log>>,
    failure: Option<FieldValue>,
}

impl LogSink for Sink {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        self.logs.lock().push(Log {
            level,
            message: message.to_string(),
            arguments: arguments
                .iter()
                .map(|argument| match argument {
                    LogArgument::Native(value) => Some((*value).clone()),
                    _ => None,
                })
                .collect(),
        });
        match &self.failure {
            Some(failure) => Err(AuthError::from_thrown(failure.clone())),
            None => Ok(()),
        }
    }
}

fn record_logs(sink: &Sink, observer: &Observer, original: &FieldValue) -> AuthResult<()> {
    for log in std::mem::take(&mut *sink.logs.lock()) {
        assert_eq!(log.level, LogLevel::Error);
        let argument = log
            .arguments
            .first()
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                AuthError::internal(
                    "safeJSONParse must log an object containing the original error",
                )
            })?;
        let error = argument.model_property("error")?;
        let same_original = error.strict_equals(original);
        let mut observer = observer.lock();
        let observed = if same_original {
            observer.observe(&error)?
        } else {
            json!({
                "name": observer.observe(&error.model_property("name")?)?,
                "message": observer.observe(&error.model_property("message")?)?,
                "properties": observer.observe(&error.enumerable_fields()?.into())?,
            })
        };
        observer.record(
            "logger:error",
            [
                ("message".into(), log.message.into()),
                ("argumentCount".into(), log.arguments.len().into()),
                ("argumentKeys".into(), keys(argument)?.into()),
                ("sameOriginal".into(), same_original.into()),
                ("error".into(), observed),
            ],
        );
    }
    Ok(())
}

fn keys(value: &FieldValue) -> AuthResult<Vec<String>> {
    value
        .own_property_keys()?
        .into_iter()
        .try_fold(Vec::new(), |mut keys, name| {
            if value
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
            {
                keys.push(name);
            }
            Ok(keys)
        })
}

fn optional_property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if value.is_null() || value.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        value.model_property(name)
    }
}

async fn run_case(name: &str) -> AuthResult<Json> {
    let observer = Observer::default();
    let input = inputs::Input::new(name, &observer)?;
    let sink = Arc::new(Sink {
        failure: (name == "logger-original-error").then(|| input.logger_failure.clone()),
        ..Default::default()
    });
    let mut config = AuthConfig {
        logger: crate::LoggerConfig {
            log: Some(sink.clone()),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    };
    config
        .initialize_logger()
        .expect("fixture initialization succeeds");
    let config = Arc::new(config);
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
        .expect("fixture context initializes");
    let parsed = context
        .with_endpoint_context(|_| async { safe_parse_field(&input.value) })
        .await;
    // Parser error logging is synchronous and terminal; observe the captured native arguments before the outcome.
    record_logs(&sink, &observer, &input.original)?;
    if name == "logger-original-error" {
        assert!(
            parsed
                .as_ref()
                .err()
                .and_then(AuthError::raw_value)
                .is_some_and(|failure| failure.strict_equals(&input.logger_failure))
        );
        assert!(
            input
                .value
                .model_property("mutation")?
                .strict_equals(&"retained-before-error".into())
        );
    }
    let result = parsed.as_ref().ok().cloned().unwrap_or_default();
    if name == "array-holes-and-undefined" {
        assert!(result.model_property("3")?.strict_equals(&input.date));
        assert!(result.model_property("4")?.strict_equals(&input.function));
        assert!(!result.has_property("ignoredNamedField")?);
    }
    if name == "object-native-children" {
        let nested = result.model_property("nested")?;
        assert!(nested.model_property("date")?.strict_equals(&input.date));
        assert!(nested.model_property("fn")?.strict_equals(&input.function));
    }
    let mut observer = observer.lock();
    let outcome = observer.outcome(parsed, &input.logger_failure)?;
    let identities = json!({
        "sameInput": result.strict_equals(&input.value),
        "sameCustomResult": input.custom_result.as_ref().is_some_and(|custom| result.strict_equals(custom)),
        "sameDateChild": optional_property(&result, "date")?.strict_equals(&input.date),
        "sameFunctionChild": optional_property(&result, "fn")?.strict_equals(&input.function),
    });
    let mut runtime = serde_json::Map::from_iter([
        ("outcome".into(), outcome),
        ("events".into(), observer.events.clone().into()),
        ("identities".into(), identities),
    ]);
    if input
        .custom_result
        .as_ref()
        .is_some_and(|custom| result.strict_equals(custom))
    {
        let _ = runtime.insert(
            "resultData".into(),
            observer.observe(&result.enumerable_fields()?.into())?,
        );
    }
    let _ = runtime.insert("inputKeysAfter".into(), keys(&input.value)?.into());
    let _ = runtime.insert(
        "mutation".into(),
        observer.observe(&input.value.model_property("mutation")?)?,
    );
    let _ = runtime.insert("functionIds".into(), observer.function_ids().into());
    Ok(runtime.into())
}

#[tokio::test]
async fn safe_json_native_runtime_matches_upstream() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/safe-json-native-1.7.6.json");
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).map_err(|error| {
        AuthError::internal(format!(
            "Cannot read safeJSONParse source observations: {error}"
        ))
    })?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    let cases = fixture
        .get("cases")
        .and_then(Json::as_array)
        .ok_or_else(|| AuthError::internal("safeJSONParse source cases are absent"))?;
    let mut paired = Vec::new();
    for case in cases {
        let name = case
            .get("name")
            .and_then(Json::as_str)
            .ok_or_else(|| AuthError::internal("safeJSONParse source case name is absent"))?;
        let expected = case
            .get("runtime")
            .ok_or_else(|| AuthError::internal("safeJSONParse runtime observation is absent"))?;
        assert_replay(&run_case(name).await?, expected, name);
        paired.push(name);
    }
    assert_eq!(
        paired,
        [
            "array-own-map-function-result",
            "array-own-map-object-result",
            "array-map-getter-error",
            "array-map-method-error",
            "array-map-noncallable",
            "array-holes-and-undefined",
            "object-key-snapshot-and-late-getters",
            "object-getter-error",
            "logger-original-error",
            "date-root-skips-properties",
            "function-root-skips-properties",
            "object-native-children",
        ]
    );
    Ok(())
}
