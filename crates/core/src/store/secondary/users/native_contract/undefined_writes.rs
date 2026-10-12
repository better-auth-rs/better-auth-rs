#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::observability::{LogArgument, LogLevel, LogSink};
use values::Root;

mod storage;
use storage::NativeStorage;

fn reference(token: &str, expiration: i64) -> FieldValue {
    FieldMap::from([
        ("token".into(), token.into()),
        ("expiresAt".into(), (NOW + expiration).into()),
        (
            "extra".into(),
            FieldMap::from([("retained".into(), token.into())]).into(),
        ),
    ])
    .into()
}

fn roots(scenario: &Json, observer: &Observer) -> AuthResult<(FieldMap, Vec<Root>)> {
    let index = Root::new("function", 0, observer.clone());
    let filtered = Root::new("function", 0, observer.clone());
    let sorted = Root::new("array", 0, observer.clone());
    let result = if scenario["result"] == "function" {
        FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into()
    } else {
        FieldValue::Undefined
    };
    let to_json_result = result.clone();
    let events = observer.clone();
    sorted.method("toJSON", move |arguments| {
        assert_eq!(arguments, &[FieldValue::from("")]);
        let mut events = events.lock().unwrap();
        let value = events.observe(&to_json_result)?;
        events.record("toJSON:result", [("value".into(), value)]);
        Ok(to_json_result.clone())
    });
    let references = if scenario["operation"] == "batch-delete" {
        vec![reference("concurrent", 180_000)]
    } else {
        vec![reference("target", 60_000), reference("retained", 90_000)]
    };
    let is_update = scenario["operation"] == "update";
    let returned = if is_update {
        filtered.value.clone()
    } else {
        sorted.value.clone()
    };
    let sorted_array = sorted.value.as_array().unwrap().clone();
    let index_receiver = index.receiver();
    let events = observer.clone();
    index.method("filter", move |arguments| {
        let [FieldValue::Function(predicate)] = arguments else {
            return Err(AuthError::internal(
                "Native filter must receive its predicate",
            ));
        };
        let index_receiver = index_receiver.upgrade().unwrap();
        let keep = references
            .iter()
            .enumerate()
            .map(|(offset, value)| {
                predicate.call_with(
                    &"ignored receiver".into(),
                    &[
                        value.clone(),
                        offset.into(),
                        index_receiver.get().unwrap().clone(),
                    ],
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        {
            let mut events = events.lock().unwrap();
            let results = events.observe(&keep.clone().into())?;
            events.record("filter:predicate", [("results".into(), results)]);
        }
        for (value, keep) in references.iter().zip(keep) {
            if keep.is_truthy() {
                sorted_array.set(sorted_array.len()?, value.clone())?;
            }
        }
        Ok(returned.clone())
    });
    if is_update {
        let returned = sorted.value.clone();
        filtered.method("concat", move |arguments| {
            let [FieldValue::Array(additions)] = arguments else {
                return Err(AuthError::internal(
                    "Native concat must receive its additions",
                ));
            };
            let sorted = returned.as_array().unwrap();
            for value in additions.iter()? {
                sorted.set(sorted.len()?, value?)?;
            }
            Ok(returned.clone())
        });
    }
    let roots = FieldMap::from([
        ("index".into(), index.value.clone()),
        ("filtered".into(), filtered.value.clone()),
        ("sorted".into(), sorted.value.clone()),
        ("toJSONResult".into(), result),
    ]);
    Ok((roots, vec![index, filtered, sorted]))
}

struct Logger {
    observer: Observer,
    original: FieldValue,
}

impl LogSink for Logger {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Error(error) => error
                    .downcast_ref::<AuthError>()
                    .unwrap()
                    .raw_value()
                    .unwrap()
                    .clone(),
                LogArgument::Native(value) => (*value).clone(),
                LogArgument::Value(value) => FieldValue::from((*value).clone()),
                LogArgument::Text(value) => FieldValue::from(*value),
            })
            .collect();
        let same_original = arguments
            .iter()
            .any(|value| value.strict_equals(&self.original));
        let mut observer = self.observer.lock().unwrap();
        let arguments = observer.observe(&arguments.into()).unwrap();
        observer.record(
            "logger",
            [
                ("level".into(), level.as_str().into()),
                ("message".into(), message.to_string().into()),
                ("arguments".into(), arguments),
                ("sameOriginal".into(), same_original.into()),
            ],
        );
        Ok(())
    }
}

async fn capture(scenario: &Json, synchronous_storage: bool) -> AuthResult<Json> {
    let observer = Observer::default();
    let original: FieldValue = FieldMap::from([
        ("rejected".into(), scenario["name"].as_str().unwrap().into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    let (roots, _held_roots) = roots(scenario, &observer)?;
    let cache = Arc::new(NativeStorage::new(
        scenario,
        &roots,
        &original,
        observer.clone(),
        synchronous_storage,
    )?);
    let initial_index = cache.value(INDEX);
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(true);
    config.logger = crate::LoggerConfig {
        level: Some(LogLevel::Debug),
        log: Some(Arc::new(Logger {
            observer: observer.clone(),
            original: original.clone(),
        })),
        ..Default::default()
    }
    .into();
    config
        .initialize_logger()
        .expect("fixture initialization succeeds");
    let config = Arc::new(config);
    let inner = Arc::new(
        EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), vec![user()]),
                (
                    "session".into(),
                    vec![session("target", 60_000), session("retained", 90_000)],
                ),
                ("account".into(), Vec::new()),
                ("verification".into(), Vec::new()),
            ],
        )?
        .with_hooks(vec![Arc::new(Hooks(observer.clone()))]),
    );
    let store = SecondaryStore::new(inner.clone(), cache.clone(), config, Default::default())?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    let before = cache.snapshot(&inner, &roots, None)?;
    let (input, result) = match scenario["operation"].as_str().unwrap() {
        "update" => (
            FieldMap::from([
                ("token".into(), "target".into()),
                ("data".into(), values::patch().into()),
            ]),
            store
                .update_session_fields("target", values::patch())
                .await
                .map(|value| value.map_or(FieldValue::Null, |value| FieldMap::from(value).into())),
        ),
        "delete" => (
            FieldMap::from([("token".into(), "target".into())]),
            store
                .delete_session("target")
                .await
                .map(|()| FieldValue::Undefined),
        ),
        "batch-delete" => (
            FieldMap::from([("userId".into(), "owner".into())]),
            store
                .delete_user_sessions("owner")
                .await
                .map(|()| FieldValue::Undefined),
        ),
        _ => return Err(AuthError::internal("Unknown native write operation")),
    };
    let outcome = observer.lock().unwrap().outcome(result, &original)?;
    let after = cache.snapshot(&inner, &roots, Some(&initial_index))?;
    let mut observer = observer.lock().unwrap();
    let input = observer.observe(&input.into())?;
    Ok(
        json!({"input":input,"before":before,"outcome":outcome,"events":observer.events,
        "after":after,"functionIds":observer.function_ids()}),
    )
}

#[tokio::test]
async fn session_undefined_writes_match_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/secondary-native-write-undefined-1.7.6.json");
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap())?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases: Vec<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["scenario"]["domain"] == "session")
        .collect();
    assert_eq!(cases.len(), 12);
    for case in cases {
        for synchronous_storage in [false, true] {
            let actual = capture(&case["scenario"], synchronous_storage).await?;
            let label = format!(
                "{}/synchronous={synchronous_storage}",
                case["scenario"]["name"].as_str().unwrap()
            );
            assert_replay(&actual, &case["runtime"], &label);
        }
    }
    Ok(())
}
