#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Frozen cases define complete records, outcomes, callback events, and descriptor graphs."
)]

use super::lock;
use better_auth_core::{
    ApiKey, AuthError, AuthRecordFields, AuthResult, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldProperty, FieldValue, FromFieldMap, store::ApiKeyRateLimitDecision,
};
use chrono::{DateTime, Utc};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::plugins::test_helpers::native_observation as native_test_observation;
use native_test_observation::assert_replay;

#[path = "rate_limit_contract_backends.rs"]
mod backends;
#[path = "../../../../../../../tests/support/native_property_graph.rs"]
mod property_graph;
use property_graph::PropertyGraph;

const NOW: i64 = 2_000_000_000_000;
const SCENARIOS: [&str; 15] = [
    "skip-global",
    "skip-key",
    "skip-null-window",
    "skip-null-maximum",
    "start-null",
    "absent-last",
    "reset",
    "deny",
    "increment",
    "first-window-failure",
    "count-failure",
    "maximum-failure",
    "second-window-failure",
    "reset-second-window-failure",
    "deny-second-window-failure",
];

fn clock() -> AuthResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(NOW)
        .ok_or_else(|| AuthError::internal("The frozen rate-limit clock is invalid"))
}

fn seed() -> FieldMap {
    FieldMap::from([
        ("id".into(), "usage-key".into()),
        ("name".into(), "Usage key".into()),
        ("start".into(), FieldValue::Null),
        ("prefix".into(), FieldValue::Null),
        ("key".into(), "usage-secret".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        ("refillInterval".into(), FieldValue::Null),
        ("refillAmount".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("enabled".into(), true.into()),
        ("rateLimitEnabled".into(), true.into()),
        ("rateLimitTimeWindow".into(), 2_000.0.into()),
        ("rateLimitMax".into(), 3.0.into()),
        ("requestCount".into(), 2.0.into()),
        ("remaining".into(), 3.0.into()),
        (
            "lastRequest".into(),
            FieldDate::from_milliseconds((NOW - 1_000) as f64).into(),
        ),
        ("expiresAt".into(), FieldValue::Null),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds((NOW - 60_000) as f64).into(),
        ),
        (
            "updatedAt".into(),
            FieldDate::from_milliseconds((NOW - 60_000) as f64).into(),
        ),
        ("permissions".into(), FieldValue::Null),
        ("metadata".into(), FieldValue::Null),
    ])
}

struct State {
    original: FieldValue,
    receivers: Mutex<FieldMap>,
    events: Mutex<Vec<FieldMap>>,
}

impl State {
    fn primitive(
        self: &Arc<Self>,
        label: &'static str,
        values: Vec<f64>,
        failure: Option<usize>,
    ) -> AuthResult<FieldValue> {
        let object = FieldObject::from(FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let state = Arc::downgrade(self);
                let calls = AtomicUsize::new(0);
                move |receiver, arguments| {
                    let state = state
                        .upgrade()
                        .ok_or_else(|| AuthError::internal("Rate-limit observer was released"))?;
                    let same = receiver.strict_equals(
                        lock(&state.receivers)?
                            .get(label)
                            .ok_or_else(|| AuthError::internal("Missing primitive receiver"))?,
                    );
                    lock(&state.events)?.push(FieldMap::from([
                        ("phase".into(), label.into()),
                        ("sameReceiver".into(), same.into()),
                        ("arguments".into(), arguments.to_vec().into()),
                    ]));
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    if Some(call) == failure {
                        return Err(AuthError::from_thrown(state.original.clone()));
                    }
                    values
                        .get(call)
                        .copied()
                        .map(Into::into)
                        .ok_or_else(|| AuthError::internal("Unexpected primitive conversion"))
                }
            })
            .into(),
        )]));
        let value = FieldValue::from(object);
        let _ = lock(&self.receivers)?.insert(label.into(), value.clone());
        Ok(value)
    }
}

struct Scenario {
    state: Arc<State>,
    key: ApiKey,
    enabled: bool,
}

impl Scenario {
    fn new(name: &str) -> AuthResult<Self> {
        let state = Arc::new(State {
            original: FieldMap::from([("cause".into(), name.into())]).into(),
            receivers: Mutex::new(FieldMap::new()),
            events: Mutex::new(Vec::new()),
        });
        let mut fields = seed();
        let failure = if matches!(name, "first-window-failure" | "start-null") {
            Some(0)
        } else if name.contains("second-window-failure") {
            Some(1)
        } else {
            None
        };
        fields.extend([
            (
                "rateLimitTimeWindow".into(),
                state.primitive(
                    "window",
                    vec![
                        if name.starts_with("reset") {
                            100.0
                        } else {
                            2_000.0
                        },
                        3_500.0,
                    ],
                    failure,
                )?,
            ),
            (
                "requestCount".into(),
                state.primitive(
                    "count",
                    vec![2.0, 4.0],
                    (name == "count-failure").then_some(0),
                )?,
            ),
            (
                "rateLimitMax".into(),
                state.primitive(
                    "maximum",
                    vec![if name.starts_with("deny") { 2.0 } else { 3.0 }],
                    (name == "maximum-failure").then_some(0),
                )?,
            ),
        ]);
        match name {
            "skip-key" => {
                let _ = fields.insert("rateLimitEnabled".into(), false.into());
            }
            "skip-null-window" => {
                let _ = fields.insert("rateLimitTimeWindow".into(), FieldValue::Null);
            }
            "skip-null-maximum" => {
                let _ = fields.insert("rateLimitMax".into(), FieldValue::Null);
            }
            "start-null" => {
                let _ = fields.insert("lastRequest".into(), FieldValue::Null);
            }
            "absent-last" => {
                let _ = fields.remove("lastRequest");
            }
            _ => {}
        }
        Ok(Self {
            state,
            key: ApiKey::from_field_values(fields)?,
            enabled: name != "skip-global",
        })
    }
}

fn decision_value(decision: ApiKeyRateLimitDecision) -> FieldValue {
    match decision {
        ApiKeyRateLimitDecision::Skip(last) => FieldMap::from([
            ("type".into(), "skip".into()),
            (
                "lastRequest".into(),
                last.map_or(FieldValue::Null, Into::into),
            ),
        ]),
        ApiKeyRateLimitDecision::Deny { try_again_in } => FieldMap::from([
            ("type".into(), "deny".into()),
            ("message".into(), "Rate limit exceeded.".into()),
            ("tryAgainIn".into(), try_again_in.into()),
        ]),
        ApiKeyRateLimitDecision::Start {
            previous_before,
            at,
        } => {
            let mut fields = FieldMap::from([
                (
                    "type".into(),
                    if previous_before.is_some() {
                        "reset"
                    } else {
                        "start"
                    }
                    .into(),
                ),
                ("now".into(), at.into()),
            ]);
            if let Some(before) = previous_before {
                let _ = fields.insert("windowStart".into(), before.into());
            }
            fields
        }
        ApiKeyRateLimitDecision::Increment {
            previous_after,
            maximum,
            at,
        } => FieldMap::from([
            ("type".into(), "increment".into()),
            ("now".into(), at.into()),
            ("max".into(), maximum),
            ("windowStart".into(), previous_after.into()),
        ]),
    }
    .into()
}

fn outcome(
    graph: &mut PropertyGraph,
    result: AuthResult<FieldValue>,
    original: &FieldValue,
    expected: &Json,
    path: &str,
) -> AuthResult<()> {
    match result {
        Ok(value) => {
            assert_eq!(
                expected
                    .as_object()
                    .map(|value| value.keys().map(String::as_str).collect::<Vec<_>>()),
                Some(vec!["returned", "result"]),
                "{path}"
            );
            assert_eq!(expected["returned"], true, "{path}");
            graph.assert_snapshot(&value, &expected["result"], &format!("{path}/result"))?;
        }
        Err(error) => {
            assert_eq!(
                expected
                    .as_object()
                    .map(|value| value.keys().map(String::as_str).collect::<Vec<_>>()),
                Some(vec!["returned", "sameOriginal", "error"]),
                "{path}"
            );
            let value = error.into_thrown_value()?;
            assert_eq!(expected["returned"], false, "{path}");
            assert_eq!(
                expected["sameOriginal"],
                value.strict_equals(original),
                "{path}"
            );
            graph.assert_snapshot(&value, &expected["error"], &format!("{path}/error"))?;
        }
    }
    Ok(())
}

fn events(graph: &mut PropertyGraph, state: &State, expected: &Json, path: &str) -> AuthResult<()> {
    let actual = lock(&state.events)?;
    let expected = expected
        .as_array()
        .ok_or_else(|| AuthError::internal("Frozen rate-limit events missing"))?;
    assert_eq!(actual.len(), expected.len(), "{path}");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let expected = expected
            .as_object()
            .ok_or_else(|| AuthError::internal("Frozen rate-limit event missing"))?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{path}/{index}"
        );
        for ((key, actual), expected) in actual.iter().zip(expected.values()) {
            graph.assert_snapshot(actual, expected, &format!("{path}/{index}/{key}"))?;
        }
    }
    Ok(())
}

fn pure(case: &Json, graph: &mut PropertyGraph, path: &str) -> AuthResult<Vec<String>> {
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing rate-limit name"))?;
    let scenario = Scenario::new(name)?;
    graph.assert_snapshot(
        &scenario.key.field_values()?.into(),
        &case["before"],
        &format!("{path}/before"),
    )?;
    let mut unpaired = Vec::new();
    let result = if case["boundary"] == "evaluateRateLimit" {
        ApiKeyRateLimitDecision::evaluate(&scenario.key, scenario.enabled, clock()?)
            .map(decision_value)
    } else {
        match super::super::apply_rate_limit_to_snapshot(&scenario.key, scenario.enabled, clock()?)
        {
            Ok(super::super::RateLimitSnapshot::Changes(changes)) => Ok(changes.into()),
            Ok(super::super::RateLimitSnapshot::RateLimited { try_again_in }) => {
                assert_eq!(name, "deny");
                assert_eq!(try_again_in, 2_500.0);
                assert_eq!(case["outcome"]["returned"], false);
                assert_eq!(case["outcome"]["sameOriginal"], false);
                unpaired.push(format!("{path}/outcome/error"));
                Ok(FieldValue::Undefined)
            }
            Err(error) => Err(error),
        }
    };
    let maximum_identity = result.as_ref().ok().and_then(|value| {
        if value
            .model_property("type")
            .ok()?
            .strict_equals(&"increment".into())
        {
            Some(
                value
                    .model_property("max")
                    .ok()?
                    .strict_equals(&scenario.key.rate_limit_max.field_value()),
            )
        } else {
            None
        }
    });
    assert_eq!(
        case["maximumIdentity"],
        maximum_identity.map_or(Json::Null, Into::into)
    );
    if unpaired.is_empty() {
        outcome(
            graph,
            result,
            &scenario.state.original,
            &case["outcome"],
            &format!("{path}/outcome"),
        )?;
    }
    graph.assert_snapshot(
        &scenario.key.field_values()?.into(),
        &case["after"],
        &format!("{path}/after"),
    )?;
    events(
        graph,
        &scenario.state,
        &case["events"],
        &format!("{path}/events"),
    )?;
    Ok(unpaired)
}

#[tokio::test]
async fn rate_limit_native_frozen_contract() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-rate-limit-native-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "api-key-rate-limit-native");
    assert_replay(&json!(SCENARIOS), &fixture["scenarios"], "/scenarios");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Frozen rate-limit cases missing"))?;
    assert_eq!(cases.len(), 33);
    let mut unpaired = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let path = format!("/cases/{index}");
        let mut graph = PropertyGraph::default();
        if index < 30 {
            assert_eq!(case["name"], SCENARIOS[index % 15]);
            assert_eq!(
                case["boundary"],
                if index < 15 {
                    "evaluateRateLimit"
                } else {
                    "applyRateLimitToSnapshot"
                }
            );
            unpaired.extend(pure(case, &mut graph, &path)?);
        } else if index == 30 {
            backends::database(case, &mut graph, &path).await?;
        } else {
            backends::secondary(case, &mut graph, &path).await?;
        }
        unpaired.extend(graph.finish(None, &path));
    }
    let ledger: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-rate-limit-native-coverage.json"
    )))?;
    assert_replay(
        &json!(unpaired),
        &ledger["unpairedPaths"],
        "/coverage/unpairedPaths",
    );
    Ok(())
}
