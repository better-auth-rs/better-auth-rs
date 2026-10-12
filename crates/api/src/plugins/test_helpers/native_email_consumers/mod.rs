//! Replay native email consumers through shared descriptor observations and production endpoint dispatch.

#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "Frozen contracts require complete source fields and fail at the first observation mismatch."
)]

use super::native_observation as native_test_observation;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldDate, FieldMap, FieldProperty, FieldValue,
};
use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, MutexGuard},
};

mod endpoint;
mod errors;
mod fixture;
mod values;

#[path = "../../../../../../tests/support/native_property_graph.rs"]
mod property_graph;
use property_graph::PropertyGraph;

pub(crate) use endpoint::{memory_from_capture, memory_snapshot, native_request};
pub(crate) use fixture::fixture;
pub(crate) use values::{native_lower, native_user, throwing_value};

pub(crate) const NOW: i64 = 2_000_000_000_000;
pub(crate) const ORIGIN: &str = "https://native-email-consumers.test";
pub(crate) const SECRET: &str =
    "native-email-consumers-contract-secret-at-least-thirty-two-characters";
pub(crate) const OWNER_EMAIL: &str = "owner@native-email-consumers.test";

pub(crate) fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Native email contract state is poisoned"))
}

pub(crate) fn clock() -> AuthResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(NOW)
        .ok_or_else(|| AuthError::internal("Native email contract clock is invalid"))
}

pub(crate) fn date(milliseconds: i64) -> FieldValue {
    FieldDate::from_milliseconds(milliseconds as f64).into()
}

pub(crate) fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .disable_session_refresh(true);
    config.telemetry.enabled = false;
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config
}

#[derive(Default)]
struct Progress {
    graph: PropertyGraph,
    event: usize,
    unpaired: Vec<String>,
}

pub(crate) struct Trace {
    pub(crate) case: Json,
    path: String,
    unpaired_events: BTreeSet<usize>,
    progress: Mutex<Progress>,
}

impl Trace {
    pub(crate) fn new(case: &Json, path: impl Into<String>) -> Arc<Self> {
        Self::with_unpaired_events(case, path, &[])
    }

    pub(crate) fn with_unpaired_events(
        case: &Json,
        path: impl Into<String>,
        unpaired_events: &[usize],
    ) -> Arc<Self> {
        let indices: BTreeSet<_> = unpaired_events.iter().copied().collect();
        assert_eq!(indices.len(), unpaired_events.len());
        for index in &indices {
            assert!(
                case["events"].get(*index).is_some(),
                "Unpaired event must exist in the frozen capture"
            );
        }
        Arc::new(Self {
            case: case.clone(),
            path: path.into(),
            unpaired_events: indices,
            progress: Mutex::default(),
        })
    }

    pub(crate) fn snapshot(&self, field: &str, actual: &FieldValue) -> AuthResult<()> {
        let expected = self
            .case
            .get(field)
            .ok_or_else(|| AuthError::internal(format!("Native email capture lacks {field}")))?;
        lock(&self.progress)?.graph.assert_snapshot(
            actual,
            expected,
            &format!("{}/{field}", self.path),
        )
    }

    pub(crate) fn record(&self, phase: &str, fields: FieldMap) -> AuthResult<()> {
        let mut progress = lock(&self.progress)?;
        self.advance_unpaired_events(&mut progress);
        let index = progress.event;
        let expected = self.case["events"]
            .as_array()
            .and_then(|events| events.get(index))
            .and_then(Json::as_object)
            .ok_or_else(|| {
                AuthError::internal(format!("Unexpected native email event: {phase}"))
            })?;
        let mut actual = FieldMap::from([("phase".into(), phase.into())]);
        actual.extend(fields);
        let path = format!("{}/events/{index}", self.path);
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{path}: complete event fields"
        );
        for ((key, actual), expected) in actual.iter().zip(expected.values()) {
            progress
                .graph
                .assert_snapshot(actual, expected, &format!("{path}/{key}"))?;
        }
        progress.event += 1;
        Ok(())
    }

    pub(crate) fn call(
        &self,
        phase: &str,
        receiver: &FieldValue,
        expected: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<()> {
        self.record(
            phase,
            FieldMap::from([
                (
                    "sameReceiver".into(),
                    receiver.strict_equals(expected).into(),
                ),
                ("arguments".into(), arguments.to_vec().into()),
            ]),
        )
    }

    pub(crate) fn outcome(
        &self,
        result: AuthResult<FieldValue>,
        original: &FieldValue,
    ) -> AuthResult<FieldValue> {
        let expected = &self.case["outcome"];
        let path = format!("{}/outcome", self.path);
        let mut progress = lock(&self.progress)?;
        match result {
            Ok(value) => {
                assert_eq!(expected["returned"], true, "{path}");
                assert_eq!(
                    expected.as_object().map(|fields| fields.len()),
                    Some(2),
                    "{path}"
                );
                progress.graph.assert_snapshot(
                    &value,
                    &expected["result"],
                    &format!("{path}/result"),
                )?;
                Ok(value)
            }
            Err(error) => {
                assert_eq!(expected["returned"], false, "{path}");
                assert_eq!(
                    expected.as_object().map(|fields| fields.len()),
                    Some(3),
                    "{path}"
                );
                errors::assert_error(&mut progress, error, original, expected, &path)?;
                Ok(FieldValue::Undefined)
            }
        }
    }

    pub(crate) fn finish(&self) -> AuthResult<Vec<String>> {
        let mut progress = lock(&self.progress)?;
        self.advance_unpaired_events(&mut progress);
        let events = self.case["events"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Native email capture events are missing"))?;
        assert_eq!(
            progress.event,
            events.len(),
            "{}: complete event order",
            self.path
        );
        let mut unpaired = std::mem::take(&mut progress.graph).finish(
            Some(&self.case["functions"]),
            &format!("{}/functions", self.path),
        );
        unpaired.extend(std::mem::take(&mut progress.unpaired));
        unpaired.sort();
        Ok(unpaired)
    }

    fn advance_unpaired_events(&self, progress: &mut Progress) {
        while self.unpaired_events.contains(&progress.event) {
            progress
                .unpaired
                .push(format!("{}/events/{}", self.path, progress.event));
            progress.event += 1;
        }
    }
}
