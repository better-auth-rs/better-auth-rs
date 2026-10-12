#![expect(
    clippy::panic_in_result_fn,
    reason = "The regression checks conversion order, branch values, and original error identity while setup errors propagate."
)]

use super::*;
use crate::{FieldFunction, FieldMap, FieldObject, FromFieldMap};
use std::sync::{Arc, Mutex, MutexGuard};

fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Rate-limit observation lock poisoned"))
}

#[derive(Default)]
struct Probe {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Probe {
    fn value(
        &self,
        name: &'static str,
        values: Vec<FieldValue>,
        failure: Option<(usize, FieldValue)>,
    ) -> AuthResult<FieldValue> {
        let object = FieldObject::from(FieldMap::new());
        let identity = object.identity();
        let events = self.events.clone();
        let calls = Mutex::new(0);
        object.set(
            "valueOf",
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(arguments.is_empty());
                assert!(
                    matches!(receiver, FieldValue::Object(value) if value.identity() == identity)
                );
                lock(&events)?.push(name);
                let mut calls = lock(&calls)?;
                let index = *calls;
                *calls += 1;
                if let Some((at, original)) = &failure
                    && index == *at
                {
                    return Err(AuthError::from_thrown(original.clone()));
                }
                values
                    .get(index)
                    .cloned()
                    .ok_or_else(|| AuthError::internal("Unexpected primitive conversion"))
            })
            .into(),
        )?;
        Ok(object.into())
    }
}

fn row(window: FieldValue, count: FieldValue, maximum: FieldValue) -> AuthResult<ApiKey> {
    ApiKey::from_field_values(
        [
            ("rateLimitEnabled".into(), true.into()),
            ("rateLimitTimeWindow".into(), window),
            ("requestCount".into(), count),
            ("rateLimitMax".into(), maximum),
            (
                "lastRequest".into(),
                FieldDate::from_milliseconds(0.0).into(),
            ),
        ]
        .into(),
    )
}

fn now() -> AuthResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(1_000).ok_or_else(|| AuthError::internal("Invalid fixed clock"))
}

#[test]
fn omitted_and_null_request_times_keep_distinct_conversion_boundaries() -> AuthResult<()> {
    let probe = Probe::default();
    let original = FieldValue::from(FieldMap::from([("cause".into(), "window".into())]));
    let window = probe.value("window", Vec::new(), Some((0, original.clone())))?;
    let mut key = row(window, 1.0.into(), 3.0.into())?;
    key.last_request = crate::SchemaValue::from_field(FieldValue::Null);
    assert!(matches!(
        ApiKeyRateLimitDecision::evaluate(&key, true, now()?)?,
        ApiKeyRateLimitDecision::Start {
            previous_before: None,
            ..
        }
    ));
    assert!(lock(&probe.events)?.is_empty());
    key.last_request = crate::SchemaValue::from_field(FieldValue::Undefined);
    let error = ApiKeyRateLimitDecision::evaluate(&key, true, now()?)
        .err()
        .ok_or_else(|| {
            AuthError::internal("An omitted previous request must compare the window")
        })?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&original))
    );
    assert_eq!(*lock(&probe.events)?, ["window"]);
    Ok(())
}

#[test]
fn every_numeric_expression_observes_the_current_window_primitive() -> AuthResult<()> {
    for branch in ["reset", "deny", "increment"] {
        let probe = Probe::default();
        let window = probe.value(
            "window",
            vec![
                if branch == "reset" { 100.0 } else { 2_000.0 }.into(),
                3_500.0.into(),
            ],
            None,
        )?;
        let count = probe.value("count", vec![2.0.into()], None)?;
        let maximum = probe.value(
            "maximum",
            vec![if branch == "increment" { 3.0 } else { 2.0 }.into()],
            None,
        )?;
        let key = row(window.clone(), count, maximum.clone())?;
        let decision = ApiKeyRateLimitDecision::evaluate(&key, true, now()?)?;
        match (branch, decision) {
            (
                "reset",
                ApiKeyRateLimitDecision::Start {
                    previous_before: Some(cutoff),
                    at,
                },
            ) => {
                assert_eq!(cutoff.milliseconds(), -2_500.0);
                assert_eq!(at, now()?);
            }
            ("deny", ApiKeyRateLimitDecision::Deny { try_again_in }) => {
                assert_eq!(try_again_in, 2_500.0);
            }
            (
                "increment",
                ApiKeyRateLimitDecision::Increment {
                    previous_after,
                    maximum: actual,
                    at,
                },
            ) => {
                assert_eq!(previous_after.milliseconds(), -2_500.0);
                assert!(actual.strict_equals(&maximum));
                assert_eq!(at, now()?);
            }
            _ => return Err(AuthError::internal("Unexpected rate-limit branch")),
        }
        assert!(
            key.rate_limit_time_window
                .field_value()
                .strict_equals(&window)
        );
        assert_eq!(
            *lock(&probe.events)?,
            if branch == "reset" {
                vec!["window", "window"]
            } else {
                vec!["window", "count", "maximum", "window"]
            }
        );
    }
    Ok(())
}

#[test]
fn numeric_failures_stop_at_their_expression_and_retain_original_identity() -> AuthResult<()> {
    for failed in ["first-window", "count", "maximum", "second-window"] {
        let probe = Probe::default();
        let original = FieldValue::from(FieldMap::from([("cause".into(), failed.into())]));
        let window = probe.value(
            "window",
            vec![2_000.0.into(), 3_500.0.into()],
            match failed {
                "first-window" => Some((0, original.clone())),
                "second-window" => Some((1, original.clone())),
                _ => None,
            },
        )?;
        let count = probe.value(
            "count",
            vec![2.0.into()],
            (failed == "count").then(|| (0, original.clone())),
        )?;
        let maximum = probe.value(
            "maximum",
            vec![3.0.into()],
            (failed == "maximum").then(|| (0, original.clone())),
        )?;
        let error = ApiKeyRateLimitDecision::evaluate(&row(window, count, maximum)?, true, now()?)
            .err()
            .ok_or_else(|| AuthError::internal("The selected primitive conversion must fail"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&original))
        );
        assert_eq!(
            *lock(&probe.events)?,
            match failed {
                "first-window" => vec!["window"],
                "count" => vec!["window", "count"],
                "maximum" => vec!["window", "count", "maximum"],
                _ => vec!["window", "count", "maximum", "window"],
            }
        );
    }
    Ok(())
}
