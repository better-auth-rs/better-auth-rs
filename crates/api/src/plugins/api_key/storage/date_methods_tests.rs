#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native method contract setup and frozen observations must remain valid."
)]

use super::*;
use async_trait::async_trait;
use better_auth_core::{FieldDate, FieldFunction, FieldObject};
use serde_json::json;
use std::sync::{Mutex, OnceLock, Weak};

use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};

mod create;
mod values;

type Observer = Arc<Mutex<NativeObservation>>;

struct Storage {
    entries: Mutex<Vec<(FieldValue, FieldValue)>>,
    observer: Observer,
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(key)?;
        observer.record("storage.get", [("key".into(), observed)]);
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|(stored, _)| stored.same_value_zero(key))
            .map(|(_, value)| value.clone()))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let key_observation = observer.observe(key)?;
        let value_observation = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map(FieldValue::from).unwrap_or_default())?;
        observer.record(
            "storage.set",
            [
                ("key".into(), key_observation),
                ("value".into(), value_observation),
                ("ttl".into(), ttl),
            ],
        );
        let mut entries = self.entries.lock().unwrap();
        if let Some((_, stored)) = entries
            .iter_mut()
            .find(|(stored, _)| stored.same_value_zero(key))
        {
            *stored = value.clone();
        } else {
            entries.push((key.clone(), value.clone()));
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.delete_native(&key.into()).await
    }

    async fn delete_native(&self, key: &FieldValue) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(key)?;
        observer.record("storage.delete", [("key".into(), observed)]);
        self.entries
            .lock()
            .unwrap()
            .retain(|(stored, _)| !stored.same_value_zero(key));
        Ok(())
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "API Key date methods do not consume atomic cache values",
        ))
    }
}

fn seed() -> FieldMap {
    FieldMap::from([
        ("id".into(), "method-key".into()),
        ("key".into(), "method-secret".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        ("createdAt".into(), FieldDate::from_milliseconds(0.0).into()),
        ("updatedAt".into(), FieldDate::from_milliseconds(0.0).into()),
        ("expiresAt".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("lastRequest".into(), FieldValue::Null),
        (
            "metadata".into(),
            FieldMap::from([("retained".into(), true.into())]).into(),
        ),
    ])
}

async fn run_case(scenario: &Value) -> AuthResult<Value> {
    let field = scenario["field"].as_str().unwrap();
    let mode = scenario["mode"].as_str().unwrap();
    let observer = Observer::default();
    let original: FieldValue =
        FieldMap::from([("cause".into(), "original date method failure".into())]).into();
    let (receiver, _returned) = values::receiver(&observer, &original, mode);
    let mut fields = seed();
    let _ = fields.insert(field.into(), receiver.as_ref().clone());
    let key = ApiKey::from_field_values(fields.clone())?;
    let before = observer.lock().unwrap().observe(&fields.into())?;
    let storage = Arc::new(Storage {
        entries: Mutex::new(vec![("api-key:by-ref:owner".into(), "[\"older\"]".into())]),
        observer: observer.clone(),
    });
    let result = put(storage.clone(), &key, true).await;
    let fields = key.field_values()?;
    assert!(fields.get(field).unwrap().strict_equals(&receiver));
    assert_eq!(observer.lock().unwrap().observe(&fields.into())?, before);
    let mut observer = observer.lock().unwrap();
    let outcome = observer.outcome(result.map(|()| FieldValue::Undefined), &original)?;
    let entries = storage
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(key, value)| vec![key.clone(), value.clone()].into())
        .collect::<Vec<FieldValue>>();
    let entries = observer.observe(&entries.into())?;
    Ok(
        json!({"before":before,"outcome":outcome,"events":observer.events,
        "entries":entries,"functionIds":observer.function_ids()}),
    )
}

#[tokio::test]
async fn native_date_methods_match_complete_upstream_cache_writes() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/api-key-date-methods-1.7.6.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture["version"], "1.7.6");
    let fields = [
        "createdAt",
        "updatedAt",
        "expiresAt",
        "lastRefillAt",
        "lastRequest",
    ];
    let modes = [
        "object-string",
        "object-undefined",
        "object-result",
        "date-to-json",
        "invalid-date-iso",
        "get-throws",
        "call-throws",
    ];
    let names = fields
        .into_iter()
        .flat_map(|field| modes.into_iter().map(move |mode| format!("{field}/{mode}")))
        .chain(["expiresAt/ttl-before-serialization".into()])
        .collect::<Vec<_>>();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), names.len());
    for (case, name) in cases.iter().zip(names) {
        assert_eq!(case["name"], name);
        assert_replay(&run_case(case).await?, &case["runtime"], &name);
    }
    Ok(())
}

#[test]
fn ttl_samples_clock_before_expiration_conversion_and_preserves_original_failure() -> AuthResult<()>
{
    for fails in [false, true] {
        let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let clock = Arc::new(std::sync::atomic::AtomicI64::new(2_000_000_000_000));
        let original = FieldValue::from(FieldMap::from([(
            "cause".into(),
            "expiry conversion".into(),
        )]));
        let projected = Arc::new(FieldValue::from(FieldMap::new()));
        let expected = Arc::downgrade(&projected);
        let observed = events.clone();
        let advanced = clock.clone();
        let failure = original.clone();
        projected.set_model_property(
            "valueOf",
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(receiver.strict_equals(&expected.upgrade().unwrap()));
                assert!(arguments.is_empty());
                observed.lock().unwrap().push("valueOf");
                advanced.store(2_000_000_060_000, std::sync::atomic::Ordering::SeqCst);
                if fails {
                    Err(AuthError::from_thrown(failure.clone()))
                } else {
                    Ok(2_000_000_060_000.0.into())
                }
            })
            .into(),
        )?;
        let mut fields = seed();
        let _ = fields.insert("expiresAt".into(), projected.as_ref().clone());
        let key = ApiKey::from_field_values(fields)?;
        let result = ttl(&key, || {
            events.lock().unwrap().push("Date.now");
            clock.load(std::sync::atomic::Ordering::SeqCst) as f64
        });
        assert_eq!(*events.lock().unwrap(), ["Date.now", "valueOf"]);
        if fails {
            assert!(
                result
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&original)
            );
        } else {
            assert_eq!(result?, Some(60));
        }
        assert!(key.expires_at.field_value().strict_equals(&projected));
    }
    Ok(())
}
