#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned encoding contracts must fail immediately on invalid fixture shapes or callback observations."
)]

use super::*;
use crate::plugins::test_helpers::{
    native_observation::NativeObservation,
    verification_consumer_native::{ReplayFailures, SECRET, assert_replay, object::Root},
};
use better_auth_core::{FieldFunction, SecretKey, VersionedSecret};
use serde_json::{Value as Json, json};
use std::sync::Mutex;

async fn capture_encoding(scenario: &Json) -> AuthResult<Json> {
    let observer = Arc::new(Mutex::new(NativeObservation::default()));
    let root = Root::new(if scenario["value"] == "function" {
        "function"
    } else {
        "object"
    });
    if scenario["value"] == "object" {
        root.data("marker", "native-generated-codes".into());
        let expected = root.owner();
        let observed = observer.clone();
        let method: FieldValue = FieldFunction::contextual(move |receiver, arguments| {
            let owner = expected.upgrade().unwrap();
            let same_receiver = receiver.strict_equals(owner.get().unwrap());
            assert!(same_receiver);
            assert_eq!(arguments, &[FieldValue::from("")]);
            let mut observer = observed.lock().unwrap();
            let key = observer.observe(&arguments[0])?;
            observer.record(
                "toJSON",
                [
                    ("sameReceiver".into(), same_receiver.into()),
                    ("key".into(), key),
                ],
            );
            Ok(FieldValue::Undefined)
        })
        .into();
        root.getter("toJSON", false, move |_| Ok(method.clone()));
    }
    let before = observer.lock().unwrap().observe(&root.value)?;
    let keys = [VersionedSecret::new(3, SECRET)];
    let key = if scenario["key"] == "single" {
        SecretKey::Single(SECRET)
    } else {
        SecretKey::Versioned {
            keys: &keys,
            legacy_secret: None,
        }
    };
    let storage = if scenario["storage"] == "plain" {
        BackupCodeStorage::Plain
    } else {
        BackupCodeStorage::Encrypted
    };
    let observed = observer.clone();
    let generated = root.value.clone();
    let options = BackupCodeOptions {
        storage,
        generate: Some(Arc::new(|| vec!["typed-fallback".to_owned()])),
        generate_native: Some(Arc::new(move || {
            observed.lock().unwrap().record("generate", []);
            Ok(generated.clone())
        })),
        ..Default::default()
    };
    let result = options.generate(key).await;
    let mut observer = observer.lock().unwrap();
    let outcome = match result {
        Ok(generated) => {
            let same_codes = generated.backup_codes.strict_equals(&root.value);
            let value = FieldValue::from(FieldMap::from([
                ("backupCodes".into(), generated.backup_codes),
                (
                    "encryptedBackupCodes".into(),
                    generated.encrypted_backup_codes,
                ),
            ]));
            json!({"returned":true,"sameCodes":same_codes,"result":observer.observe(&value)?})
        }
        Err(error) => {
            let error = error.into_thrown_value()?;
            json!({"returned":false,"error":{
                "name":observer.observe(&error.model_property("name")?)?,
                "message":observer.observe(&error.model_property("message")?)?,
                "ownEnumerable":observer.observe(&error)?,
            }})
        }
    };
    Ok(
        json!({"before":before,"events":observer.events,"outcome":outcome,
        "after":observer.observe(&root.value)?}),
    )
}

#[tokio::test]
async fn backup_code_encoding_matches_native_callbacks_and_undefined_boundary() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/two-factor-backup-code-encoding-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "two-factor-backup-code-encoding");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = super::backup_code_native_contract::capture(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    let encodings = fixture["encodings"].as_array().unwrap();
    assert_eq!(encodings.len(), 4);
    for case in encodings {
        let name = case["name"].as_str().unwrap();
        let actual = capture_encoding(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    failures.finish();
    Ok(())
}
