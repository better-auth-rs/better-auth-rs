use super::*;

pub(crate) fn api_key_value(row: &ApiKey) -> AuthResult<Value> {
    let mut result = serde_json::to_value(
        better_auth::__private_core::wire::ApiKeyView::try_from(row)?,
    )?;
    result["key"] = json!(row.key_hash);
    result["name"] = values::observe(&row.name.field_value())?;
    Ok(result)
}

pub(crate) fn passkey_value(row: &Passkey) -> AuthResult<Value> {
    let mut result = serde_json::to_value(row)?;
    result["name"] = values::observe(&row.name.field_value())?;
    result["aaguid"] = values::observe(&row.aaguid.field_value())?;
    Ok(result)
}

// Compare timestamp invariants separately. Memory Passkey retains its verified legacy envelope.
fn stable_row(value: &Value, backend: &str, target: Target, stored: bool) -> Value {
    let mut value = value.clone();
    if let Some(fields) = value.as_object_mut() {
        let _ = fields.remove("createdAt");
        let _ = fields.remove("updatedAt");
        if stored && backend == "memory" && target != Target::ApiKeyName {
            assert_eq!(
                fields.remove("credential"),
                Some(json!("ordinary-private-record"))
            );
        }
    }
    value
}

// Compare field presence as a set. The retained fixture also records unpaired JavaScript key order.
fn stable_keys(
    keys: &Value,
    backend: &str,
    target: Target,
    stored: bool,
) -> TestResult<Vec<String>> {
    let mut names = keys
        .as_array()
        .ok_or("Missing observed field keys")?
        .iter()
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .ok_or("Invalid observed field key")
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.retain(|name| {
        !matches!(name.as_str(), "createdAt" | "updatedAt")
            && !(stored
                && backend == "memory"
                && target != Target::ApiKeyName
                && name == "credential")
    });
    names.sort();
    Ok(names)
}

pub(super) fn compare_storage(
    backend: &str,
    target: Target,
    actual: &Value,
    expected: &Value,
) -> TestResult {
    let actual = actual.as_array().ok_or("Missing actual stored rows")?;
    let expected = expected.as_array().ok_or("Missing upstream stored rows")?;
    assert_eq!(
        actual.len(),
        expected.len(),
        "{backend} {target:?} row count"
    );
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(
            stable_row(&actual["row"], backend, target, true),
            stable_row(&expected["row"], backend, target, false),
            "{backend} {target:?} stored fields"
        );
        assert_eq!(
            stable_keys(&actual["keys"], backend, target, true)?,
            stable_keys(&expected["keys"], backend, target, false)?,
            "{backend} {target:?} stored field set"
        );
        for field in ["displaySqlNull", "displayText"] {
            assert_eq!(
                actual.get(field),
                expected.get(field),
                "{backend} {target:?} {field}"
            );
        }
    }
    Ok(())
}

pub(super) fn verify_write_boundary(
    before: &Value,
    after: &Value,
    result: &AuthResult<Option<Value>>,
    expected: &Value,
) -> TestResult {
    let operation = expected["name"].as_str().ok_or("Missing operation name")?;
    let write = matches!(operation, "create" | "seed" | "update");
    let output_error = expected["error"]["sameCallbackError"] == true
        && expected["events"]
            .as_array()
            .and_then(|events| events.last())
            .is_some_and(|event| event["phase"] == "output");
    if !write || result.is_err() && !output_error {
        assert_eq!(
            after, before,
            "Reads and rejected input must preserve every stored field, including timestamps"
        );
    } else if operation == "update" {
        let before = before.as_array().ok_or("Missing pre-update rows")?;
        let after = after.as_array().ok_or("Missing post-update rows")?;
        assert_eq!(before.len(), 1);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0]["row"]["createdAt"], before[0]["row"]["createdAt"]);
    }
    Ok(())
}

fn timestamp(value: &Value) -> TestResult<f64> {
    let text = value
        .as_str()
        .or_else(|| {
            (value["type"] == "date")
                .then(|| value["value"].as_str())
                .flatten()
        })
        .ok_or("Expected an actual stored or returned timestamp")?;
    Ok(
        text.parse::<better_auth::seaorm::__private_chrono::DateTime<
            better_auth::seaorm::__private_chrono::Utc,
        >>()?
        .timestamp_millis() as f64,
    )
}

pub(super) fn compare(
    backend: &str,
    target: Target,
    started: f64,
    result: &AuthResult<Option<Value>>,
    events: Vec<Value>,
    stored: &Value,
    expected: &Value,
) -> TestResult {
    assert_eq!(
        result.is_ok(),
        expected["returned"]
            .as_bool()
            .ok_or("Missing return state")?,
        "{backend} {target:?} {}: {result:?}",
        expected["name"]
    );
    assert_eq!(
        Value::Array(events),
        expected["events"],
        "{backend} {target:?} {} callback trace",
        expected["name"]
    );
    let rows = stored.as_array().ok_or("Missing stored observations")?;
    for stored in rows {
        assert_eq!(stored["row"]["id"], ID);
        let created = timestamp(&stored["row"]["createdAt"])?;
        assert!(
            created >= started && created <= now(),
            "createdAt must use the real operation clock"
        );
        if let Some(updated) = stored["row"].get("updatedAt") {
            let updated = timestamp(updated)?;
            assert!(
                updated >= created && updated <= now(),
                "updatedAt must follow creation on the real clock"
            );
        }
    }
    match result {
        Ok(result) => {
            let actual = result.as_ref().unwrap_or(&Value::Null);
            let wanted = &expected["result"];
            assert_eq!(
                stable_row(actual, backend, target, false),
                stable_row(wanted, backend, target, false),
                "{backend} {target:?} {} result",
                expected["name"]
            );
            let actual_keys = actual
                .as_object()
                .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            assert_eq!(
                stable_keys(&json!(actual_keys), backend, target, false)?,
                stable_keys(&expected["keys"], backend, target, false)?
            );
            if result.is_some() {
                assert_eq!(actual["id"], ID);
                assert_eq!(rows.len(), 1);
                for field in ["createdAt", "updatedAt"] {
                    if let Some(value) = actual.get(field) {
                        assert_eq!(
                            timestamp(value)?,
                            timestamp(&rows[0]["row"][field])?,
                            "Returned {field} must equal storage"
                        );
                    }
                }
            }
        }
        Err(error) => {
            if expected["error"]["sameCallbackError"] == true {
                let AuthError::Internal(message) = error else {
                    return Err(format!("Callback error changed category: {error:?}").into());
                };
                assert_eq!(
                    Some(message.as_str()),
                    expected["error"]["message"].as_str()
                );
            } else {
                // Drivers expose different error shapes. Assert rejection and storage atomicity, then retain both diagnostics.
                assert!(
                    matches!(error, AuthError::Database(_)),
                    "The database must reject the captured invalid JSON binding: {error:?}"
                );
                eprintln!(
                    "display JSON driver diagnostic: backend={backend}; target={target:?}; Rust={error:?}; upstream={}",
                    expected["error"]
                );
            }
        }
    }
    compare_storage(backend, target, stored, &expected["stored"])
}
