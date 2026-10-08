use super::*;

fn keys(value: &Value) -> TestResult<Vec<&str>> {
    let mut keys = value
        .as_array()
        .ok_or("Missing observed keys")?
        .iter()
        .map(|value| value.as_str().ok_or("Invalid field name"))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_unstable();
    Ok(keys)
}

pub(super) fn storage(actual: &Value, expected: &Value) -> TestResult {
    let actual = actual.as_array().ok_or("Missing stored rows")?;
    let expected = expected.as_array().ok_or("Missing upstream stored rows")?;
    assert_eq!(actual.len(), expected.len(), "stored row count");
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual["row"], expected["row"], "all stored fields");
        assert_eq!(
            keys(&actual["keys"])?,
            keys(&expected["keys"])?,
            "stored field presence"
        );
    }
    Ok(())
}

pub(super) fn compare(
    before: &Value,
    stored: &Value,
    result: &AuthResult<Option<FieldMap>>,
    state: &mut policies::State,
    expected: &Value,
) -> TestResult {
    assert_eq!(
        result.is_ok(),
        expected["returned"].as_bool().ok_or("Missing outcome")?,
        "{}: {result:?}",
        expected["name"]
    );
    assert_eq!(
        json!(std::mem::take(&mut state.events)),
        expected["events"],
        "{} callback trace",
        expected["name"]
    );
    let output_error = expected["events"]
        .as_array()
        .and_then(|events| events.last())
        .is_some_and(|event| event["phase"] == "output");
    if expected["method"] == "findOne" || result.is_err() && !output_error {
        assert_eq!(
            stored, before,
            "Reads and input failures must preserve every stored value"
        );
    }
    for row in stored.as_array().ok_or("Missing storage observations")? {
        assert_eq!(row["row"]["id"], ID);
    }
    match result {
        Ok(Some(row)) => {
            let actual = observe(&FieldValue::from(row.clone()))?;
            assert_eq!(
                actual, expected["result"],
                "{} complete result",
                expected["name"]
            );
            let names = json!(
                actual
                    .as_object()
                    .ok_or("Missing projected record")?
                    .keys()
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                keys(&names)?,
                keys(&expected["keys"])?,
                "projected field presence"
            );
        }
        Ok(None) => assert_eq!(expected["result"], Value::Null),
        Err(AuthError::Internal(message)) => {
            assert_eq!(
                message.as_ptr() as usize,
                state.error_pointer,
                "The callback error must propagate without wrapping or copying"
            );
            assert_eq!(
                expected["error"],
                json!({"name":"Error", "message":message, "sameCallbackError":true, "properties":{}})
            );
        }
        Err(error) => return Err(format!("Unexpected native replacement error: {error:?}").into()),
    }
    storage(stored, &expected["stored"])
}
