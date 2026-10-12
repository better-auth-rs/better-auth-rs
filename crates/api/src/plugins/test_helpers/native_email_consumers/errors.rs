use super::*;
use better_auth_core::error::ApiErrorClass;
use serde_json::json;

pub(super) fn assert_error(
    progress: &mut Progress,
    error: AuthError,
    original: &FieldValue,
    expected: &Json,
    outcome_path: &str,
) -> AuthResult<()> {
    let clone_error = matches!(error.original(), AuthError::DataClone);
    let api_error = error.is_api_error_instance(ApiErrorClass::BetterCall);
    let runtime_error = error.is_error_instance();
    let captured_headers = error.captured_headers_value();
    let value = error.into_thrown_value()?;
    assert_eq!(
        expected["sameOriginal"],
        value.strict_equals(original),
        "{outcome_path}"
    );
    let path = format!("{outcome_path}/error");
    let expected = &expected["error"];
    if clone_error {
        assert_eq!(value.model_property("name")?, "DataCloneError".into());
        assert!(value.as_object().is_some());
        assert_eq!(expected["type"], "object");
        assert_eq!(
            expected["ownKeys"],
            json!(["line", "column", "sourceURL", "stack"])
        );
        // Bun's DOMException has host location descriptors; Rust retains the DataCloneError variant and name.
        progress
            .unpaired
            .extend([format!("{path}/ownKeys"), format!("{path}/properties")]);
        return Ok(());
    }
    if api_error {
        return api_error_snapshot(progress, &value, captured_headers, expected, &path);
    }
    if runtime_error
        && value
            .model_property("name")?
            .strict_equals(&"TypeError".into())
    {
        assert_eq!(
            expected["ownKeys"],
            json!([
                "message",
                "originalLine",
                "originalColumn",
                "line",
                "column",
                "sourceURL",
                "stack"
            ])
        );
        let mut message_graph = expected.clone();
        message_graph["ownKeys"]
            .as_array_mut()
            .ok_or_else(|| AuthError::internal("TypeError own keys are missing"))?
            .truncate(1);
        let properties = message_graph["properties"]
            .as_array_mut()
            .ok_or_else(|| AuthError::internal("TypeError descriptors are missing"))?;
        assert_eq!(properties.len(), 7);
        properties.truncate(1);
        progress
            .graph
            .assert_snapshot(&value, &message_graph, &path)?;
        for index in 1..7 {
            progress.unpaired.extend([
                format!("{path}/ownKeys/{index}"),
                format!("{path}/properties/{index}"),
            ]);
        }
        return Ok(());
    }
    progress.graph.assert_snapshot(&value, expected, &path)
}

fn api_error_snapshot(
    progress: &mut Progress,
    value: &FieldValue,
    captured_headers: Option<FieldValue>,
    expected: &Json,
    path: &str,
) -> AuthResult<()> {
    let mut strings = expected.clone();
    let keys = strings["ownKeys"]
        .as_array_mut()
        .ok_or_else(|| AuthError::internal("APIError own keys are missing"))?;
    let symbol = keys
        .pop()
        .ok_or_else(|| AuthError::internal("APIError header symbol is missing"))?;
    assert_eq!(
        symbol,
        json!({"type":"symbol","value":"Symbol(better-call:api-error-headers)"})
    );
    let index = keys.len();
    assert!(
        keys.iter().all(Json::is_string),
        "{path}: all own string keys must be paired"
    );
    let properties = strings["properties"]
        .as_array_mut()
        .ok_or_else(|| AuthError::internal("APIError descriptors are missing"))?;
    assert_eq!(properties.len(), index + 1);
    let property = properties
        .pop()
        .ok_or_else(|| AuthError::internal("APIError header descriptor is missing"))?;
    assert_eq!(property[0], symbol);
    assert_eq!(property[1]["enumerable"], false);
    assert_eq!(property[1]["configurable"], true);
    assert_eq!(property[1]["writable"], false);
    assert_eq!(property[1].as_object().map(|value| value.len()), Some(4));
    progress.graph.assert_snapshot(value, &strings, path)?;
    let headers = captured_headers
        .ok_or_else(|| AuthError::internal("Rust endpoint did not retain APIError headers"))?;
    assert!(property[1]["value"].get("reference").is_none());
    assert!(!headers.strict_equals(value));
    for key in value.own_property_keys()? {
        assert!(
            !headers.strict_equals(&value.model_property(&key)?),
            "{path}: captured headers retain their distinct identity"
        );
    }
    progress.graph.assert_snapshot(
        &headers,
        &property[1]["value"],
        &format!("{path}/properties/{index}/1/value"),
    )?;
    // Endpoint metadata retains the captured value. JavaScript Symbol keys and their reflection flags remain unpaired.
    progress.unpaired.extend([
        format!("{path}/ownKeys/{index}"),
        format!("{path}/properties/{index}/0"),
        format!("{path}/properties/{index}/1/enumerable"),
        format!("{path}/properties/{index}/1/configurable"),
        format!("{path}/properties/{index}/1/writable"),
    ]);
    Ok(())
}
