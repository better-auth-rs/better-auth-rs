#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::panic,
    reason = "Frozen method diagnostics require exact error text, descriptors, callback order and an explicit coverage ledger."
)]

use crate::{
    AuthError, AuthResult, FieldDate, FieldFunction, FieldMap, FieldPropertyDefinition,
    FieldPropertyUpdate, FieldValue,
    native_property_graph::PropertyGraph,
    native_test_observation::{NativeObservation, assert_replay},
};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

fn method(name: &str) -> FieldValue {
    match name {
        "undefined" => FieldValue::Undefined,
        "null" => FieldValue::Null,
        "false" => false.into(),
        "true" => true.into(),
        "zero" => 0.0.into(),
        "negative-zero" => (-0.0).into(),
        "number" => 17.into(),
        "nan" => f64::NAN.into(),
        "infinity" => f64::INFINITY.into(),
        "negative-infinity" => f64::NEG_INFINITY.into(),
        "string" => "text".into(),
        "empty-string" => "".into(),
        "escaped-string" => "quote\"\nline".into(),
        "object" => FieldMap::from([("marker".into(), "object".into())]).into(),
        "array" => vec![1.into(), 2.into()].into(),
        "date" => FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
        "invalid-date" => FieldDate::invalid().into(),
        _ => panic!("Unexpected frozen method value: {name}"),
    }
}

fn getter(get: FieldFunction, configurable: bool) -> FieldPropertyDefinition {
    FieldPropertyDefinition {
        configurable: Some(configurable),
        property: FieldPropertyUpdate::Accessor {
            get: Some(Some(get)),
            set: None,
        },
        ..Default::default()
    }
}

fn paired_graph(expected: &Json, path: &str, unpaired: &mut Vec<String>) -> Json {
    let mut paired = expected.clone();
    if let Some(keys) = expected["ownKeys"].as_array()
        && let Some(index) = keys.iter().position(Json::is_object)
    {
        // The value model has string keys. Retain the exact symbol descriptor in the coverage ledger.
        assert_eq!(index + 1, keys.len());
        assert_eq!(
            keys[index],
            json!({"type":"symbol","value":"Symbol(Symbol.toPrimitive)"})
        );
        assert_eq!(expected["properties"][index][0], keys[index]);
        assert_eq!(
            expected["properties"][index][1]["get"]["value"]["identity"],
            "function-4"
        );
        let _ = paired["ownKeys"].as_array_mut().unwrap().pop();
        let _ = paired["properties"].as_array_mut().unwrap().pop();
        unpaired.extend([
            format!("{path}/ownKeys/{index}"),
            format!("{path}/properties/{index}"),
        ]);
    }
    paired
}

fn replay(case: &Json, path: &str, unpaired: &mut Vec<String>) -> AuthResult<()> {
    let method = method(case["name"].as_str().unwrap());
    let events = Arc::new(Mutex::new(NativeObservation::default()));
    let object = matches!(
        method,
        FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_)
    );
    if object {
        for key in ["toString", "valueOf", "toJSON"] {
            let events = events.clone();
            assert!(method.define_own_property(
                key,
                getter(
                    FieldFunction::contextual(move |_, _| {
                        events
                            .lock()
                            .unwrap()
                            .record("unexpected-coercion", [("key".into(), key.into())]);
                        Err(AuthError::internal(
                            "Diagnostic construction consumed a coercion getter",
                        ))
                    }),
                    true
                )
            )?);
        }
    }
    let receiver: FieldValue = FieldMap::new().into();
    let receiver_identity = Arc::new(receiver.clone());
    let expected_receiver = Arc::downgrade(&receiver_identity);
    let returned = method.clone();
    let called = events.clone();
    assert!(receiver.define_own_property(
        "split",
        getter(
            FieldFunction::contextual(move |actual, args| {
                assert!(actual.strict_equals(expected_receiver.upgrade().unwrap().as_ref()));
                assert!(args.is_empty());
                called.lock().unwrap().record("get:split", []);
                Ok(returned.clone())
            }),
            false
        )
    )?);
    let mut graph = PropertyGraph::default();
    let input_path = format!("{path}/input");
    graph.assert_snapshot(
        &method,
        &paired_graph(&case["input"], &input_path, unpaired),
        &input_path,
    )?;
    let (expression, separator) = match case["member"].as_str().unwrap() {
        "receiver.split" => ("receiver", ":"),
        "receiver?.split" => ("receiver?", ","),
        other => panic!("Unexpected frozen member: {other}"),
    };
    let error = receiver
        .split_method(
            &separator.into(),
            expression,
            case["source"].as_str().unwrap(),
        )
        .unwrap_err();
    assert!(error.is_error_instance());
    assert!(!error.is_api_error()?);
    let error = error.into_thrown_value()?;
    let mut observation = NativeObservation::default();
    let error = json!({
        "name": observation.observe(&error.model_property("name")?)?,
        "message": observation.observe(&error.model_property("message")?)?,
    });
    assert_replay(
        &error["name"],
        &case["error"]["name"],
        &format!("{path}/error/name"),
    );
    assert_replay(
        &error["message"],
        &case["error"]["message"],
        &format!("{path}/error/message"),
    );
    assert_eq!(
        case["error"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "originalLine",
            "originalColumn",
            "line",
            "column",
            "sourceURL"
        ]
    );
    unpaired.extend(
        case["error"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|key| format!("{path}/error/properties/{key}")),
    );
    let after_path = format!("{path}/after");
    graph.assert_snapshot(
        &method,
        &paired_graph(&case["after"], &after_path, unpaired),
        &after_path,
    )?;
    assert_replay(
        &json!(events.lock().unwrap().events),
        &case["events"],
        &format!("{path}/events"),
    );
    let mut functions = case["functions"].clone();
    if object {
        assert_eq!(functions.as_array().unwrap().len(), 4);
        assert_eq!(functions[3]["identity"], "function-4");
        let _ = functions.as_array_mut().unwrap().pop();
        unpaired.push(format!("{path}/functions/3"));
    }
    unpaired.extend(graph.finish(Some(&functions), &format!("{path}/functions")));
    Ok(())
}

#[test]
fn native_method_diagnostics_match_error_text_descriptors_and_zero_coercion() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-method-diagnostics-1.7.6.json"
    ))?;
    let coverage: Json = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-method-diagnostics-1.7.6.coverage.json"
    ))?;
    assert_eq!(fixture["contract"], "native-method-diagnostics");
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 34);
    let mut unpaired = vec!["/runtime/bun".into()];
    for (index, case) in cases.iter().enumerate() {
        replay(case, &format!("/cases/{index}"), &mut unpaired)?;
    }
    unpaired.sort();
    assert_replay(
        &json!(unpaired),
        &coverage["unpairedPaths"],
        "/coverage/unpairedPaths",
    );
    Ok(())
}
