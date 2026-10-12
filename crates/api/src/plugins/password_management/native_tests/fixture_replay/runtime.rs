#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;

/// Keep functions opaque at the runtime boundary while retaining their source descriptors in the fixture.
/// The shared source decoder still rejects aliases, accessors, sparse arrays, and extra non-enumerable data.
pub(super) fn snapshot(value: &Json) -> AuthResult<Json> {
    source::source_value_with(value, &|source| {
        if source.get("identity").is_some() && source["type"] == "function" {
            let function = &source["value"];
            assert_eq!(function["type"], "function");
            assert!(
                function["identity"]
                    .as_str()
                    .unwrap()
                    .starts_with("function-")
            );
            Ok(Some(function.clone()))
        } else {
            Ok(None)
        }
    })
}

fn event(value: &Json) -> AuthResult<Json> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| Ok((name.clone(), snapshot(value)?)))
        .collect::<AuthResult<serde_json::Map<_, _>>>()
        .map(Into::into)
}

pub(super) fn query_expected(case: &Json) -> AuthResult<Json> {
    let mut outcome = case["outcome"].clone();
    if outcome["returned"] == true {
        outcome["result"] = snapshot(&outcome["result"])?;
    }
    assert_eq!(case["errorFunctions"], json!([]));
    Ok(json!({
        "projected":snapshot(&case["projected"])?, "outcome":outcome,
        "events":case["events"].as_array().unwrap().iter().map(event).collect::<AuthResult<Vec<_>>>()?,
        "functionIds":case["functions"].as_array().unwrap().iter().map(|function| function["identity"].clone()).collect::<Vec<_>>(),
        "errorFunctions":[], "stored":source::source_value(&case["stored"])?,
    }))
}

pub(super) fn outcome(
    result: AuthResult<FieldValue>,
    native: &mut NativeObservation,
    original: Option<&FieldValue>,
) -> AuthResult<Json> {
    match result {
        Ok(value) => Ok(json!({"returned":true,"result":native.observe(&value)?})),
        Err(error) => {
            let error = error.into_thrown_value()?;
            let same_original = original.map(|original| error.strict_equals(original));
            let name = error.model_property("name")?;
            let mut observer = NativeObservation::default();
            let observed = if name.is_undefined() {
                json!({"thrown":observer.observe(&error)?})
            } else {
                let mut properties = FieldMap::new();
                let object = error.as_object().ok_or_else(|| {
                    AuthError::internal("A named password failure must expose its error properties")
                })?;
                for key in object.own_keys()? {
                    if !["stack", "name", "message"].contains(&key.as_str()) {
                        let _ =
                            properties.insert(key.clone(), object.get(&key)?.unwrap_or_default());
                    }
                }
                json!({"name":observer.observe(&name)?,"message":observer.observe(&error.model_property("message")?)?,"properties":observer.observe(&properties.into())?})
            };
            assert!(observer.function_ids().is_empty());
            let mut outcome = serde_json::Map::from_iter([("returned".into(), false.into())]);
            if let Some(same_original) = same_original {
                let _ = outcome.insert("sameOriginal".into(), same_original.into());
            }
            let _ = outcome.insert("error".into(), observed);
            Ok(outcome.into())
        }
    }
}
