use super::support::{fixture, observe, operation, user};
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, StructuredCloneContext, UserView,
    user_fields::{
        FieldTransforms, FieldValidators, UserConfig, UserFieldConfig, UserFieldFactory,
        UserFieldTransform,
    },
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Calls {
    factory: AtomicUsize,
    returned: AtomicUsize,
    validator: AtomicUsize,
    input: AtomicUsize,
}

impl Calls {
    fn observe(&self) -> Value {
        json!({
            "factory": self.factory.load(Ordering::SeqCst),
            "returnedFunction": self.returned.load(Ordering::SeqCst),
            "validator": self.validator.load(Ordering::SeqCst),
            "input": self.input.load(Ordering::SeqCst),
            "output": 0,
            "admission": 0,
            "before": 0,
            "after": 0,
            "generateId": 0,
        })
    }
}

struct Harness {
    fields: UserConfig,
    factory: UserFieldFactory,
    default: FieldValue,
    returned: FieldValue,
    calls: Arc<Calls>,
}

impl Harness {
    fn new(result: &str) -> Self {
        let calls = Arc::new(Calls::default());
        let returned_calls = calls.clone();
        let returned_factory: UserFieldFactory = Arc::new(move || {
            let _ = returned_calls.returned.fetch_add(1, Ordering::SeqCst);
            Ok("returned-function-value".into())
        });
        let returned = FieldValue::Function(returned_factory.into());
        let returned_value = returned.clone();
        let result = result.to_owned();
        let factory_calls = calls.clone();
        let factory: UserFieldFactory = Arc::new(move || {
            let _ = factory_calls.factory.fetch_add(1, Ordering::SeqCst);
            match result.as_str() {
                "string" => Ok("factory-value".into()),
                "undefined" => Ok(FieldValue::Undefined),
                "throws" => Err(AuthError::internal("protected-default-failed")),
                "function" => Ok(returned_value.clone()),
                _ => Err(AuthError::internal("Unknown protected factory result")),
            }
        });
        let default = FieldValue::Function(factory.clone().into());
        let validator_calls = calls.clone();
        let input_calls = calls.clone();
        let fields = UserConfig {
            additional_fields: Some(
                [(
                    "protectedValue".into(),
                    UserFieldConfig {
                        required: Some(false),
                        input: Some(false),
                        returned: Some(true),
                        default_value_fn: Some(factory.clone()),
                        validator: Some(FieldValidators {
                            input: Some(Arc::new(move |value| {
                                let _ = validator_calls.validator.fetch_add(1, Ordering::SeqCst);
                                Ok(value)
                            })),
                            ..Default::default()
                        }),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                let _ = input_calls.input.fetch_add(1, Ordering::SeqCst);
                                Ok(value)
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        Self {
            fields,
            factory,
            default,
            returned,
            calls,
        }
    }
}

#[test]
fn own_property_parser_outcomes_match_captured_function_defaults() -> AuthResult<()> {
    let fixture = fixture("input");
    let mut paired = 0;
    let mut inherited = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let harness = Harness::new(case["result"].as_str().unwrap());
        for expected in case["operations"].as_array().unwrap() {
            // FieldMap has own properties only. JavaScript prototypes, this, and arguments are outside this contract.
            if expected["input"] == "inherited" {
                inherited += 1;
                continue;
            }
            let input = expected["data"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.clone(),
                        if value.get("type").and_then(Value::as_str) == Some("undefined") {
                            FieldValue::Undefined
                        } else {
                            FieldValue::from_json(value.clone())?
                        },
                    ))
                })
                .collect::<AuthResult<FieldMap>>()?;
            assert_eq!(
                json!(input.keys().collect::<Vec<_>>()),
                expected["inputOwnKeys"]
            );
            assert_eq!(
                input.contains_key("protectedValue"),
                expected["inputHasOwn"].as_bool().unwrap()
            );
            let result = harness
                .fields
                .parse_input(&input, expected["action"] == "create");
            assert_eq!(result.is_ok(), expected["returned"].as_bool().unwrap());
            match result {
                Ok(fields) => {
                    assert_eq!(
                        json!(fields.keys().collect::<Vec<_>>()),
                        expected["ownKeys"]
                    );
                    assert_eq!(
                        fields.contains_key("protectedValue"),
                        expected["ownsField"].as_bool().unwrap()
                    );
                    for (name, reference) in [
                        ("sameDefault", &harness.default),
                        ("sameReturned", &harness.returned),
                    ] {
                        assert_eq!(
                            fields
                                .get("protectedValue")
                                .is_some_and(|value| value.strict_equals(reference)),
                            expected[name].as_bool().unwrap()
                        );
                    }
                    assert_eq!(
                        observe(&fields.into(), &harness.default, &harness.returned)?,
                        expected["result"]
                    );
                }
                Err(AuthError::FieldInput { code, message }) => {
                    assert_eq!(
                        json!({"code": code, "message": message}),
                        expected["error"]["properties"]["body"]
                    );
                    assert_eq!(expected["error"]["properties"]["statusCode"], 400);
                }
                Err(error) => {
                    assert!(matches!(error, AuthError::Internal(_)));
                    assert_eq!(
                        error.instrumentation_message(),
                        expected["error"]["message"]
                    );
                    assert_eq!(expected["error"]["name"], "Error");
                }
            }
            assert_eq!(harness.calls.observe(), expected["counts"]);
            paired += 1;
        }
    }
    assert_eq!(paired, 56);
    assert_eq!(inherited, 8);
    Ok(())
}

#[test]
fn function_handles_preserve_identity_and_require_explicit_invocation() -> AuthResult<()> {
    let harness = Harness::new("function");
    let alias = FieldValue::Function(harness.factory.clone().into());
    let distinct = Harness::new("function");
    assert!(alias.strict_equals(&harness.default));
    assert!(alias.same_value_zero(&harness.default));
    assert_eq!(alias, harness.default);
    assert!(!alias.strict_equals(&distinct.default));
    assert!(!alias.strict_equals(&harness.returned));
    assert!(alias.is_truthy());
    assert!(!alias.is_undefined());
    assert!(better_auth_core::query::field_number(&alias)?.is_nan());
    assert_eq!(
        better_auth_core::utils::symmetric::decrypt_field("function-type-diagnostic", &alias)
            .unwrap_err()
            .instrumentation_message(),
        "hex string expected, got function"
    );
    assert_eq!(harness.calls.factory.load(Ordering::SeqCst), 0);
    let FieldValue::Function(function) = alias else {
        return Err(AuthError::internal("Expected callable default"));
    };
    let returned = function.call()?;
    assert!(returned.strict_equals(&harness.returned));
    assert_eq!(harness.calls.factory.load(Ordering::SeqCst), 1);
    assert_eq!(harness.calls.returned.load(Ordering::SeqCst), 0);
    let FieldValue::Function(function) = returned else {
        return Err(AuthError::internal("Expected callable factory result"));
    };
    assert_eq!(
        function.call()?,
        FieldValue::from("returned-function-value")
    );
    assert_eq!(harness.calls.returned.load(Ordering::SeqCst), 1);

    let mut fields = harness.fields.clone();
    let declaration = fields.fields_mut().get_mut("protectedValue").unwrap();
    declaration.default_value_fn = None;
    declaration.default_value = Some(harness.default.clone());
    let supplied = fields.parse_input(
        &FieldMap::from([("protectedValue".into(), FieldValue::Undefined)]),
        true,
    )?;
    assert!(supplied["protectedValue"].strict_equals(&harness.default));
    assert_eq!(harness.calls.factory.load(Ordering::SeqCst), 1);
    let missing = fields.parse_input(&FieldMap::new(), true)?;
    assert!(missing["protectedValue"].strict_equals(&harness.returned));
    assert_eq!(harness.calls.factory.load(Ordering::SeqCst), 2);
    assert_eq!(harness.calls.returned.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn json_and_recursive_clone_boundaries_preserve_captured_function_behavior() -> AuthResult<()> {
    let fixture = fixture("memory");
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "raw-string")
        .unwrap();
    let harness = Harness::new("string");
    let object = FieldValue::from(FieldMap::from([("value".into(), harness.default.clone())]));
    let array = FieldValue::from(vec![harness.default.clone()]);
    let root = harness
        .default
        .stringify()?
        .map(FieldValue::from)
        .unwrap_or_default();
    assert_eq!(
        json!({
            "object": object.stringify()?.unwrap(),
            "array": array.stringify()?.unwrap(),
            "root": observe(&root, &harness.default, &harness.returned)?,
        }),
        operation(case, "direct:json-only")["result"]
    );
    assert_eq!(object.json()?, Some(json!({})));
    assert_eq!(array.json()?, Some(json!([null])));
    assert_eq!(harness.default.json()?, None);
    let view = UserView::try_from(FieldMap::from([
        ("value".into(), harness.default.clone()),
        ("array".into(), array.clone()),
    ]))?;
    assert_eq!(serde_json::to_value(view)?, json!({"array": [null]}));
    let nested = FieldValue::from(FieldMap::from([("nested".into(), array.clone())]));
    for value in [&harness.default, &object, &array, &nested] {
        let result = StructuredCloneContext::new().clone_value(value);
        assert!(matches!(result, Err(AuthError::DataClone)));
        let error = result.unwrap_err();
        assert_eq!(
            error.instrumentation_message(),
            operation(case, "direct:public-output")["error"]["message"]
        );
    }
    assert!(matches!(
        StructuredCloneContext::new().clone_map(&object.as_object().unwrap().snapshot_fields()?),
        Err(AuthError::DataClone)
    ));
    assert!(
        object
            .as_object()
            .unwrap()
            .get("value")?
            .unwrap()
            .strict_equals(&harness.default)
    );
    assert_eq!(harness.calls.factory.load(Ordering::SeqCst), 0);
    assert_eq!(harness.calls.returned.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn synthetic_visibility_and_default_calls_match_captured_rows() -> AuthResult<()> {
    let fixture = fixture("memory");
    for name in ["raw-string", "hidden-function"] {
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        for (shape, literal) in [
            ("provided", false),
            ("missing", false),
            ("undefined", false),
            ("provided", true),
            ("missing", true),
            ("undefined", true),
        ] {
            let mut harness = Harness::new("string");
            let declaration = harness
                .fields
                .fields_mut()
                .get_mut("protectedValue")
                .unwrap();
            declaration.returned = Some(name != "hidden-function");
            if literal {
                declaration.default_value_fn = None;
                declaration.default_value = Some(harness.default.clone());
            }
            let extra = match shape {
                "provided" => FieldMap::from([("protectedValue".into(), harness.default.clone())]),
                "undefined" => FieldMap::from([("protectedValue".into(), FieldValue::Undefined)]),
                _ => FieldMap::new(),
            };
            let expected = operation(case, &format!("synthetic:{shape}"));
            let output = UserView::synthetic_output(
                user("synthetic-user", extra),
                &harness.fields,
                &harness.fields,
            )?;
            let returned = expected["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["phase"] == "synthetic:return")
                .unwrap();
            assert_eq!(
                observe(&output.clone().into(), &harness.default, &harness.returned)?,
                returned["user"]
            );
            assert_eq!(
                harness.calls.factory.load(Ordering::SeqCst) as u64,
                expected["counts"]["factory"].as_u64().unwrap()
                    - expected["before"]["counts"]["factory"].as_u64().unwrap()
            );
            assert_eq!(harness.calls.input.load(Ordering::SeqCst), 0);
            let cloned = StructuredCloneContext::new().clone_map(&output);
            assert_eq!(cloned.is_ok(), expected["returned"].as_bool().unwrap());
            match cloned {
                Ok(fields) => {
                    let value = FieldValue::from(fields);
                    let json = FieldValue::from(FieldMap::from([("user".into(), value.clone())]))
                        .stringify()?
                        .unwrap();
                    assert_eq!(
                        json!({
                            "user": observe(&value, &harness.default, &harness.returned)?,
                            "json": json,
                        }),
                        expected["result"]
                    );
                }
                Err(error) => assert!(matches!(error, AuthError::DataClone)),
            }
        }
    }
    Ok(())
}
