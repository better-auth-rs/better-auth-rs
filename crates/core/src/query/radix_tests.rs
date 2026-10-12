#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Frozen numeric observations require exact values, signed zero, rendering and explicit NaN payload coverage."
)]

use crate::{
    AuthError, AuthResult, FieldValue,
    native_test_observation::{NativeObservation, assert_replay},
    query::{field_number, parse_decimal_integer, parse_integer},
    user_fields::{UserFieldConfig, UserFieldType},
};
use serde_json::{Value as Json, json};

fn query_bindings(input: &str, expected: &Json, path: &str) -> AuthResult<()> {
    let field = UserFieldConfig {
        field_type: UserFieldType::Number,
        ..Default::default()
    };
    let invalid = expected == &json!({"type":"number","value":"NaN"});
    let mut observation = NativeObservation::default();
    let scalar = crate::user_query::bind_filter(&field, &input.into())?;
    let expected_scalar = if invalid {
        json!(input)
    } else {
        expected.clone()
    };
    assert_replay(
        &observation.observe(&scalar)?,
        &expected_scalar,
        &format!("{path}/scalar-filter"),
    );
    let array = crate::user_query::bind_filter(&field, &vec![input.into(), "1".into()].into())?;
    let expected_array = if invalid {
        json!([input, "1"])
    } else {
        json!([expected, 1])
    };
    assert_replay(
        &observation.observe(&array)?,
        &expected_array,
        &format!("{path}/array-filter"),
    );
    Ok(())
}

fn replay_case(case: &Json, path: &str, unpaired: &mut Vec<Json>) -> AuthResult<()> {
    let input = case["input"].as_str().unwrap();
    let operations = case["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 3);
    let mut observation = NativeObservation::default();
    for (index, (expected, name)) in operations
        .iter()
        .zip(["inferred", "decimal", "number"])
        .enumerate()
    {
        assert_eq!(expected["name"], name);
        let (number, source) = match name {
            "inferred" => (parse_integer(input), "parseInt(input)"),
            "decimal" => (parse_decimal_integer(input), "parseInt(input, 10)"),
            "number" => (field_number(&input.into())?, "Number(input)"),
            _ => return Err(AuthError::internal("Unexpected frozen numeric operation")),
        };
        let path = format!("{path}/operations/{index}");
        assert_eq!(expected["source"], source, "{path}/source");
        let value = FieldValue::from(number);
        assert_replay(
            &observation.observe(&value)?,
            &expected["result"],
            &format!("{path}/result"),
        );
        assert_replay(
            &json!(number == 0.0 && number.is_sign_negative()),
            &expected["negativeZero"],
            &format!("{path}/negativeZero"),
        );
        assert_replay(
            &json!(value.display_utf16()?.to_utf8().unwrap()),
            &expected["string"],
            &format!("{path}/string"),
        );
        assert_replay(
            &json!(value.stringify()?.unwrap()),
            &expected["json"],
            &format!("{path}/json"),
        );
        if number.is_nan() {
            let source_bits = expected["bits"].as_str().unwrap();
            assert!(f64::from_bits(u64::from_str_radix(source_bits, 16).unwrap()).is_nan());
            unpaired.push(json!({"path":format!("{path}/bits"),"sourceBits":source_bits}));
        } else {
            assert_replay(
                &json!(format!("{:016x}", number.to_bits())),
                &expected["bits"],
                &format!("{path}/bits"),
            );
        }
        if name == "number" && case["boundary"] != "syntax" {
            query_bindings(input, &expected["result"], &path)?;
        }
    }
    Ok(())
}

#[test]
fn shared_radix_parsing_matches_native_results_rendering_and_query_binding() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-radix-parsing-1.7.6.json"
    ))?;
    let coverage: Json = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-radix-parsing-1.7.6.coverage.json"
    ))?;
    assert_eq!(fixture["contract"], "native-radix-parsing");
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 135);
    assert_eq!(coverage["pairedOperations"], 405);
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["boundary"] != "syntax")
            .count(),
        96
    );
    assert_eq!(coverage["pairedQueryBindingCases"], 96);
    let mut unpaired = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        replay_case(case, &format!("/cases/{index}"), &mut unpaired)?;
    }
    assert_replay(
        &json!(unpaired),
        &coverage["unpairedNaNBits"],
        "/coverage/unpairedNaNBits",
    );
    Ok(())
}
