#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::plugins::test_helpers::native_sort_contract::{
    Harness, assert_case, cases, getter_cases,
};

#[test]
fn api_key_native_sort_replays_complete_source_runtime() -> AuthResult<()> {
    for case in cases("api-key") {
        run_case(case, false)?;
    }
    Ok(())
}

#[test]
fn api_key_accessor_sort_replays_complete_source_runtime() -> AuthResult<()> {
    let cases = getter_cases("api-key").collect::<Vec<_>>();
    assert_eq!(cases.len(), 46);
    for case in cases {
        run_case(case, true)?;
    }
    Ok(())
}

fn run_case(case: &serde_json::Value, accessors: bool) -> AuthResult<()> {
    let harness = if accessors {
        Harness::new_getters(case)?
    } else {
        Harness::new(case)?
    };
    let before = harness.before()?;
    let mut keys = harness.rows();
    let result =
        sort_keys(&mut keys, "name", case["direction"].as_str()).map(|()| FieldValue::from(keys));
    assert_case(&harness.finish(before, result)?, case);
    Ok(())
}
