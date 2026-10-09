#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned fixture keys and setup must fail immediately when the protected function contract changes"
)]

#[path = "protected_function_tests/support.rs"]
mod support;
#[path = "protected_function_tests/values.rs"]
mod values;
