//! # Spec-Driven Compatibility Testing Framework
//!
//! Shared modules for validating better-auth-rs API responses against the
//! generated upstream Better Auth OpenAPI contract from the pinned published
//! reference package.
//!
//! ## Module layout
//!
//! | Module       | Responsibility |
//! |--------------|----------------|
//! | `schema`     | OpenAPI spec loading, `$ref` resolution, `SchemaExpectation` types |
//! | `validation` | Response validation against schemas (`ShapeDiff`, `validate_response`) |
//! | `shapes`     | JSON shape comparison, camelCase checks, type-signature extraction |
//! | `helpers`    | Auth setup, HTTP request builders, signup/signin helpers |
//! | `dual_server`| Shared dual-server oracle infrastructure and control hooks |
//! | `validator`  | `SpecValidator` framework for batch endpoint validation + reporting |

// Each integration test binary compiles this module independently, so items
// used only by *other* test files appear dead/unreachable in any single binary.
// We use `allow` rather than `expect` because which items are "dead" varies
// per test binary — `expect` would fail in binaries that use all items.
//
// Test utility code legitimately uses panic (via unwrap_or_else, assert_eq,
// etc.) for setup failures and test assertions, plus indexing for known-valid
// array access in schema comparison code.
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod dual_server;
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod helpers;
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod schema;
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod shapes;
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod validation;
#[allow(
    dead_code,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    unused_results,
    reason = "shared test utilities — lints vary per binary and test code legitimately panics on failures"
)]
pub mod validator;
