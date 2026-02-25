//! # Spec-Driven Compatibility Testing Framework
//!
//! Shared modules for validating better-auth-rs API responses against the
//! canonical better-auth OpenAPI specification (`better-auth.yaml`).
//!
//! ## Module layout
//!
//! | Module       | Responsibility |
//! |--------------|----------------|
//! | `schema`     | OpenAPI spec loading, `$ref` resolution, `SchemaExpectation` types |
//! | `validation` | Response validation against schemas (`ShapeDiff`, `validate_response`) |
//! | `shapes`     | JSON shape comparison, camelCase checks, type-signature extraction |
//! | `helpers`    | Auth setup, HTTP request builders, signup/signin helpers |
//! | `validator`  | `SpecValidator` framework for batch endpoint validation + reporting |

pub mod helpers;
pub mod schema;
pub mod shapes;
pub mod validation;
pub mod validator;
