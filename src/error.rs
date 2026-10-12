//! Error types and result aliases for Better Auth.

pub use better_auth_core::error::{
    ApiErrorClass, ApiErrorInit, AuthError, AuthResult, DatabaseError, DatabaseErrorCause,
    SharedAuthError, is_error_value,
};
