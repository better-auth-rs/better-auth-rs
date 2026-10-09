//! Callable field values retain the identity of their declaration factory.

use crate::{AuthResult, FieldValue, user_fields::UserFieldFactory};
use std::{fmt, sync::Arc};

/// A synchronous field function. Clones retain the original callback identity.
#[derive(Clone)]
pub struct FieldFunction(UserFieldFactory);

impl FieldFunction {
    /// Invoke the callback without changing its result or error.
    pub fn call(&self) -> AuthResult<FieldValue> {
        (self.0)()
    }

    pub(crate) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as *const () as usize
    }
}

impl From<UserFieldFactory> for FieldFunction {
    fn from(factory: UserFieldFactory) -> Self {
        Self(factory)
    }
}

impl From<FieldFunction> for FieldValue {
    fn from(function: FieldFunction) -> Self {
        Self::Function(function)
    }
}

impl PartialEq for FieldFunction {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FieldFunction {}

impl fmt::Debug for FieldFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldFunction")
            .finish_non_exhaustive()
    }
}
