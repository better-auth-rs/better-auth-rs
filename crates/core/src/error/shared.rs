use std::{fmt, sync::Arc};

use super::AuthError;
use crate::FieldValue;

/// Shared ownership of an original error, with independent endpoint header capture.
#[derive(Clone)]
pub struct SharedAuthError {
    pub(super) source: Arc<AuthError>,
    pub(super) captured_headers: Option<FieldValue>,
}

impl fmt::Display for SharedAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for SharedAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl fmt::Debug for SharedAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedAuthError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl AuthError {
    /// Share an error without evaluating native properties or copying its source.
    pub fn into_shared(self) -> Self {
        match self {
            Self::Shared(_) => self,
            source => Self::Shared(SharedAuthError {
                source: Arc::new(source),
                captured_headers: None,
            }),
        }
    }

    /// Borrow the original variant for typed error handling across shared transports.
    pub fn original(&self) -> &Self {
        let mut error = self;
        while let Self::Shared(shared) = error {
            error = &shared.source;
        }
        error
    }
}

#[cfg(test)]
mod tests;
