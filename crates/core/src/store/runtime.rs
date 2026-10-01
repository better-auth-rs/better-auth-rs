use std::sync::Arc;

use super::{AuthStore, database_hooks::DatabaseHooks};
use crate::{AuthConfig, AuthError, AuthResult, AuthSchema};

/// Create an isolated configuration view over the same stored records.
pub trait RuntimeStore<S: AuthSchema>: Send + Sync {
    /// Install plugin hooks before application hooks without changing the original store.
    /// Custom adapters need this capability only for plugins that register fields or database hooks.
    fn with_runtime(
        &self,
        _config: Arc<AuthConfig>,
        _hooks: Vec<Arc<dyn DatabaseHooks<S>>>,
    ) -> AuthResult<Arc<dyn AuthStore<S>>> {
        Err(AuthError::config(
            "This adapter does not support plugin database hooks or fields",
        ))
    }
}
