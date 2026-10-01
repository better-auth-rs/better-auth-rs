use std::sync::Arc;

use super::{AuthStore, database_hooks::DatabaseHooks};
use crate::{AuthConfig, AuthError, AuthResult, AuthSchema};

/// Create an isolated configuration view over the same stored records.
pub trait RuntimeStore<S: AuthSchema>: Send + Sync {
    /// Create an independent verdict for one auth build; return None if this adapter cannot inspect its schema.
    fn schema_check(
        &self,
        _config: &super::schema::SchemaConfiguration,
    ) -> AuthResult<Option<Arc<super::schema::SchemaCheck>>> {
        Ok(None)
    }

    /// Runtime facade registration. Raw adapter CRUD does not invoke this check.
    fn schema_validation(&self) -> Option<&super::schema::SchemaValidation> {
        None
    }

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
