use std::sync::Arc;

use super::{AuthStore, database_hooks::DatabaseHooks};
use crate::{AuthConfig, AuthResult, AuthSchema};

/// Create an isolated configuration view over the same stored records.
pub trait RuntimeStore<S: AuthSchema>: Send + Sync {
    /// Identify the adapter in initialization metadata without querying stored records.
    fn adapter_id(&self) -> &'static str {
        "unknown"
    }

    /// Declared callbacks installed on this adapter, without invoking any hook.
    fn database_hook_metadata(&self) -> Vec<crate::observability::database::DatabaseHookMetadata> {
        Vec::new()
    }

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

    /// Bind the final configuration and prepend plugin hooks without changing the original store.
    /// Share stored records, but isolate configuration and hook lists for each auth build.
    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        hooks: Vec<Arc<dyn DatabaseHooks<S>>>,
    ) -> AuthResult<Arc<dyn AuthStore<S>>>;
}
